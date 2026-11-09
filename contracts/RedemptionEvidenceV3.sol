// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {
    RedemptionTypesV3,
    IRedemptionEvidenceV3,
    IZkCheckpointVerifierV3
} from "./RedemptionTypesV3.sol";

/// @notice The sealed voucher supplies the immutable program identity and lifetime issuance cap.
interface IVoucherEvidenceBindingV3 {
    function saleProgramId() external view returns (bytes32);
    function issuanceSealed() external view returns (bool);
    function issuanceCapNwei() external view returns (uint256);
}

/// @title Synergy Redemption V3 Evidence Registry
/// @notice Authenticates native checkpoint roots, then verifies bounded Merkle proofs for the voucher.
/// @dev A Merkle proof supplies inclusion, not finality. The one-time sealed policy selects either
///      explicitly trusted on-chain committee approvals OR a separately reviewed concrete ZK verifier.
///      There is no fallback between modes and no administrator root-insertion or outcome-override path.
///      This registry cannot prove the honesty of its initially approved committee or ZK implementation.
contract RedemptionEvidenceV3 is IRedemptionEvidenceV3 {
    /// @notice Full review interval after every proposed configuration replacement.
    uint64 public constant CONFIGURATION_DELAY = 7 days;
    /// @notice Limits the cost and administrative surface of the explicitly trusted committee.
    uint256 public constant MAX_COMMITTEE_SIZE = 16;
    /// @notice Limits proof decoding and hashing to at most 32 siblings.
    uint256 public constant MAX_PROOF_DEPTH = 32;
    /// @notice The sole native receiving-account profile admitted by this protocol version.
    bytes32 public constant RECIPIENT_PROFILE = keccak256("SYNW_HEX_EIP55_V1");
    /// @notice Native coin identity; this deployment does not settle a wrapped or ERC-20 asset.
    bytes32 public constant NATIVE_ASSET_ID = keccak256(
        "SYNERGY_NATIVE_SNRG_9_DECIMALS"
    );
    /// @notice Ethereum mainnet genesis, fixed alongside source chain ID 1.
    bytes32 public constant SOURCE_GENESIS_HASH =
        0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3;
    bytes32 private constant DESCRIPTOR_DOMAIN = keccak256(
        "SYNERGY_DESTINATION_DESCRIPTOR_V3"
    );
    bytes32 private constant CHECKPOINT_DOMAIN = keccak256(
        "SYNERGY_NATIVE_CHECKPOINT_V3"
    );
    bytes32 private constant COMMITTEE_DOMAIN = keccak256(
        "SYNERGY_CHECKPOINT_COMMITTEE_V3"
    );
    bytes32 private constant ZK_DOMAIN = keccak256(
        "SYNERGY_CHECKPOINT_ZK_POLICY_V3"
    );

    /// @notice Verification mode is selected once; a missing ZK verifier never falls back to committee.
    enum ProofMode {
        Unset,
        Committee,
        ZeroKnowledge
    }

    /// @notice Production facts whose canonical ABI encoding defines the destination descriptor.
    /// @dev Native configuration/capability hashes must exclude this descriptor to avoid recursion.
    struct Destination {
        bytes32 sourceGenesisHash;
        bytes32 destinationNamespaceHash;
        uint64 destinationChainId;
        bytes32 destinationGenesisHash;
        bytes32 settlementContractIdHash;
        bytes32 nativeConfigurationHash;
        bytes32 nativeRuntimeCodeHash;
        bytes32 nativeCapabilityHash;
        bytes32 recipientProfileId;
    }

    /// @notice A finalized native block and its authenticated settlement-message commitment.
    /// @dev The selected verifier must establish messagesRoot's relationship to the accepted stateRoot.
    struct Checkpoint {
        uint64 height;
        bytes32 blockHash;
        bytes32 stateRoot;
        bytes32 messagesRoot;
    }

    /// @notice Queryable authenticated checkpoint; approved roots are never deleted or replaced.
    struct ApprovedCheckpoint {
        uint64 height;
        bytes32 blockHash;
        bytes32 stateRoot;
        bytes32 messagesRoot;
        bool approved;
    }

    /// @notice Initial configuration and emergency-pause authority, with no power to create valid proofs.
    address public immutable admin;
    /// @notice The only voucher/program pair for which this registry can report readiness.
    address public immutable sourceVoucher;
    /// @notice Immutable economic program identity, independent from future network activation.
    bytes32 public immutable saleProgramId;
    /// @notice Prevents new checkpoint admission and proof acceptance during an incident.
    bool public paused;
    /// @notice Permanent configuration latch; no root policy or network change is possible afterward.
    bool public configurationSealed;
    /// @notice True only after an authenticated funded native-activation record was proven.
    bool public nativeActivationConfirmed;
    /// @notice Current proposed or sealed destination facts.
    Destination public destination;
    /// @notice Full production destination and verifier-policy commitment.
    bytes32 public descriptorHash;
    /// @notice Exact committee membership/threshold or ZK implementation/key commitment.
    bytes32 public policyHash;
    /// @notice The selected verification class; remains unchanged after sealing.
    ProofMode public proofMode;
    /// @notice Full review deadline; replacement proposals reset this timestamp.
    uint64 public configurationReadyAt;
    /// @notice Required distinct approvals in committee mode.
    uint8 public committeeThreshold;
    /// @notice Pinned ZK verifier; zero in committee mode.
    address public zkVerifier;
    /// @notice Pinned verifier runtime-bytecode hash, checked for every ZK checkpoint admission.
    bytes32 public zkVerifierCodeHash;
    /// @notice Approved proof-system identity; not a claim of post-quantum security.
    bytes32 public zkProofSystemId;
    /// @notice Approved circuit verification-key identity.
    bytes32 public zkVerificationKeyHash;
    /// @notice Actual native cap proven in the readiness record.
    uint96 public fundedCapNwei;
    /// @notice Largest approved native height; older valid checkpoints can still be admitted.
    uint64 public latestApprovedHeight;

    address[] private _committee;
    mapping(address member => bool enabled) public isCommitteeMember;
    mapping(bytes32 checkpointId => uint8 approvals)
        public checkpointApprovalCount;
    mapping(uint64 height => mapping(address member => bytes32 checkpointId))
        public committeeVoteAtHeight;
    mapping(uint64 height => bytes32 checkpointId)
        public approvedCheckpointAtHeight;
    mapping(bytes32 checkpointId => ApprovedCheckpoint record)
        public approvedCheckpoints;

    event ConfigurationProposed(
        bytes32 indexed descriptorHash,
        bytes32 indexed policyHash,
        ProofMode mode,
        uint64 readyAt
    );
    event ConfigurationSealed(
        bytes32 indexed descriptorHash,
        bytes32 indexed policyHash
    );
    event CheckpointVoted(
        bytes32 indexed checkpointId,
        address indexed member,
        uint8 approvals
    );
    event CheckpointApproved(
        bytes32 indexed checkpointId,
        uint64 indexed height,
        bytes32 blockHash,
        bytes32 stateRoot,
        bytes32 messagesRoot
    );
    event NativeActivationConfirmed(
        bytes32 indexed descriptorHash,
        uint96 fundedCapNwei
    );
    event PauseChanged(bool paused);

    error Unauthorized();
    error InvalidConfiguration();
    error AlreadySealed();
    error NotSealed();
    error ReviewDelayActive();
    error InvalidCheckpoint();
    error DuplicateVote();
    error ConflictingCheckpoint();
    error InvalidProof();
    error WrongProofMode();
    error Paused();
    error VerifierChanged();
    error InsufficientNativeBacking();

    /// @param admin_ Authority that proposes configuration and controls incident pause.
    /// @param sourceVoucher_ Deployed V3 voucher, whose minting can precede redemption by months.
    /// @param saleProgramId_ Immutable program identifier matching that voucher.
    constructor(
        address admin_,
        address sourceVoucher_,
        bytes32 saleProgramId_
    ) {
        if (
            block.chainid != 1 ||
            admin_ == address(0) ||
            sourceVoucher_.code.length == 0 ||
            saleProgramId_ == bytes32(0)
        ) revert InvalidConfiguration();
        if (
            IVoucherEvidenceBindingV3(sourceVoucher_).saleProgramId() !=
            saleProgramId_
        ) revert InvalidConfiguration();
        admin = admin_;
        sourceVoucher = sourceVoucher_;
        saleProgramId = saleProgramId_;
    }

    modifier onlyAdmin() {
        if (msg.sender != admin) revert Unauthorized();
        _;
    }
    modifier whenOperational() {
        if (!configurationSealed) revert NotSealed();
        if (paused) revert Paused();
        _;
    }

    /// @notice Returns the configured committee in its canonical increasing-address order.
    function committeeMembers() external view returns (address[] memory) {
        return _committee;
    }

    /// @notice Proposes or corrects configuration before the irreversible seal; resets the full delay.
    /// @param proposed Complete, independently approved future mainnet facts, with no placeholder values.
    /// @param mode Exactly one authentication mode.
    /// @param members Sorted, distinct committee addresses; empty for ZK mode.
    /// @param threshold Strictly more than two-thirds of 3–16 trusted members; zero for ZK mode.
    /// @param verifier Concrete reviewed ZK verifier, or zero for committee mode.
    function proposeConfiguration(
        Destination calldata proposed,
        ProofMode mode,
        address[] calldata members,
        uint8 threshold,
        address verifier
    ) external onlyAdmin {
        if (configurationSealed) revert AlreadySealed();
        _validateDestination(proposed);
        for (uint256 i; i < _committee.length; ++i)
            isCommitteeMember[_committee[i]] = false;
        delete _committee;
        bytes32 nextPolicy;
        if (mode == ProofMode.Committee) {
            uint256 count = members.length;
            if (
                verifier != address(0) ||
                count < 3 ||
                count > MAX_COMMITTEE_SIZE ||
                threshold < 2 ||
                threshold > count ||
                uint256(threshold) * 3 <= count * 2
            ) revert InvalidConfiguration();
            address previous;
            for (uint256 i; i < count; ++i) {
                address member = members[i];
                if (member <= previous) revert InvalidConfiguration();
                previous = member;
                isCommitteeMember[member] = true;
                _committee.push(member);
            }
            nextPolicy = keccak256(
                abi.encode(COMMITTEE_DOMAIN, members, threshold)
            );
            committeeThreshold = threshold;
            zkVerifier = address(0);
            zkVerifierCodeHash = bytes32(0);
            zkProofSystemId = bytes32(0);
            zkVerificationKeyHash = bytes32(0);
        } else if (mode == ProofMode.ZeroKnowledge) {
            if (
                members.length != 0 ||
                threshold != 0 ||
                verifier.code.length == 0
            ) revert InvalidConfiguration();
            bytes32 systemId = IZkCheckpointVerifierV3(verifier)
                .proofSystemId();
            bytes32 keyHash = IZkCheckpointVerifierV3(verifier)
                .verificationKeyHash();
            if (systemId == bytes32(0) || keyHash == bytes32(0))
                revert InvalidConfiguration();
            zkVerifier = verifier;
            zkVerifierCodeHash = verifier.codehash;
            zkProofSystemId = systemId;
            zkVerificationKeyHash = keyHash;
            committeeThreshold = 0;
            nextPolicy = keccak256(
                abi.encode(
                    ZK_DOMAIN,
                    verifier,
                    verifier.codehash,
                    systemId,
                    keyHash
                )
            );
        } else revert InvalidConfiguration();
        destination = proposed;
        proofMode = mode;
        policyHash = nextPolicy;
        descriptorHash = keccak256(
            abi.encode(
                DESCRIPTOR_DOMAIN,
                block.chainid,
                sourceVoucher,
                saleProgramId,
                proposed,
                NATIVE_ASSET_ID,
                mode,
                nextPolicy
            )
        );
        configurationReadyAt = uint64(block.timestamp + CONFIGURATION_DELAY);
        emit ConfigurationProposed(
            descriptorHash,
            nextPolicy,
            mode,
            configurationReadyAt
        );
    }

    /// @notice Irreversibly seals the reviewed destination and proof policy; does not enable redemption.
    /// @dev Native readiness must still be proven, and the voucher performs its own delayed seal.
    function sealConfiguration() external onlyAdmin {
        if (configurationSealed) revert AlreadySealed();
        if (descriptorHash == bytes32(0)) revert InvalidConfiguration();
        if (block.timestamp < configurationReadyAt) revert ReviewDelayActive();
        IVoucherEvidenceBindingV3 voucher = IVoucherEvidenceBindingV3(
            sourceVoucher
        );
        if (
            !voucher.issuanceSealed() ||
            voucher.issuanceCapNwei() == 0 ||
            voucher.issuanceCapNwei() > type(uint96).max
        ) revert InvalidConfiguration();
        if (proofMode == ProofMode.ZeroKnowledge) _checkZkVerifier();
        configurationSealed = true;
        emit ConfigurationSealed(descriptorHash, policyHash);
    }

    /// @notice Pauses proof acceptance without changing any approved root, destination or entitlement.
    function setPaused(bool value) external onlyAdmin {
        paused = value;
        emit PauseChanged(value);
    }

    /// @notice Canonical domain-separated digest authenticated by committee calls or the ZK verifier.
    /// @param checkpoint Finalized native header and settlement-message root.
    function checkpointId(
        Checkpoint calldata checkpoint
    ) public view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    CHECKPOINT_DOMAIN,
                    block.chainid,
                    address(this),
                    descriptorHash,
                    policyHash,
                    checkpoint.height,
                    checkpoint.blockHash,
                    checkpoint.stateRoot,
                    checkpoint.messagesRoot
                )
            );
    }

    /// @notice Records one native-finality attestation from a configured member's Ethereum transaction.
    /// @dev Each member can vote once per height; a minority proposal cannot block a different quorum.
    function approveCheckpoint(
        Checkpoint calldata checkpoint
    ) external whenOperational {
        if (proofMode != ProofMode.Committee) revert WrongProofMode();
        if (!isCommitteeMember[msg.sender]) revert Unauthorized();
        _validateCheckpoint(checkpoint);
        bytes32 id = checkpointId(checkpoint);
        bytes32 previousVote = committeeVoteAtHeight[checkpoint.height][
            msg.sender
        ];
        if (previousVote != bytes32(0)) revert DuplicateVote();
        bytes32 approved = approvedCheckpointAtHeight[checkpoint.height];
        if (approved != bytes32(0) && approved != id)
            revert ConflictingCheckpoint();
        committeeVoteAtHeight[checkpoint.height][msg.sender] = id;
        uint8 approvals = checkpointApprovalCount[id] + 1;
        checkpointApprovalCount[id] = approvals;
        emit CheckpointVoted(id, msg.sender, approvals);
        if (
            approvals >= committeeThreshold && !approvedCheckpoints[id].approved
        ) _approve(id, checkpoint);
    }

    /// @notice Permissionlessly admits a checkpoint only through the sealed concrete ZK verifier.
    /// @param checkpoint Claimed finalized native header and message root, all bound into the public digest.
    /// @param proof Proof in the exact approved verifier's format; bounded to prevent oversized inputs.
    function approveCheckpointWithProof(
        Checkpoint calldata checkpoint,
        bytes calldata proof
    ) external whenOperational {
        if (proofMode != ProofMode.ZeroKnowledge) revert WrongProofMode();
        if (proof.length == 0 || proof.length > 131072) revert InvalidProof();
        _validateCheckpoint(checkpoint);
        _checkZkVerifier();
        bytes32 id = checkpointId(checkpoint);
        if (!IZkCheckpointVerifierV3(zkVerifier).verifyCheckpoint(id, proof))
            revert InvalidProof();
        _approve(id, checkpoint);
    }

    /// @notice Confirms actual funded native activation from an already authenticated checkpoint.
    /// @param nativeCapNwei Native contract's activated, nonwithdrawable program cap.
    /// @param proof ABI encoding of (bytes32 checkpointId, bytes32[] sorted-pair Merkle siblings).
    function confirmNativeActivation(
        uint96 nativeCapNwei,
        bytes calldata proof
    ) external whenOperational {
        uint256 required = IVoucherEvidenceBindingV3(sourceVoucher)
            .issuanceCapNwei();
        if (required == 0 || nativeCapNwei < required)
            revert InsufficientNativeBacking();
        bytes32 leaf = RedemptionTypesV3.readinessLeaf(
            descriptorHash,
            destination.recipientProfileId,
            saleProgramId,
            sourceVoucher,
            nativeCapNwei
        );
        if (!_verifyLeaf(leaf, proof)) revert InvalidProof();
        if (nativeActivationConfirmed && fundedCapNwei != nativeCapNwei)
            revert ConflictingCheckpoint();
        fundedCapNwei = nativeCapNwei;
        nativeActivationConfirmed = true;
        emit NativeActivationConfirmed(descriptorHash, nativeCapNwei);
    }

    /// @inheritdoc IRedemptionEvidenceV3
    function isReady(
        bytes32 descriptor,
        bytes32 profile,
        address voucher,
        bytes32 program
    ) public view returns (bool) {
        return
            configurationSealed &&
            nativeActivationConfirmed &&
            !paused &&
            descriptor == descriptorHash &&
            profile == destination.recipientProfileId &&
            voucher == sourceVoucher &&
            program == saleProgramId;
    }

    /// @inheritdoc IRedemptionEvidenceV3
    function verifyRecipientAcceptance(
        bytes32 descriptor,
        bytes32 allocationKey,
        bytes32 attemptId,
        uint96 amountNwei,
        bytes32 recipientHash,
        uint64 deadline,
        bytes calldata proof
    ) external view returns (bool) {
        if (
            !_validMessage(
                descriptor,
                allocationKey,
                attemptId,
                amountNwei,
                recipientHash
            )
        ) return false;
        return
            _verifyLeaf(
                RedemptionTypesV3.acceptanceLeaf(
                    descriptor,
                    allocationKey,
                    attemptId,
                    amountNwei,
                    recipientHash,
                    deadline
                ),
                proof
            );
    }

    /// @inheritdoc IRedemptionEvidenceV3
    function verifyOutcome(
        bytes32 descriptor,
        bytes32 allocationKey,
        bytes32 attemptId,
        uint96 amountNwei,
        bytes32 recipientHash,
        uint8 outcome,
        bytes calldata proof
    ) external view returns (bool) {
        if (
            (outcome != 1 && outcome != 2) ||
            !_validMessage(
                descriptor,
                allocationKey,
                attemptId,
                amountNwei,
                recipientHash
            )
        ) return false;
        return
            _verifyLeaf(
                RedemptionTypesV3.outcomeLeaf(
                    outcome,
                    descriptor,
                    allocationKey,
                    attemptId,
                    amountNwei,
                    recipientHash
                ),
                proof
            );
    }

    function _validMessage(
        bytes32 descriptor,
        bytes32 allocationKey,
        bytes32 attemptId,
        uint96 amountNwei,
        bytes32 recipientHash
    ) private view returns (bool) {
        return
            isReady(
                descriptor,
                destination.recipientProfileId,
                sourceVoucher,
                saleProgramId
            ) &&
            allocationKey != bytes32(0) &&
            attemptId != bytes32(0) &&
            amountNwei != 0 &&
            amountNwei <= fundedCapNwei &&
            recipientHash != bytes32(0);
    }

    function _verifyLeaf(
        bytes32 leaf,
        bytes calldata proof
    ) private view returns (bool) {
        // Bound the complete ABI layout before decoding its dynamic array.
        if (proof.length < 96 || proof.length > 96 + 32 * MAX_PROOF_DEPTH)
            return false;
        uint256 offset;
        uint256 count;
        assembly ("memory-safe") {
            offset := calldataload(add(proof.offset, 32))
            count := calldataload(add(proof.offset, 64))
        }
        if (
            offset != 64 ||
            count > MAX_PROOF_DEPTH ||
            proof.length != 96 + 32 * count
        ) return false;
        (bytes32 id, bytes32[] memory siblings) = abi.decode(
            proof,
            (bytes32, bytes32[])
        );
        ApprovedCheckpoint storage checkpoint = approvedCheckpoints[id];
        return
            checkpoint.approved &&
            MerkleProof.verify(siblings, checkpoint.messagesRoot, leaf);
    }

    function _approve(bytes32 id, Checkpoint calldata checkpoint) private {
        bytes32 previous = approvedCheckpointAtHeight[checkpoint.height];
        if (previous != bytes32(0) && previous != id)
            revert ConflictingCheckpoint();
        if (approvedCheckpoints[id].approved) return;
        approvedCheckpointAtHeight[checkpoint.height] = id;
        approvedCheckpoints[id] = ApprovedCheckpoint(
            checkpoint.height,
            checkpoint.blockHash,
            checkpoint.stateRoot,
            checkpoint.messagesRoot,
            true
        );
        if (checkpoint.height > latestApprovedHeight)
            latestApprovedHeight = checkpoint.height;
        emit CheckpointApproved(
            id,
            checkpoint.height,
            checkpoint.blockHash,
            checkpoint.stateRoot,
            checkpoint.messagesRoot
        );
    }

    function _checkZkVerifier() private view {
        if (
            zkVerifier.codehash != zkVerifierCodeHash ||
            IZkCheckpointVerifierV3(zkVerifier).proofSystemId() !=
                zkProofSystemId ||
            IZkCheckpointVerifierV3(zkVerifier).verificationKeyHash() !=
                zkVerificationKeyHash
        ) revert VerifierChanged();
    }

    function _validateCheckpoint(Checkpoint calldata checkpoint) private pure {
        if (
            checkpoint.height == 0 ||
            checkpoint.blockHash == bytes32(0) ||
            checkpoint.stateRoot == bytes32(0) ||
            checkpoint.messagesRoot == bytes32(0)
        ) revert InvalidCheckpoint();
    }

    function _validateDestination(Destination calldata value) private pure {
        if (
            value.sourceGenesisHash != SOURCE_GENESIS_HASH ||
            value.destinationNamespaceHash == bytes32(0) ||
            value.destinationChainId == 0 ||
            value.destinationGenesisHash == bytes32(0) ||
            value.settlementContractIdHash == bytes32(0) ||
            value.nativeConfigurationHash == bytes32(0) ||
            value.nativeRuntimeCodeHash == bytes32(0) ||
            value.nativeCapabilityHash == bytes32(0) ||
            value.recipientProfileId != RECIPIENT_PROFILE
        ) revert InvalidConfiguration();
    }
}
