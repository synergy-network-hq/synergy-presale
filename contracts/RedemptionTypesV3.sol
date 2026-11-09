// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

/// @title Synergy Redemption V3 Message Commitments
/// @notice Canonical typed, double-hashed Merkle leaves shared with the native settlement runtime.
/// @dev ABI words, Keccak-256 and sorted-pair Merkle hashing are normative. Double hashing avoids
///      treating a 64-byte leaf preimage as an internal Merkle node. Version 2 signatures are not used.
library RedemptionTypesV3 {
    bytes32 internal constant REQUEST_TYPEHASH = keccak256(
        "SynergyRequestV3(uint8 action,bytes32 descriptorHash,bytes32 allocationKey,bytes32 attemptId,uint96 amountNwei,bytes32 recipientHash)"
    );
    bytes32 internal constant OUTCOME_TYPEHASH = keccak256(
        "SynergyOutcomeV3(uint8 outcome,bytes32 descriptorHash,bytes32 allocationKey,bytes32 attemptId,uint96 amountNwei,bytes32 recipientHash)"
    );
    bytes32 internal constant ACCEPTANCE_TYPEHASH = keccak256(
        "SynergyRecipientAcceptanceV3(bytes32 descriptorHash,bytes32 allocationKey,bytes32 attemptId,uint96 amountNwei,bytes32 recipientHash,uint64 deadline)"
    );
    bytes32 internal constant READINESS_TYPEHASH = keccak256(
        "SynergyReadinessV3(bytes32 descriptorHash,bytes32 recipientProfileId,bytes32 saleProgramId,address sourceVoucher,uint96 fundedCapNwei)"
    );

    /// @notice Commits to a finalized pending request (1) or cancellation request (2).
    function requestLeaf(
        uint8 action,
        bytes32 descriptorHash,
        bytes32 allocationKey,
        bytes32 attemptId,
        uint96 amountNwei,
        bytes32 recipientHash
    ) internal pure returns (bytes32) {
        return
            keccak256(
                bytes.concat(
                    keccak256(
                        abi.encode(
                            REQUEST_TYPEHASH,
                            action,
                            descriptorHash,
                            allocationKey,
                            attemptId,
                            amountNwei,
                            recipientHash
                        )
                    )
                )
            );
    }

    /// @notice Commits to a permanent native settlement (1) or cancellation (2) outcome.
    function outcomeLeaf(
        uint8 outcome,
        bytes32 descriptorHash,
        bytes32 allocationKey,
        bytes32 attemptId,
        uint96 amountNwei,
        bytes32 recipientHash
    ) internal pure returns (bytes32) {
        return
            keccak256(
                bytes.concat(
                    keccak256(
                        abi.encode(
                            OUTCOME_TYPEHASH,
                            outcome,
                            descriptorHash,
                            allocationKey,
                            attemptId,
                            amountNwei,
                            recipientHash
                        )
                    )
                )
            );
    }

    /// @notice Commits to native account consent for one exact attempt and source-submission deadline.
    function acceptanceLeaf(
        bytes32 descriptorHash,
        bytes32 allocationKey,
        bytes32 attemptId,
        uint96 amountNwei,
        bytes32 recipientHash,
        uint64 deadline
    ) internal pure returns (bytes32) {
        return
            keccak256(
                bytes.concat(
                    keccak256(
                        abi.encode(
                            ACCEPTANCE_TYPEHASH,
                            descriptorHash,
                            allocationKey,
                            attemptId,
                            amountNwei,
                            recipientHash,
                            deadline
                        )
                    )
                )
            );
    }

    /// @notice Commits to actual native activation with a funded, nonwithdrawable program cap.
    function readinessLeaf(
        bytes32 descriptorHash,
        bytes32 profileId,
        bytes32 saleProgramId,
        address sourceVoucher,
        uint96 fundedCapNwei
    ) internal pure returns (bytes32) {
        return
            keccak256(
                bytes.concat(
                    keccak256(
                        abi.encode(
                            READINESS_TYPEHASH,
                            descriptorHash,
                            profileId,
                            saleProgramId,
                            sourceVoucher,
                            fundedCapNwei
                        )
                    )
                )
            );
    }
}

/// @notice Exact interface consumed by the V3 voucher after one-time delayed configuration sealing.
interface IRedemptionEvidenceV3 {
    function isReady(
        bytes32 descriptorHash,
        bytes32 recipientProfileId,
        address sourceVoucher,
        bytes32 saleProgramId
    ) external view returns (bool);
    function verifyRecipientAcceptance(
        bytes32 descriptorHash,
        bytes32 allocationKey,
        bytes32 attemptId,
        uint96 amountNwei,
        bytes32 recipientHash,
        uint64 deadline,
        bytes calldata proof
    ) external view returns (bool);
    function verifyOutcome(
        bytes32 descriptorHash,
        bytes32 allocationKey,
        bytes32 attemptId,
        uint96 amountNwei,
        bytes32 recipientHash,
        uint8 outcome,
        bytes calldata proof
    ) external view returns (bool);
}

/// @notice Integration boundary for a separately reviewed concrete consensus/finality ZK verifier.
/// @dev The implementation must prove native finality and the messagesRoot/stateRoot relationship.
///      It must bind this exact public-input digest and use the approved immutable verification key.
///      No production implementation or trusted-setup material is fabricated by this package.
interface IZkCheckpointVerifierV3 {
    function proofSystemId() external view returns (bytes32);
    function verificationKeyHash() external view returns (bytes32);
    function verifyCheckpoint(
        bytes32 publicInputsDigest,
        bytes calldata proof
    ) external view returns (bool);
}
