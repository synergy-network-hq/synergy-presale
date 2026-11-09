// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {RecipientCodec} from "./RecipientCodec.sol";
import {RedemptionTypesV3} from "./RedemptionTypesV3.sol";

/// @title V3 Authenticated Native Evidence Interface
/// @author Synergy Network
/// @notice Reads destination readiness, native recipient acceptance, and final terminal outcomes.
/// @dev Implementations must authenticate finality roots and their policy; inclusion in an arbitrary
///      relayer-supplied Merkle root is insufficient. The selected runtime is pinned at configuration.
interface IVoucherRedemptionEvidenceV3 {
    /// @notice Checks that the exact destination, profile and source deployment are ready.
    /// @param descriptorHash Full reviewed destination deployment descriptor hash.
    /// @param recipientProfileId Activated native recipient profile.
    /// @param sourceVoucher This source collection.
    /// @param saleProgramId The source sale program.
    /// @return ready Whether the verifier has finalized its matching activation configuration.
    function isReady(
        bytes32 descriptorHash,
        bytes32 recipientProfileId,
        address sourceVoucher,
        bytes32 saleProgramId
    ) external view returns (bool ready);

    /// @notice Verifies native account-policy acceptance of the exact proposed attempt.
    /// @param descriptorHash Sealed destination descriptor.
    /// @param allocationKey Stable source entitlement identity.
    /// @param attemptId Owner-, recipient- and nonce-bound attempt identity.
    /// @param amountNwei Exact immutable native entitlement.
    /// @param recipientHash Typed canonical native account hash.
    /// @param deadline Source admission deadline explicitly accepted by the native account.
    /// @param proof Proof against an authenticated finalized acceptance root.
    /// @return accepted Whether the exact native recipient acceptance was authenticated.
    function verifyRecipientAcceptance(
        bytes32 descriptorHash,
        bytes32 allocationKey,
        bytes32 attemptId,
        uint96 amountNwei,
        bytes32 recipientHash,
        uint64 deadline,
        bytes calldata proof
    ) external view returns (bool accepted);

    /// @notice Verifies the final destination outcome of the exact current attempt.
    /// @param descriptorHash Sealed destination descriptor.
    /// @param allocationKey Stable source entitlement identity.
    /// @param attemptId Exact pending attempt.
    /// @param amountNwei Exact immutable native entitlement.
    /// @param recipientHash Typed canonical native account hash.
    /// @param outcome One for settled; two for cancelled with a permanent destination tombstone.
    /// @param proof Proof against an authenticated finalized outcome root.
    /// @return verified Whether the final terminal outcome was authenticated.
    function verifyOutcome(
        bytes32 descriptorHash,
        bytes32 allocationKey,
        bytes32 attemptId,
        uint96 amountNwei,
        bytes32 recipientHash,
        uint8 outcome,
        bytes calldata proof
    ) external view returns (bool verified);
}

/// @title Canonical Presale Issuance Policy
/// @author Synergy Network
/// @notice Minimal views used to seal and validate the only permitted voucher issuance paths.
/// @dev The presale exposes a request hash only during its atomic, accounted mint operation.
interface ISealedPresaleIssuer {
    /// @notice Returns the voucher collection configured by the presale.
    /// @dev Must be this voucher before the one-time issuer seal can be created.
    /// @return collection Configured voucher address.
    function voucher() external view returns (address collection);

    /// @notice Returns the presale's immutable referral issuer.
    /// @dev Must match the second issuer selected by the voucher administrator.
    /// @return authorizer Configured referral issuer address.
    function referralAuthorizer() external view returns (address authorizer);

    /// @notice Returns the maximum new lifetime entitlement permitted by this sale's inventory and budget.
    /// @dev Historical obligations remain reserved outside this new collection's issuance capacity.
    /// @return cap Maximum new issuance in native SNRG base units.
    function issuanceCapNwei() external view returns (uint256 cap);

    /// @notice Checks whether an exact mint request is currently authorized by accounted presale state.
    /// @dev The digest is keccak256(abi.encode(request)), including all metadata and economic fields.
    /// @param issuer One of the two permanently sealed issuer addresses.
    /// @param requestHash Hash of the entire mint payload about to be consumed.
    /// @return authorized True only while the presale is executing that accounted issuance.
    function isMintAuthorized(
        address issuer,
        bytes32 requestHash
    ) external view returns (bool authorized);
}

/// @title Canonical Referral Issuer Views
/// @author Synergy Network
/// @notice Reads immutable links from the referral issuer during one-time sealing.
/// @dev These checks prevent accidentally sealing a referral issuer belonging to another deployment.
interface ISealedReferralIssuer {
    /// @notice Returns the presale that created and exclusively controls this referral issuer.
    /// @dev Must equal the presale being sealed by the voucher.
    /// @return sale Immutable originating presale address.
    function presale() external view returns (address sale);

    /// @notice Returns the voucher collection used for referral issuance.
    /// @dev Must equal the voucher executing the seal.
    /// @return collection Immutable voucher collection address.
    function voucher() external view returns (address collection);
}

/// @title SNRGClaimVoucherSoulboundV3
/// @author Synergy Network
/// @notice Ethereum claim voucher whose owner can request settlement in native SNRG on Synergy Network.
/// @dev Protocol V3 locks a pending voucher and burns only after verified final native settlement.
///      Verified destination cancellation unlocks the same NFT. A local timer never unlocks it.
///      This separate V3 collection does not alter or replace the existing V2 collection.
/// @dev SNRG uses 9 decimals. Every `snrgAmountNwei` value is already expressed in the smallest native
///      SNRG unit: 1 SNRG = 1_000_000_000 nWei. No 18-decimal conversion is performed anywhere.
/// @dev New deployments require a one-time issuance seal to the presale and its immutable referral
///      issuer. No direct or historical import minting path exists in this hardened collection.
contract SNRGClaimVoucherSoulboundV3 is
    ERC721,
    AccessControl,
    Pausable,
    ReentrancyGuard
{
    /// @notice Role authorized to issue paid and referral claim vouchers.
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    /// @notice Role authorized to pause and resume minting and redemption.
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /// @notice Decimal precision of native SNRG; retained as a public integration constant.
    uint8 public constant SNRG_DECIMALS = 9;
    /// @notice Number of native nWei in one SNRG; retained as a public integration constant.
    uint256 public constant SNRG_BASE_UNIT = 1_000_000_000;

    /// @notice Maximum percentage in basis points, equivalent to 100 percent.
    uint256 private constant MAX_BPS = 10_000;
    /// @notice Largest payment-token decimal count accepted in a receipt.
    uint8 private constant MAX_PAYMENT_TOKEN_DECIMALS = 36;
    /// @notice Explicit protocol version; legacy EIP-712 signatures grant no V3 authority.
    uint8 public constant PROTOCOL_VERSION = 3;
    /// @notice Minimum public review interval after every proposed destination configuration.
    uint256 public constant REDEMPTION_CONFIG_REVIEW_DELAY = 7 days;
    /// @notice Stable source-entitlement identity domain, independent of recipient and attempt.
    bytes32 public constant ALLOCATION_DOMAIN = keccak256(
        "SYNERGY_ALLOCATION_V3"
    );
    /// @notice Owner-, destination-, recipient- and nonce-bound request identity domain.
    bytes32 public constant ATTEMPT_DOMAIN = keccak256("SYNERGY_ATTEMPT_V3");
    /// @notice The only recipient profile this implementation can decode.
    bytes32 public constant SYNW_PROFILE_ID = keccak256("SYNW_HEX_EIP55_V1");

    /// @notice Immutable identifier for the sale program this voucher contract represents.
    bytes32 public immutable saleProgramId;

    /// @notice Full sealed V3 destination descriptor hash, zero before redemption activation.
    /// @dev The legacy getter name is retained; this is not a human-readable chain-name hash.
    bytes32 public destinationNetworkIdHash;
    /// @notice Native recipient profile fixed permanently at redemption activation.
    bytes32 public recipientProfileId;
    /// @notice Authenticated evidence contract fixed permanently at redemption activation.
    address public outcomeVerifier;
    /// @notice Expected runtime hash of the sealed evidence contract.
    bytes32 public outcomeVerifierCodeHash;
    /// @notice Whether redemption has been configured and activated after its review delay.
    /// @dev Issuance and paid-purchase activation do not depend on this flag.
    bool public redemptionEnabled;

    /// @notice V3 numbering continues after the legacy collection's last reported token ID (#108).
    /// @dev Token IDs remain collection-scoped; every redemption identity also binds this contract address.
    uint256 private _nextTokenId = 109;

    /// @notice Whether the two effective issuers and the lifetime issuance limit have been fixed forever.
    bool public issuanceSealed;

    /// @notice Only presale permitted to issue paid-purchase vouchers after sealing.
    address public sealedPresale;

    /// @notice Only referral issuer permitted to issue already accrued reward vouchers after sealing.
    address public sealedReferralAuthorizer;

    /// @notice Maximum lifetime issuance copied once from the sealed presale's approved capacity.
    uint256 public issuanceCapNwei;

    /// @notice Total entitlement ever minted by this collection; burns never release issuance capacity.
    uint256 public lifetimeIssuedNwei;

    /// @notice A required account was the zero address.
    error ZeroAddress();
    /// @notice The configured sale program identifier was empty.
    error InvalidSaleProgramId();
    /// @notice A proposed destination, recipient profile or verifier runtime was invalid.
    error InvalidRedemptionConfiguration();
    /// @notice The final destination configuration has already been sealed forever.
    error RedemptionAlreadyEnabled();
    /// @notice No reviewed and verified destination configuration has been activated.
    error RedemptionNotEnabled();
    /// @notice The latest destination proposal has not completed its public review interval.
    error RedemptionReviewPending(uint64 sealAfter);
    /// @notice The proposed verifier is not ready for this exact source and destination.
    error RedemptionVerifierNotReady();
    /// @notice The configured verifier runtime no longer matches its reviewed code hash.
    error RedemptionVerifierChanged();
    /// @notice The mint payload contained missing or inconsistent receipt facts.
    error InvalidMintRequest();
    /// @notice The supplied stage identifiers were inconsistent.
    error InvalidStageRange();
    /// @notice The payment asset precision was outside supported bounds.
    error InvalidPaymentTokenDecimals();
    /// @notice The release schedule was inconsistent or could not fully release the entitlement.
    error InvalidVestingTerms();
    /// @notice The recipient-accepted source admission deadline has passed.
    error AuthorizationExpired(uint64 deadline);
    /// @notice Native account-policy acceptance of the exact request was not authenticated.
    error InvalidRecipientAcceptance();
    /// @notice A final native settlement or cancellation outcome was not authenticated.
    error InvalidRedemptionOutcome();
    /// @notice This allocation fingerprint has already been used.
    error DuplicateFingerprint(bytes32 fingerprint);
    /// @notice This ledger identifier has already been used.
    error DuplicateLedgerId(uint64 ledgerId);
    /// @notice This chain-bound sale reference has already been used.
    error DuplicateSaleKey(bytes32 saleKey);
    /// @notice The token identifier has never been minted.
    error TokenNotMinted(uint256 tokenId);
    /// @notice The caller does not own the voucher they attempted to redeem.
    error NotTokenOwner(address caller, uint256 tokenId);
    /// @notice The voucher has already been burned after authenticated native settlement.
    error AlreadyRedeemed(uint256 tokenId);
    /// @notice The voucher is already locked by an outstanding destination attempt.
    error RedemptionPending(uint256 tokenId);
    /// @notice The voucher has no current pending attempt to cancel or finalize.
    error RedemptionNotPending(uint256 tokenId);
    /// @notice The owner has not requested cancellation of this exact pending attempt.
    error CancellationNotRequested();
    /// @notice The owner has already requested cancellation of this exact pending attempt.
    error CancellationAlreadyRequested();
    /// @notice Transfers and operator approvals are disabled for soulbound vouchers.
    error SoulboundTransferBlocked();
    /// @notice Minting was attempted before the permanent issuance policy was configured.
    error IssuanceNotSealed();
    /// @notice The one-time issuer configuration has already been sealed.
    error IssuanceAlreadySealed();
    /// @notice An issuer address or its immutable deployment relationships were inconsistent.
    error InvalidIssuerConfiguration();
    /// @notice A mint request was not authorized by the sealed presale's accounted state.
    error UnauthorizedIssuance();
    /// @notice A mint would exceed the collection's permanent lifetime issuance capacity.
    error IssuanceCapExceeded();

    /// @notice Entitlement release terms carried to the destination settlement layer.
    /// @dev The tuple is retained for mint ABI compatibility; V3 accepts only (0, 0, 0, 10000).
    struct VestingTerms {
        uint64 vestingStart;
        uint32 cliffSeconds;
        uint32 durationSeconds;
        uint16 initialUnlockBps;
    }

    /// @notice Mint payload aligned with the current presale ledger export.
    /// @dev `snrgAmountNwei` is a 9-decimal base-unit amount. Do not scale it to 18 decimals.
    struct MintRequest {
        uint64 ledgerId;
        bytes32 saleIdHash;
        address walletAddress;
        address purchaserAddress;
        bytes32 networkIdHash;
        uint256 paymentChainId;
        bytes32 assetSymbolHash;
        uint96 snrgAmountNwei;
        uint128 paymentAmountRaw;
        address paymentTokenAddress;
        uint8 paymentTokenDecimals;
        bytes32 paymentTxHash;
        uint32 stageFrom;
        uint32 stageTo;
        uint32 stageId;
        uint128 priceUsdE8;
        uint128 usdValueE8;
        uint64 purchaseTimestamp;
        bytes32 sourceHash;
        bytes32 statusHash;
        bool processedPaymentTx;
        bool nftMinted;
        VestingTerms vesting;
        string metadataURI;
    }

    /// @notice Immutable allocation facts and final native settlement status of a minted voucher.
    /// @dev Field order is preserved for existing consumers of allocationOf.
    struct Allocation {
        uint64 ledgerId;
        bytes32 saleIdHash;
        address walletAddress;
        address purchaserAddress;
        bytes32 networkIdHash;
        uint256 paymentChainId;
        bytes32 assetSymbolHash;
        uint96 snrgAmountNwei;
        uint128 paymentAmountRaw;
        address paymentTokenAddress;
        uint8 paymentTokenDecimals;
        bytes32 paymentTxHash;
        uint32 stageFrom;
        uint32 stageTo;
        uint32 stageId;
        uint128 priceUsdE8;
        uint128 usdValueE8;
        uint64 purchaseTimestamp;
        bytes32 sourceHash;
        VestingTerms vesting;
        bool redeemed;
    }

    /// @notice Source lifecycle of a historically minted voucher.
    /// @dev Active is also the storage default; public views reject token IDs never minted.
    enum RedemptionState {
        Active,
        Pending,
        Settled
    }

    /// @notice A reviewable destination proposal; only sealing grants redemption authority.
    struct RedemptionConfigProposal {
        bytes32 descriptorHash;
        bytes32 recipientProfileId;
        address verifier;
        bytes32 verifierCodeHash;
        uint64 sealAfter;
    }

    /// @notice Persistent details of the latest attempt, including a cancelled or settled attempt.
    /// @dev outcome is zero while pending, one after settlement, and two after cancellation.
    ///      requestedAt is a source timestamp. admissionDeadline never expires a pending entitlement.
    struct RedemptionRecord {
        bytes32 allocationKey;
        bytes32 attemptId;
        bytes32 recipientHash;
        bytes20 recipientAccount;
        address ethereumOwner;
        uint96 amountNwei;
        uint64 nonce;
        uint64 requestedAt;
        uint64 admissionDeadline;
        bool cancellationRequested;
        uint8 outcome;
        string canonicalRecipient;
    }

    /// @notice Latest publicly reviewable configuration; replacement restarts the full review delay.
    RedemptionConfigProposal public redemptionConfigProposal;

    /// @notice Immutable allocation data and redemption status indexed by voucher ID.
    mapping(uint256 tokenId => Allocation allocation) private _allocations;
    /// @notice Historical issuance markers, retained after voucher redemption.
    mapping(uint256 tokenId => bool wasMinted) private _minted;
    /// @notice Immutable receipt metadata, retained after voucher redemption.
    mapping(uint256 tokenId => string metadataURI) private _receiptURIs;
    /// @notice Owner-authorized destination requests indexed by voucher ID.
    mapping(uint256 tokenId => RedemptionRecord redemption)
        private _redemptions;
    /// @notice Current source lifecycle state, separately checked from historical mint existence.
    mapping(uint256 tokenId => RedemptionState state) private _redemptionStates;
    /// @notice Last used attempt nonce. Every successful new request increments it; it never resets.
    mapping(uint256 tokenId => uint64 nonce) public attemptNonceOf;
    /// @notice Final outcome of every acknowledged historical attempt, retained across cancellation retries.
    mapping(bytes32 attemptId => uint8 outcome) public finalizedAttemptOutcome;

    /// @notice Computed payment/allocation fingerprint => processed flag.
    mapping(bytes32 fingerprint => bool processed) public processedFingerprints;

    /// @notice Presale ledger row id => processed flag.
    mapping(uint64 ledgerId => bool processed) public processedLedgerIds;

    /// @notice sale key, computed as keccak256(abi.encode(paymentChainId, saleIdHash)) => processed flag.
    mapping(bytes32 saleKey => bool processed) public processedSaleKeys;

    /// @notice tokenId => computed payment/allocation fingerprint.
    mapping(uint256 tokenId => bytes32 fingerprint) public tokenFingerprint;

    /// @notice tokenId => computed sale key.
    mapping(uint256 tokenId => bytes32 saleKey) public tokenSaleKey;

    /// @notice A new immutable allocation was issued to its purchaser.
    /// @dev paymentTxHash may be a typed purchase reference; use transaction receipts for the actual hash.
    event ReceiptMinted(
        uint256 indexed tokenId,
        address indexed purchaserAddress,
        uint256 indexed paymentChainId,
        uint64 ledgerId,
        bytes32 saleIdHash,
        address walletAddress,
        uint96 snrgAmountNwei,
        uint128 paymentAmountRaw,
        address paymentTokenAddress,
        uint8 paymentTokenDecimals,
        bytes32 paymentTxHash,
        uint32 stageFrom,
        uint32 stageTo,
        uint32 stageId,
        uint128 usdValueE8,
        uint128 priceUsdE8,
        bytes32 sourceHash,
        bytes32 fingerprint,
        bytes32 saleKey
    );

    /// @notice Source attempt created only after authenticated native recipient acceptance.
    /// @dev The NFT still exists and is pending. The double-hashed requestLeaf is the canonical
    ///      V3 evidence leaf; source finality must be authenticated before native settlement.
    event SynergyRedemptionRequestedV3(
        bytes32 indexed allocationKey,
        bytes32 indexed attemptId,
        uint256 indexed tokenId,
        address ethereumOwner,
        bytes32 voucherFingerprint,
        bytes32 saleProgramId,
        bytes32 descriptorHash,
        bytes32 recipientProfileId,
        bytes32 recipientHash,
        bytes20 recipientAccount,
        string canonicalRecipient,
        uint96 amountNwei,
        uint64 nonce,
        uint64 admissionDeadline,
        uint64 requestedAt,
        uint256 ethereumChainId,
        bytes32 requestLeaf
    );

    /// @notice Owner intent to cancel a pending attempt; this event never unlocks or burns the NFT.
    /// @dev The destination must finalize a cancellation tombstone before source acknowledgement.
    event RedemptionCancellationRequested(
        bytes32 indexed allocationKey,
        bytes32 indexed attemptId,
        uint256 indexed tokenId,
        address ethereumOwner,
        uint64 nonce,
        bytes32 requestLeaf
    );

    /// @notice An authenticated final outcome burned the NFT or restored the same NFT to Active.
    event RedemptionFinalized(
        bytes32 indexed allocationKey,
        bytes32 indexed attemptId,
        uint256 indexed tokenId,
        uint8 outcome,
        address ethereumOwner,
        uint96 amountNwei,
        bytes32 recipientHash
    );

    /// @notice Legacy summary emitted only after verified final native settlement and source burn.
    event ReceiptRedeemed(
        uint256 indexed tokenId,
        address indexed purchaserAddress,
        uint96 snrgAmountNwei,
        uint256 redeemedAt
    );

    /// @notice A complete configuration entered or restarted the seven-day public review period.
    event RedemptionConfigProposed(
        bytes32 indexed descriptorHash,
        bytes32 indexed recipientProfileId,
        address indexed verifier,
        bytes32 verifierCodeHash,
        uint64 sealAfter
    );

    /// @notice The reviewed configuration became the collection's permanent redemption authority.
    event RedemptionConfigSealed(
        bytes32 indexed descriptorHash,
        bytes32 indexed recipientProfileId,
        address indexed verifier,
        bytes32 verifierCodeHash
    );

    /// @notice The collection permanently fixed its only two issuers and its issuance capacity.
    /// @param presale Canonical paid-purchase issuer.
    /// @param referralAuthorizer Canonical accrued-reward issuer.
    /// @param capNwei Maximum lifetime entitlement in native SNRG base units.
    event IssuersSealed(
        address indexed presale,
        address indexed referralAuthorizer,
        uint256 capNwei
    );

    /// @notice Creates a non-upgradeable V3 collection without guessing a future native network.
    /// @dev Only admin and pauser roles are initially granted. Minting requires sealIssuers;
    ///      redemption separately requires a reviewed, ready, permanently sealed configuration.
    ///      This new source cannot upgrade an already deployed V2 collection.
    /// @param admin_ Initial administrator responsible for role and delayed redemption configuration.
    /// @param saleProgramId_ Canonical identifier of the represented sale program.
    constructor(
        address admin_,
        bytes32 saleProgramId_
    ) ERC721("Synergy Claim Voucher", "SNRG-CV") {
        if (admin_ == address(0)) revert ZeroAddress();
        if (saleProgramId_ == bytes32(0)) revert InvalidSaleProgramId();
        saleProgramId = saleProgramId_;
        _grantRole(DEFAULT_ADMIN_ROLE, admin_);
        _grantRole(PAUSER_ROLE, admin_);
    }

    /// @notice Proposes a complete destination configuration for public review before activation.
    /// @dev Admin may correct a proposal only before sealing; every correction restarts seven days.
    ///      A code hash pins this verifier runtime, not any unreviewed mutable proxy dependencies.
    /// @param descriptorHash Hash binding the native genesis, settlement deployment, and proof policy.
    /// @param profileId The activated SYNW_HEX_EIP55_V1 recipient profile.
    /// @param verifier Deployed authenticated evidence verifier for this collection and sale.
    function proposeRedemptionConfig(
        bytes32 descriptorHash,
        bytes32 profileId,
        address verifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (redemptionEnabled) revert RedemptionAlreadyEnabled();
        if (descriptorHash == bytes32(0) || profileId != SYNW_PROFILE_ID)
            revert InvalidRedemptionConfiguration();
        if (verifier == address(this) || verifier.code.length == 0)
            revert InvalidRedemptionConfiguration();
        uint64 sealAfter = uint64(
            block.timestamp + REDEMPTION_CONFIG_REVIEW_DELAY
        );
        bytes32 verifierCodeHash = verifier.codehash;
        redemptionConfigProposal = RedemptionConfigProposal({
            descriptorHash: descriptorHash,
            recipientProfileId: profileId,
            verifier: verifier,
            verifierCodeHash: verifierCodeHash,
            sealAfter: sealAfter
        });
        emit RedemptionConfigProposed(
            descriptorHash,
            profileId,
            verifier,
            verifierCodeHash,
            sealAfter
        );
    }

    /// @notice Permanently activates the reviewed destination only after its verifier reports readiness.
    /// @dev No destination, profile, verifier, or code-hash setter exists after this seal.
    function sealRedemptionConfig()
        external
        nonReentrant
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (redemptionEnabled) revert RedemptionAlreadyEnabled();
        if (!issuanceSealed) revert IssuanceNotSealed();
        RedemptionConfigProposal memory proposal = redemptionConfigProposal;
        if (proposal.verifier == address(0))
            revert InvalidRedemptionConfiguration();
        if (block.timestamp < proposal.sealAfter)
            revert RedemptionReviewPending(proposal.sealAfter);
        if (proposal.verifier.codehash != proposal.verifierCodeHash)
            revert RedemptionVerifierChanged();
        if (
            !IVoucherRedemptionEvidenceV3(proposal.verifier).isReady(
                proposal.descriptorHash,
                proposal.recipientProfileId,
                address(this),
                saleProgramId
            )
        ) revert RedemptionVerifierNotReady();
        destinationNetworkIdHash = proposal.descriptorHash;
        recipientProfileId = proposal.recipientProfileId;
        outcomeVerifier = proposal.verifier;
        outcomeVerifierCodeHash = proposal.verifierCodeHash;
        redemptionEnabled = true;
        emit RedemptionConfigSealed(
            proposal.descriptorHash,
            proposal.recipientProfileId,
            proposal.verifier,
            proposal.verifierCodeHash
        );
    }

    /// @notice Permanently binds new issuance to one accounted presale and its referral issuer.
    /// @dev May be called only once, by the default administrator. There is no issuer replacement or
    ///      cap-increase path. Standard role revocation remains available to disable either issuer;
    ///      a role may subsequently be regranted only to those same two sealed addresses.
    /// @param presale_ Deployed presale whose voucher and referral issuer references must match.
    /// @param authorizer_ Referral issuer created by that presale for this collection.
    function sealIssuers(
        address presale_,
        address authorizer_
    ) external nonReentrant onlyRole(DEFAULT_ADMIN_ROLE) {
        if (issuanceSealed) revert IssuanceAlreadySealed();
        if (presale_.code.length == 0) revert InvalidIssuerConfiguration();
        if (authorizer_.code.length == 0) revert InvalidIssuerConfiguration();
        if (presale_ == authorizer_) revert InvalidIssuerConfiguration();

        ISealedPresaleIssuer sale = ISealedPresaleIssuer(presale_);
        if (sale.voucher() != address(this))
            revert InvalidIssuerConfiguration();
        if (sale.referralAuthorizer() != authorizer_)
            revert InvalidIssuerConfiguration();
        ISealedReferralIssuer referral = ISealedReferralIssuer(authorizer_);
        if (referral.presale() != presale_) revert InvalidIssuerConfiguration();
        if (referral.voucher() != address(this))
            revert InvalidIssuerConfiguration();
        uint256 cap = sale.issuanceCapNwei();
        if (cap == 0) revert InvalidIssuerConfiguration();

        sealedPresale = presale_;
        sealedReferralAuthorizer = authorizer_;
        issuanceCapNwei = cap;
        issuanceSealed = true;
        _grantRole(MINTER_ROLE, presale_);
        _grantRole(MINTER_ROLE, authorizer_);
        emit IssuersSealed(presale_, authorizer_, cap);
    }

    /// @notice Issues one soulbound voucher for a validated and previously unprocessed allocation.
    /// @dev The entire request must match a currently authorized, cap-accounted presale operation.
    ///      Duplicate markers, lifetime issuance and allocation data are committed before the
    ///      ERC-721 receiver callback. Any receiver failure rolls all those changes back.
    /// @param request Canonical allocation and immutable receipt metadata supplied by an authorized minter.
    /// @return tokenId Newly allocated voucher identifier.
    function mintReceipt(
        MintRequest calldata request
    )
        external
        nonReentrant
        onlyRole(MINTER_ROLE)
        whenNotPaused
        returns (uint256 tokenId)
    {
        if (!issuanceSealed) revert IssuanceNotSealed();
        if (msg.sender != sealedPresale) {
            if (msg.sender != sealedReferralAuthorizer)
                revert UnauthorizedIssuance();
        }
        _validateMintRequest(request);
        if (
            !ISealedPresaleIssuer(sealedPresale).isMintAuthorized(
                msg.sender,
                keccak256(abi.encode(request))
            )
        ) {
            revert UnauthorizedIssuance();
        }
        uint256 newLifetimeIssued = lifetimeIssuedNwei + request.snrgAmountNwei;
        if (newLifetimeIssued > issuanceCapNwei) revert IssuanceCapExceeded();
        lifetimeIssuedNwei = newLifetimeIssued;

        bytes32 fingerprint = _computeFingerprint(request);
        bytes32 saleKey = _computeSaleKey(
            request.paymentChainId,
            request.saleIdHash
        );

        if (processedFingerprints[fingerprint])
            revert DuplicateFingerprint(fingerprint);
        if (processedLedgerIds[request.ledgerId])
            revert DuplicateLedgerId(request.ledgerId);
        if (processedSaleKeys[saleKey]) revert DuplicateSaleKey(saleKey);

        processedFingerprints[fingerprint] = true;
        processedLedgerIds[request.ledgerId] = true;
        processedSaleKeys[saleKey] = true;

        tokenId = _nextTokenId;
        _nextTokenId = tokenId + 1;

        _minted[tokenId] = true;
        tokenFingerprint[tokenId] = fingerprint;
        tokenSaleKey[tokenId] = saleKey;
        _receiptURIs[tokenId] = request.metadataURI;

        // A fresh token ID always addresses fresh storage. Its redeemed flag remains false.
        Allocation storage allocation = _allocations[tokenId];
        allocation.ledgerId = request.ledgerId;
        allocation.saleIdHash = request.saleIdHash;
        allocation.walletAddress = request.walletAddress;
        allocation.purchaserAddress = request.purchaserAddress;
        allocation.networkIdHash = request.networkIdHash;
        allocation.paymentChainId = request.paymentChainId;
        allocation.assetSymbolHash = request.assetSymbolHash;
        allocation.snrgAmountNwei = request.snrgAmountNwei;
        allocation.paymentAmountRaw = request.paymentAmountRaw;
        allocation.paymentTokenAddress = request.paymentTokenAddress;
        allocation.paymentTokenDecimals = request.paymentTokenDecimals;
        allocation.paymentTxHash = request.paymentTxHash;
        allocation.stageFrom = request.stageFrom;
        allocation.stageTo = request.stageTo;
        allocation.stageId = request.stageId;
        allocation.priceUsdE8 = request.priceUsdE8;
        allocation.usdValueE8 = request.usdValueE8;
        allocation.purchaseTimestamp = request.purchaseTimestamp;
        allocation.sourceHash = request.sourceHash;
        allocation.vesting = request.vesting;

        _safeMint(request.purchaserAddress, tokenId);

        emit ReceiptMinted(
            tokenId,
            request.purchaserAddress,
            request.paymentChainId,
            request.ledgerId,
            request.saleIdHash,
            request.walletAddress,
            request.snrgAmountNwei,
            request.paymentAmountRaw,
            request.paymentTokenAddress,
            request.paymentTokenDecimals,
            request.paymentTxHash,
            request.stageFrom,
            request.stageTo,
            request.stageId,
            request.usdValueE8,
            request.priceUsdE8,
            request.sourceHash,
            fingerprint,
            saleKey
        );
    }

    /// @notice Locks a voucher while its exact owner-approved native settlement attempt is pending.
    /// @dev Native account control and acceptance must already be authenticated by the sealed verifier.
    ///      This transaction does not burn, transfer, or prove destination payment.
    /// @param tokenId Live active voucher owned by the caller.
    /// @param canonicalRecipient Exact 44-byte canonical SYNW_HEX_EIP55_V1 destination.
    /// @param admissionDeadline Last source timestamp accepted by the native recipient for this request.
    /// @param recipientAcceptanceProof Authenticated final native recipient-acceptance inclusion proof.
    /// @return attemptId The nonce-bound attempt committed in the source request event.
    function requestRedemption(
        uint256 tokenId,
        string calldata canonicalRecipient,
        uint64 admissionDeadline,
        bytes calldata recipientAcceptanceProof
    ) external nonReentrant whenNotPaused returns (bytes32 attemptId) {
        return
            _requestRedemption(
                tokenId,
                canonicalRecipient,
                admissionDeadline,
                recipientAcceptanceProof
            );
    }

    /// @notice V3 compatibility entry point for creating a pending request without burning the NFT.
    /// @dev The bytes parameter is a V3 native acceptance proof, never a V2 EIP-712/ERC-1271 signature.
    ///      Integrators must consume SynergyRedemptionRequestedV3 and the V3 lifecycle.
    /// @param tokenId Live active voucher owned by the caller.
    /// @param canonicalRecipient Exact canonical SYNW recipient.
    /// @param admissionDeadline Last source admission timestamp bound by the native acceptance.
    /// @param recipientAcceptanceProof Authenticated final native acceptance proof.
    /// @return attemptId New pending attempt identifier.
    function redeemToSynergy(
        uint256 tokenId,
        string calldata canonicalRecipient,
        uint64 admissionDeadline,
        bytes calldata recipientAcceptanceProof
    ) external nonReentrant whenNotPaused returns (bytes32 attemptId) {
        return
            _requestRedemption(
                tokenId,
                canonicalRecipient,
                admissionDeadline,
                recipientAcceptanceProof
            );
    }

    /// @notice Records owner intent to cancel the current attempt without changing its pending lock.
    /// @dev Cancellation intent remains available during a pause. It never proves non-payment and
    ///      never unlocks the NFT. Native settlement may win before cancellation becomes final.
    /// @param tokenId Pending voucher currently owned by the caller.
    function requestCancellation(uint256 tokenId) external nonReentrant {
        if (!_minted[tokenId]) revert TokenNotMinted(tokenId);
        if (_redemptionStates[tokenId] != RedemptionState.Pending)
            revert RedemptionNotPending(tokenId);
        RedemptionRecord storage redemption = _redemptions[tokenId];
        if (msg.sender != redemption.ethereumOwner)
            revert NotTokenOwner(msg.sender, tokenId);
        if (redemption.cancellationRequested)
            revert CancellationAlreadyRequested();
        redemption.cancellationRequested = true;
        emit RedemptionCancellationRequested(
            redemption.allocationKey,
            redemption.attemptId,
            tokenId,
            redemption.ethereumOwner,
            redemption.nonce,
            RedemptionTypesV3.requestLeaf(
                2,
                destinationNetworkIdHash,
                redemption.allocationKey,
                redemption.attemptId,
                redemption.amountNwei,
                redemption.recipientHash
            )
        );
    }

    /// @notice Acknowledges an authenticated final native settlement or cancellation outcome.
    /// @dev Anyone may relay the exact proof. Outcome 1 burns; outcome 2 unlocks the same NFT only
    ///      after its owner requested cancellation. Local timeouts and administrative overrides cannot
    ///      unlock or burn an entitlement. A pending deadline does not limit terminal acknowledgement.
    /// @param tokenId Voucher with a current pending attempt.
    /// @param outcome One for final settlement; two for a final destination cancellation tombstone.
    /// @param proof Authenticated finalized native outcome inclusion proof.
    function finalizeRedemption(
        uint256 tokenId,
        uint8 outcome,
        bytes calldata proof
    ) external nonReentrant whenNotPaused {
        if (!_minted[tokenId]) revert TokenNotMinted(tokenId);
        if (_redemptionStates[tokenId] != RedemptionState.Pending)
            revert RedemptionNotPending(tokenId);
        if (outcome != 1 && outcome != 2) revert InvalidRedemptionOutcome();
        RedemptionRecord storage redemption = _redemptions[tokenId];
        if (outcome == 2 && !redemption.cancellationRequested)
            revert CancellationNotRequested();
        if (
            !_configuredVerifier().verifyOutcome(
                destinationNetworkIdHash,
                redemption.allocationKey,
                redemption.attemptId,
                redemption.amountNwei,
                redemption.recipientHash,
                outcome,
                proof
            )
        ) revert InvalidRedemptionOutcome();

        // Each source token has exactly one pending attempt. Its immutable fields, not relayer inputs,
        // select the verified leaf. Old cancellation evidence therefore cannot unlock a newer attempt.
        redemption.outcome = outcome;
        finalizedAttemptOutcome[redemption.attemptId] = outcome;
        if (outcome == 1) {
            _redemptionStates[tokenId] = RedemptionState.Settled;
            _allocations[tokenId].redeemed = true;
            _burn(tokenId);
            emit ReceiptRedeemed(
                tokenId,
                redemption.ethereumOwner,
                redemption.amountNwei,
                block.timestamp
            );
        } else {
            _redemptionStates[tokenId] = RedemptionState.Active;
        }
        emit RedemptionFinalized(
            redemption.allocationKey,
            redemption.attemptId,
            tokenId,
            outcome,
            redemption.ethereumOwner,
            redemption.amountNwei,
            redemption.recipientHash
        );
    }

    /// @notice Computes the next exact native acceptance target for a live active voucher.
    /// @dev Uses the actual current owner and next monotonic nonce. A preview is not proof or authority;
    ///      another successful request can consume its nonce before a later transaction executes.
    /// @param tokenId Live active voucher identifier.
    /// @param canonicalRecipient Exact canonical native recipient.
    /// @return allocationKey Stable source allocation identity.
    /// @return attemptId The next owner-, recipient-, destination- and nonce-bound attempt.
    /// @return recipientHash Hash of the profile ID and right-padded bytes20 account.
    /// @return recipientAccount Raw 20-byte native account.
    /// @return nextNonce Next request nonce, beginning with one.
    function previewRedemption(
        uint256 tokenId,
        string calldata canonicalRecipient
    )
        external
        view
        returns (
            bytes32 allocationKey,
            bytes32 attemptId,
            bytes32 recipientHash,
            bytes20 recipientAccount,
            uint64 nextNonce
        )
    {
        if (!redemptionEnabled) revert RedemptionNotEnabled();
        address ethereumOwner = _activeOwner(tokenId);
        recipientAccount = RecipientCodec.decode(canonicalRecipient);
        recipientHash = RecipientCodec.identityHash(recipientAccount);
        allocationKey = allocationKeyOf(tokenId);
        nextNonce = attemptNonceOf[tokenId] + 1;
        attemptId = _computeAttemptId(
            allocationKey,
            nextNonce,
            ethereumOwner,
            _allocations[tokenId].snrgAmountNwei,
            recipientHash
        );
    }

    /// @notice Returns stable entitlement identity across all retries and recipient selections.
    /// @dev Original V2 allocation fingerprints are unchanged; V3 wraps them in a distinct source domain.
    ///      This collection has no historical alias import path; migration alias policy is separate.
    /// @param tokenId Historically minted voucher identifier.
    /// @return allocationKey Source chain-, collection-, sale- and token-bound allocation key.
    function allocationKeyOf(
        uint256 tokenId
    ) public view returns (bytes32 allocationKey) {
        if (!_minted[tokenId]) revert TokenNotMinted(tokenId);
        return
            keccak256(
                abi.encode(
                    ALLOCATION_DOMAIN,
                    block.chainid,
                    address(this),
                    saleProgramId,
                    tokenId,
                    tokenFingerprint[tokenId]
                )
            );
    }

    /// @notice Returns Active, Pending, or Settled for a historically minted voucher.
    /// @param tokenId Historically minted voucher identifier.
    /// @return state Current source lifecycle state.
    function redemptionStateOf(
        uint256 tokenId
    ) external view returns (RedemptionState state) {
        if (!_minted[tokenId]) revert TokenNotMinted(tokenId);
        return _redemptionStates[tokenId];
    }

    /// @notice Decodes the sole supported recipient profile and returns its typed identity hash.
    /// @dev Syntax validation does not prove account control, funding, or destination activation.
    /// @param canonicalRecipient Exact canonical SYNW_HEX_EIP55_V1 display value.
    /// @return account Raw 20-byte native account ID.
    /// @return recipientHash Profile-bound identity hash used by V3 evidence.
    function decodeRecipient(
        string calldata canonicalRecipient
    ) external pure returns (bytes20 account, bytes32 recipientHash) {
        account = RecipientCodec.decode(canonicalRecipient);
        recipientHash = RecipientCodec.identityHash(account);
    }

    /// @notice Returns immutable allocation facts and the current redemption status.
    /// @dev Historical records remain readable after the voucher is burned.
    /// @param tokenId Historically minted voucher identifier.
    /// @return Allocation record associated with the voucher.
    function allocationOf(
        uint256 tokenId
    ) external view returns (Allocation memory) {
        if (!_minted[tokenId]) revert TokenNotMinted(tokenId);
        return _allocations[tokenId];
    }

    /// @notice Returns the destination request recorded for a voucher.
    /// @dev Before its first request a voucher returns the default empty record; cancelled attempts remain readable.
    /// @param tokenId Historically minted voucher identifier.
    /// @return Persistent destination request, if one has been made.
    function redemptionOf(
        uint256 tokenId
    ) external view returns (RedemptionRecord memory) {
        if (!_minted[tokenId]) revert TokenNotMinted(tokenId);
        return _redemptions[tokenId];
    }

    /// @notice Computes the canonical fingerprint of a structurally valid mint request.
    /// @dev Does not mark the request as processed; the stable ABI encoding excludes mutable display data.
    /// @param request Allocation payload to validate and hash.
    /// @return Canonical allocation fingerprint.
    function computeFingerprint(
        MintRequest calldata request
    ) external view returns (bytes32) {
        _validateMintRequest(request);
        return _computeFingerprint(request);
    }

    /// @notice Computes the canonical replay-protection key for a sale reference.
    /// @dev Encoding is preserved for all historical indexers and minters.
    /// @param paymentChainId Nonzero identifier of the payment chain.
    /// @param saleIdHash Nonzero canonical sale identifier hash.
    /// @return Chain-bound sale key.
    function computeSaleKey(
        uint256 paymentChainId,
        bytes32 saleIdHash
    ) external pure returns (bytes32) {
        if (paymentChainId == 0) revert InvalidMintRequest();
        if (saleIdHash == bytes32(0)) revert InvalidMintRequest();
        return _computeSaleKey(paymentChainId, saleIdHash);
    }

    /// @notice Returns the next never-used voucher identifier.
    /// @dev Read-only estimate; another successful mint can consume this ID before a transaction executes.
    /// @return Next voucher token identifier.
    function nextTokenId() external view returns (uint256) {
        return _nextTokenId;
    }

    /// @notice Returns whether authenticated final native settlement caused the source voucher to burn.
    /// @dev Pending requests and finalized cancellations both return false.
    /// @param tokenId Historically minted voucher identifier.
    /// @return True only after acknowledgement of a verified Settled outcome.
    function isRedeemed(uint256 tokenId) external view returns (bool) {
        if (!_minted[tokenId]) revert TokenNotMinted(tokenId);
        return _allocations[tokenId].redeemed;
    }

    /// @notice Returns the immutable metadata URI for a historical receipt.
    /// @dev Retains receipt access after the ERC-721 token has been burned.
    /// @param tokenId Historically minted voucher identifier.
    /// @return Receipt metadata URI provided at mint time.
    function receiptURI(uint256 tokenId) external view returns (string memory) {
        if (!_minted[tokenId]) revert TokenNotMinted(tokenId);
        return _receiptURIs[tokenId];
    }

    /// @inheritdoc ERC721
    /// @dev Enforces live ERC-721 existence. Use receiptURI for historical metadata after redemption.
    function tokenURI(
        uint256 tokenId
    ) public view override returns (string memory) {
        _requireOwned(tokenId);
        return _receiptURIs[tokenId];
    }

    /// @notice Pauses minting, new redemption requests, and proof finalization during an incident.
    /// @dev Restricted to PAUSER_ROLE; OpenZeppelin emits Paused for the state transition.
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Resumes minting, new requests, and proof finalization after an incident is resolved.
    /// @dev Restricted to PAUSER_ROLE; OpenZeppelin emits Unpaused for the state transition.
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /// @inheritdoc ERC721
    /// @dev Always reverts because vouchers are soulbound; approval arguments are intentionally unused.
    function approve(
        address /* to */,
        uint256 /* tokenId */
    ) public pure override {
        revert SoulboundTransferBlocked();
    }

    /// @inheritdoc ERC721
    /// @dev Always reverts because vouchers are soulbound; operator arguments are intentionally unused.
    function setApprovalForAll(
        address /* operator */,
        bool /* approved */
    ) public pure override {
        revert SoulboundTransferBlocked();
    }

    // Standard transferFrom and both safeTransferFrom entry points are inherited. They all
    // reach _update, which rejects every wallet-to-wallet transfer before any receiver callback.

    /// @inheritdoc ERC721
    /// @dev This is internal super dispatch to OpenZeppelin implementations, not an external
    ///      interface probe against an untrusted contract.
    function supportsInterface(
        bytes4 interfaceId
    ) public view override(ERC721, AccessControl) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    /// @inheritdoc ERC721
    /// @dev Only minting from address zero or burning to address zero is permitted. There is no
    ///      public administrator burn function; only verified final settlement reaches _burn.
    function _update(
        address to,
        uint256 tokenId,
        address auth
    ) internal override returns (address) {
        address from = _ownerOf(tokenId);

        // Allow mint (from == 0) and burn (to == 0), but block wallet-to-wallet transfers.
        if (from != address(0)) {
            if (to != address(0)) revert SoulboundTransferBlocked();
        }

        return super._update(to, tokenId, auth);
    }

    /// @notice Creates a pending attempt after verifying the actual owner's exact native acceptance.
    /// @param tokenId Active voucher identifier.
    /// @param canonicalRecipient Canonical native recipient.
    /// @param admissionDeadline Native-accepted source admission deadline.
    /// @param recipientAcceptanceProof Authenticated native acceptance evidence.
    /// @return attemptId New pending attempt identifier.
    function _requestRedemption(
        uint256 tokenId,
        string calldata canonicalRecipient,
        uint64 admissionDeadline,
        bytes calldata recipientAcceptanceProof
    ) private returns (bytes32 attemptId) {
        IVoucherRedemptionEvidenceV3 verifier = _configuredVerifier();
        address ethereumOwner = _activeOwner(tokenId);
        if (ethereumOwner != msg.sender)
            revert NotTokenOwner(msg.sender, tokenId);
        if (block.timestamp > admissionDeadline)
            revert AuthorizationExpired(admissionDeadline);
        bytes20 recipientAccount = RecipientCodec.decode(canonicalRecipient);
        bytes32 recipientHash = RecipientCodec.identityHash(recipientAccount);
        bytes32 allocationKey = allocationKeyOf(tokenId);
        uint64 nonce = attemptNonceOf[tokenId] + 1;
        uint96 amountNwei = _allocations[tokenId].snrgAmountNwei;
        attemptId = _computeAttemptId(
            allocationKey,
            nonce,
            ethereumOwner,
            amountNwei,
            recipientHash
        );
        if (
            !verifier.verifyRecipientAcceptance(
                destinationNetworkIdHash,
                allocationKey,
                attemptId,
                amountNwei,
                recipientHash,
                admissionDeadline,
                recipientAcceptanceProof
            )
        ) revert InvalidRecipientAcceptance();

        attemptNonceOf[tokenId] = nonce;
        _redemptionStates[tokenId] = RedemptionState.Pending;
        _redemptions[tokenId] = RedemptionRecord({
            allocationKey: allocationKey,
            attemptId: attemptId,
            recipientHash: recipientHash,
            recipientAccount: recipientAccount,
            ethereumOwner: ethereumOwner,
            amountNwei: amountNwei,
            nonce: nonce,
            requestedAt: uint64(block.timestamp),
            admissionDeadline: admissionDeadline,
            cancellationRequested: false,
            outcome: 0,
            canonicalRecipient: canonicalRecipient
        });
        emit SynergyRedemptionRequestedV3(
            allocationKey,
            attemptId,
            tokenId,
            ethereumOwner,
            tokenFingerprint[tokenId],
            saleProgramId,
            destinationNetworkIdHash,
            recipientProfileId,
            recipientHash,
            recipientAccount,
            canonicalRecipient,
            amountNwei,
            nonce,
            admissionDeadline,
            uint64(block.timestamp),
            block.chainid,
            RedemptionTypesV3.requestLeaf(
                1,
                destinationNetworkIdHash,
                allocationKey,
                attemptId,
                amountNwei,
                recipientHash
            )
        );
    }

    /// @notice Returns the current owner only when an issued voucher is active and unsettled.
    /// @param tokenId Historically minted voucher identifier.
    /// @return ethereumOwner Current owner of the active source voucher.
    function _activeOwner(
        uint256 tokenId
    ) private view returns (address ethereumOwner) {
        if (!_minted[tokenId]) revert TokenNotMinted(tokenId);
        RedemptionState state = _redemptionStates[tokenId];
        if (state == RedemptionState.Settled) revert AlreadyRedeemed(tokenId);
        if (state == RedemptionState.Pending) revert RedemptionPending(tokenId);
        return ownerOf(tokenId);
    }

    /// @notice Returns the sealed verifier only while its reviewed runtime remains intact.
    /// @return verifier The permanently selected V3 authenticated evidence implementation.
    function _configuredVerifier()
        private
        view
        returns (IVoucherRedemptionEvidenceV3 verifier)
    {
        if (!redemptionEnabled) revert RedemptionNotEnabled();
        if (outcomeVerifier.codehash != outcomeVerifierCodeHash)
            revert RedemptionVerifierChanged();
        return IVoucherRedemptionEvidenceV3(outcomeVerifier);
    }

    /// @notice Computes one destination attempt without changing the stable allocation identity.
    /// @dev abi.encode uses fixed-width 32-byte words; amount and nonce are unsigned integers.
    /// @param allocationKey Stable entitlement identity.
    /// @param nonce Monotonic source attempt nonce.
    /// @param ethereumOwner Actual source NFT owner.
    /// @param amountNwei Immutable entitlement in native nWei.
    /// @param recipientHash Profile-bound raw native account hash.
    /// @return attemptId Exact V3 attempt identifier.
    function _computeAttemptId(
        bytes32 allocationKey,
        uint64 nonce,
        address ethereumOwner,
        uint96 amountNwei,
        bytes32 recipientHash
    ) private view returns (bytes32 attemptId) {
        return
            keccak256(
                abi.encode(
                    ATTEMPT_DOMAIN,
                    allocationKey,
                    nonce,
                    destinationNetworkIdHash,
                    ethereumOwner,
                    amountNwei,
                    recipientHash
                )
            );
    }

    /// @notice Computes the stable hash of the canonical mint payload.
    /// @dev Keep the ABI-encoded fields and ordering unchanged to preserve historical compatibility.
    /// @param request Validated mint payload.
    /// @return Canonical immutable allocation fingerprint.
    function _computeFingerprint(
        MintRequest calldata request
    ) internal view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    saleProgramId,
                    request.ledgerId,
                    request.saleIdHash,
                    request.walletAddress,
                    request.purchaserAddress,
                    request.networkIdHash,
                    request.paymentChainId,
                    request.assetSymbolHash,
                    request.snrgAmountNwei,
                    request.paymentAmountRaw,
                    request.paymentTokenAddress,
                    request.paymentTokenDecimals,
                    request.paymentTxHash,
                    request.stageFrom,
                    request.stageTo,
                    request.stageId,
                    request.priceUsdE8,
                    request.usdValueE8,
                    request.purchaseTimestamp,
                    request.sourceHash,
                    request.vesting.vestingStart,
                    request.vesting.cliffSeconds,
                    request.vesting.durationSeconds,
                    request.vesting.initialUnlockBps
                )
            );
    }

    /// @notice Computes a payment-chain-specific sale reference key.
    /// @dev Uses the existing ABI encoding to preserve duplicate protection across integrations.
    /// @param paymentChainId Payment chain identifier.
    /// @param saleIdHash Canonical sale reference hash.
    /// @return Chain-specific sale key.
    function _computeSaleKey(
        uint256 paymentChainId,
        bytes32 saleIdHash
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(paymentChainId, saleIdHash));
    }

    /// @notice Validates a mint payload before storage changes or callbacks can occur.
    /// @dev A zero payment-token address denotes native currency and is intentionally valid.
    ///      The issuance policy separately binds all fields to canonical paid-purchase or reward state.
    ///      Historical imports into this new collection are not supported.
    /// @param request Mint payload to validate.
    function _validateMintRequest(MintRequest calldata request) internal view {
        if (request.ledgerId == 0) revert InvalidMintRequest();
        if (request.saleIdHash == bytes32(0)) revert InvalidMintRequest();
        if (request.walletAddress == address(0)) revert InvalidMintRequest();
        if (request.purchaserAddress == address(0)) revert InvalidMintRequest();
        if (request.networkIdHash == bytes32(0)) revert InvalidMintRequest();
        if (request.paymentChainId == 0) revert InvalidMintRequest();
        if (request.assetSymbolHash == bytes32(0)) revert InvalidMintRequest();
        if (request.snrgAmountNwei == 0) revert InvalidMintRequest();
        if (request.paymentAmountRaw == 0) revert InvalidMintRequest();
        if (request.paymentTxHash == bytes32(0)) revert InvalidMintRequest();
        if (request.priceUsdE8 == 0) revert InvalidMintRequest();
        if (request.usdValueE8 == 0) revert InvalidMintRequest();
        if (request.purchaseTimestamp == 0) revert InvalidMintRequest();
        if (request.purchaseTimestamp > block.timestamp)
            revert InvalidMintRequest();
        if (request.sourceHash == bytes32(0)) revert InvalidMintRequest();
        if (request.statusHash != keccak256("confirmed"))
            revert InvalidMintRequest();
        if (!request.processedPaymentTx) revert InvalidMintRequest();
        if (request.nftMinted) revert InvalidMintRequest();
        if (bytes(request.metadataURI).length == 0) revert InvalidMintRequest();

        if (request.stageFrom == 0) revert InvalidStageRange();
        if (request.stageTo == 0) revert InvalidStageRange();
        if (request.stageId == 0) revert InvalidStageRange();
        if (request.stageFrom > request.stageTo) revert InvalidStageRange();
        if (request.stageId < request.stageFrom) revert InvalidStageRange();
        if (request.stageId > request.stageTo) revert InvalidStageRange();

        if (request.paymentTokenDecimals == 0)
            revert InvalidPaymentTokenDecimals();
        if (request.paymentTokenDecimals > MAX_PAYMENT_TOKEN_DECIMALS) {
            revert InvalidPaymentTokenDecimals();
        }

        if (request.vesting.vestingStart != 0) revert InvalidVestingTerms();
        if (request.vesting.cliffSeconds != 0) revert InvalidVestingTerms();
        if (request.vesting.durationSeconds != 0) revert InvalidVestingTerms();
        if (request.vesting.initialUnlockBps != MAX_BPS)
            revert InvalidVestingTerms();
    }

    /// @inheritdoc AccessControl
    /// @dev Rejects zero-address grantees and all minter grants outside the permanent issuer seal.
    ///      Standard role authorization, revocation, renunciation and RoleGranted events remain unchanged.
    function _grantRole(
        bytes32 role,
        address account
    ) internal override returns (bool) {
        if (account == address(0)) revert ZeroAddress();
        if (role == MINTER_ROLE) {
            if (!issuanceSealed) revert IssuanceNotSealed();
            if (account != sealedPresale) {
                if (account != sealedReferralAuthorizer)
                    revert UnauthorizedIssuance();
            }
        }
        return super._grantRole(role, account);
    }
}
