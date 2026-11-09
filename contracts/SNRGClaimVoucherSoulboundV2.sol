// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

/// @title SNRGClaimVoucherSoulboundV2
/// @notice Ethereum claim voucher whose owner can request settlement in native SNRG on Synergy Network.
/// @dev This contract does not move assets across chains. It burns the Ethereum voucher and emits a
///      destination-bound claim that a Synergy bridge/settlement service must finalize exactly once.
/// @dev SNRG uses 9 decimals. Every `snrgAmountNwei` value is already expressed in the smallest native
///      SNRG unit: 1 SNRG = 1_000_000_000 nWei. No 18-decimal conversion is performed anywhere.
contract SNRGClaimVoucherSoulboundV2 is
    ERC721,
    AccessControl,
    Pausable,
    ReentrancyGuard,
    EIP712
{
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    uint8 public constant SNRG_DECIMALS = 9;
    uint256 public constant SNRG_BASE_UNIT = 1_000_000_000;

    uint256 private constant MAX_BPS = 10_000;
    uint8 private constant MAX_PAYMENT_TOKEN_DECIMALS = 36;
    uint256 private constant MAX_SYNERGY_RECIPIENT_BYTES = 128;

    bytes32 public constant CLAIM_DOMAIN = keccak256("SNRG_NATIVE_CLAIM_V1");

    bytes32 public constant REDEEM_AUTHORIZATION_TYPEHASH = keccak256(
        "RedeemAuthorization(uint256 tokenId,address ethereumOwner,bytes32 voucherFingerprint,bytes32 saleProgramId,bytes32 destinationNetworkIdHash,uint96 snrgAmountNwei,bytes32 synergyRecipientHash,uint64 deadline)"
    );

    /// @notice Immutable identifier for the sale program this voucher contract represents.
    bytes32 public immutable saleProgramId;

    /// @notice Hash of the canonical destination network identifier, for example
    ///         keccak256(bytes("synergy-mainnet-beta")). Use the network's canonical identifier.
    bytes32 public immutable destinationNetworkIdHash;

    /// @notice Ethereum address or ERC-1271 contract that authorizes a validated Synergy recipient.
    /// @dev Operate this as a multisig or tightly controlled bridge signer, not a browser hot key.
    address public redemptionAuthorizer;

    uint256 private _nextTokenId = 1;

    error ZeroAddress();
    error InvalidSaleProgramId();
    error InvalidDestinationNetworkId();
    error InvalidMintRequest();
    error InvalidStageRange();
    error InvalidPaymentTokenDecimals();
    error InvalidVestingTerms();
    error InvalidSynergyRecipient();
    error AuthorizationExpired(uint64 deadline);
    error InvalidRedemptionAuthorization();
    error DuplicateFingerprint(bytes32 fingerprint);
    error DuplicateLedgerId(uint64 ledgerId);
    error DuplicateSaleKey(bytes32 saleKey);
    error DuplicateClaimId(bytes32 claimId);
    error TokenNotMinted(uint256 tokenId);
    error NotTokenOwner(address caller, uint256 tokenId);
    error AlreadyRedeemed(uint256 tokenId);
    error SoulboundTransferBlocked();

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

    struct RedemptionRecord {
        bytes32 claimId;
        bytes32 synergyRecipientHash;
        uint64 requestedAt;
        string synergyRecipient;
    }

    mapping(uint256 => Allocation) private _allocations;
    mapping(uint256 => bool) private _minted;
    mapping(uint256 => string) private _receiptURIs;
    mapping(uint256 => RedemptionRecord) private _redemptions;

    /// @notice Computed payment/allocation fingerprint => processed flag.
    mapping(bytes32 => bool) public processedFingerprints;

    /// @notice Presale ledger row id => processed flag.
    mapping(uint64 => bool) public processedLedgerIds;

    /// @notice sale key, computed as keccak256(abi.encode(paymentChainId, saleIdHash)) => processed flag.
    mapping(bytes32 => bool) public processedSaleKeys;

    /// @notice claim ID => emitted flag. The destination must maintain its own processed-claim mapping too.
    mapping(bytes32 => bool) public emittedClaimIds;

    /// @notice tokenId => computed payment/allocation fingerprint.
    mapping(uint256 => bytes32) public tokenFingerprint;

    /// @notice tokenId => computed sale key.
    mapping(uint256 => bytes32) public tokenSaleKey;

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

    /// @notice Canonical source-chain event consumed by the Synergy settlement layer.
    /// @dev `snrgAmountNwei` must be relayed exactly, with no decimal conversion.
    event SynergyRedemptionRequested(
        bytes32 indexed claimId,
        uint256 indexed tokenId,
        address indexed ethereumOwner,
        bytes32 voucherFingerprint,
        bytes32 saleProgramId,
        bytes32 destinationNetworkIdHash,
        bytes32 synergyRecipientHash,
        string synergyRecipient,
        uint96 snrgAmountNwei,
        uint64 vestingStart,
        uint32 cliffSeconds,
        uint32 durationSeconds,
        uint16 initialUnlockBps,
        uint256 ethereumChainId,
        uint256 requestedAt
    );

    /// @notice Legacy-friendly summary event for indexers already consuming ReceiptRedeemed.
    event ReceiptRedeemed(
        uint256 indexed tokenId,
        address indexed purchaserAddress,
        uint96 snrgAmountNwei,
        uint256 redeemedAt
    );

    event RedemptionAuthorizerUpdated(address indexed previousAuthorizer, address indexed newAuthorizer);

    constructor(
        address admin_,
        bytes32 saleProgramId_,
        bytes32 destinationNetworkIdHash_,
        address redemptionAuthorizer_
    )
        ERC721("Synergy Claim Voucher", "SNRG-CV")
        EIP712("Synergy SNRG Claim Voucher", "2")
    {
        if (admin_ == address(0) || redemptionAuthorizer_ == address(0)) revert ZeroAddress();
        if (saleProgramId_ == bytes32(0)) revert InvalidSaleProgramId();
        if (destinationNetworkIdHash_ == bytes32(0)) revert InvalidDestinationNetworkId();

        saleProgramId = saleProgramId_;
        destinationNetworkIdHash = destinationNetworkIdHash_;
        redemptionAuthorizer = redemptionAuthorizer_;

        _grantRole(DEFAULT_ADMIN_ROLE, admin_);
        _grantRole(MINTER_ROLE, admin_);
        _grantRole(PAUSER_ROLE, admin_);
    }

    function mintReceipt(
        MintRequest calldata request
    ) external onlyRole(MINTER_ROLE) whenNotPaused nonReentrant returns (uint256 tokenId) {
        _validateMintRequest(request);

        bytes32 fingerprint = _computeFingerprint(request);
        bytes32 saleKey = _computeSaleKey(request.paymentChainId, request.saleIdHash);

        if (processedFingerprints[fingerprint]) revert DuplicateFingerprint(fingerprint);
        if (processedLedgerIds[request.ledgerId]) revert DuplicateLedgerId(request.ledgerId);
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

        _allocations[tokenId] = Allocation({
            ledgerId: request.ledgerId,
            saleIdHash: request.saleIdHash,
            walletAddress: request.walletAddress,
            purchaserAddress: request.purchaserAddress,
            networkIdHash: request.networkIdHash,
            paymentChainId: request.paymentChainId,
            assetSymbolHash: request.assetSymbolHash,
            snrgAmountNwei: request.snrgAmountNwei,
            paymentAmountRaw: request.paymentAmountRaw,
            paymentTokenAddress: request.paymentTokenAddress,
            paymentTokenDecimals: request.paymentTokenDecimals,
            paymentTxHash: request.paymentTxHash,
            stageFrom: request.stageFrom,
            stageTo: request.stageTo,
            stageId: request.stageId,
            priceUsdE8: request.priceUsdE8,
            usdValueE8: request.usdValueE8,
            purchaseTimestamp: request.purchaseTimestamp,
            sourceHash: request.sourceHash,
            vesting: request.vesting,
            redeemed: false
        });

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

    /// @notice Burns a voucher and creates a destination-bound native SNRG settlement request.
    /// @param tokenId Voucher token ID owned by the caller.
    /// @param synergyRecipient Canonical Synergy mainnet-beta address string validated by the authorizer.
    /// @param authorizationDeadline Last Ethereum timestamp at which the authorization is valid.
    /// @param authorizationSignature EIP-712 signature from `redemptionAuthorizer`.
    /// @return claimId Canonical cross-chain claim ID used for destination replay protection.
    function redeemToSynergy(
        uint256 tokenId,
        string calldata synergyRecipient,
        uint64 authorizationDeadline,
        bytes calldata authorizationSignature
    ) external whenNotPaused nonReentrant returns (bytes32 claimId) {
        if (!_minted[tokenId]) revert TokenNotMinted(tokenId);

        Allocation storage allocation = _allocations[tokenId];
        if (allocation.redeemed) revert AlreadyRedeemed(tokenId);
        if (ownerOf(tokenId) != msg.sender) revert NotTokenOwner(msg.sender, tokenId);

        bytes memory recipientBytes = bytes(synergyRecipient);
        if (
            recipientBytes.length == 0 ||
            recipientBytes.length > MAX_SYNERGY_RECIPIENT_BYTES
        ) {
            revert InvalidSynergyRecipient();
        }
        if (block.timestamp > authorizationDeadline) {
            revert AuthorizationExpired(authorizationDeadline);
        }

        bytes32 fingerprint = tokenFingerprint[tokenId];
        bytes32 recipientHash = keccak256(recipientBytes);
        bytes32 digest = _redemptionAuthorizationDigest(
            tokenId,
            msg.sender,
            fingerprint,
            allocation.snrgAmountNwei,
            recipientHash,
            authorizationDeadline
        );

        if (
            !SignatureChecker.isValidSignatureNow(
                redemptionAuthorizer,
                digest,
                authorizationSignature
            )
        ) {
            revert InvalidRedemptionAuthorization();
        }

        claimId = _computeClaimId(
            tokenId,
            msg.sender,
            fingerprint,
            allocation.snrgAmountNwei,
            recipientHash
        );
        if (emittedClaimIds[claimId]) revert DuplicateClaimId(claimId);

        // Effects precede the ERC-721 burn. Destination settlement is asynchronous and must
        // independently reject any replay of this claim ID.
        allocation.redeemed = true;
        emittedClaimIds[claimId] = true;
        _redemptions[tokenId] = RedemptionRecord({
            claimId: claimId,
            synergyRecipientHash: recipientHash,
            requestedAt: uint64(block.timestamp),
            synergyRecipient: synergyRecipient
        });

        _burn(tokenId);

        VestingTerms memory vesting = allocation.vesting;
        emit SynergyRedemptionRequested(
            claimId,
            tokenId,
            msg.sender,
            fingerprint,
            saleProgramId,
            destinationNetworkIdHash,
            recipientHash,
            synergyRecipient,
            allocation.snrgAmountNwei,
            vesting.vestingStart,
            vesting.cliffSeconds,
            vesting.durationSeconds,
            vesting.initialUnlockBps,
            block.chainid,
            block.timestamp
        );

        emit ReceiptRedeemed(
            tokenId,
            msg.sender,
            allocation.snrgAmountNwei,
            block.timestamp
        );
    }

    /// @notice Returns the EIP-712 digest the authorizer must sign for a redemption.
    function redemptionAuthorizationDigest(
        uint256 tokenId,
        address ethereumOwner,
        string calldata synergyRecipient,
        uint64 deadline
    ) external view returns (bytes32) {
        if (!_minted[tokenId]) revert TokenNotMinted(tokenId);
        bytes memory recipientBytes = bytes(synergyRecipient);
        if (
            recipientBytes.length == 0 ||
            recipientBytes.length > MAX_SYNERGY_RECIPIENT_BYTES
        ) {
            revert InvalidSynergyRecipient();
        }

        return _redemptionAuthorizationDigest(
            tokenId,
            ethereumOwner,
            tokenFingerprint[tokenId],
            _allocations[tokenId].snrgAmountNwei,
            keccak256(recipientBytes),
            deadline
        );
    }

    /// @notice Computes the exact claim ID that `redeemToSynergy` will emit.
    function previewClaimId(
        uint256 tokenId,
        address ethereumOwner,
        string calldata synergyRecipient
    ) external view returns (bytes32) {
        if (!_minted[tokenId]) revert TokenNotMinted(tokenId);
        bytes memory recipientBytes = bytes(synergyRecipient);
        if (
            recipientBytes.length == 0 ||
            recipientBytes.length > MAX_SYNERGY_RECIPIENT_BYTES
        ) {
            revert InvalidSynergyRecipient();
        }

        return _computeClaimId(
            tokenId,
            ethereumOwner,
            tokenFingerprint[tokenId],
            _allocations[tokenId].snrgAmountNwei,
            keccak256(recipientBytes)
        );
    }

    function setRedemptionAuthorizer(address newAuthorizer) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newAuthorizer == address(0)) revert ZeroAddress();
        address previousAuthorizer = redemptionAuthorizer;
        redemptionAuthorizer = newAuthorizer;
        emit RedemptionAuthorizerUpdated(previousAuthorizer, newAuthorizer);
    }

    function allocationOf(uint256 tokenId) external view returns (Allocation memory) {
        if (!_minted[tokenId]) revert TokenNotMinted(tokenId);
        return _allocations[tokenId];
    }

    function redemptionOf(uint256 tokenId) external view returns (RedemptionRecord memory) {
        if (!_minted[tokenId]) revert TokenNotMinted(tokenId);
        return _redemptions[tokenId];
    }

    function computeFingerprint(MintRequest calldata request) external view returns (bytes32) {
        _validateMintRequest(request);
        return _computeFingerprint(request);
    }

    function computeSaleKey(uint256 paymentChainId, bytes32 saleIdHash) external pure returns (bytes32) {
        if (paymentChainId == 0 || saleIdHash == bytes32(0)) revert InvalidMintRequest();
        return _computeSaleKey(paymentChainId, saleIdHash);
    }

    function nextTokenId() external view returns (uint256) {
        return _nextTokenId;
    }

    function isRedeemed(uint256 tokenId) external view returns (bool) {
        if (!_minted[tokenId]) revert TokenNotMinted(tokenId);
        return _allocations[tokenId].redeemed;
    }

    function receiptURI(uint256 tokenId) external view returns (string memory) {
        if (!_minted[tokenId]) revert TokenNotMinted(tokenId);
        return _receiptURIs[tokenId];
    }

    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        if (!_minted[tokenId]) revert TokenNotMinted(tokenId);
        return _receiptURIs[tokenId];
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    function approve(address, uint256) public override {
        revert SoulboundTransferBlocked();
    }

    function setApprovalForAll(address, bool) public override {
        revert SoulboundTransferBlocked();
    }

    function transferFrom(address, address, uint256) public override {
        revert SoulboundTransferBlocked();
    }

    function safeTransferFrom(address, address, uint256, bytes memory) public override {
        revert SoulboundTransferBlocked();
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721, AccessControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function _update(address to, uint256 tokenId, address auth)
        internal
        override
        returns (address)
    {
        address from = _ownerOf(tokenId);

        // Allow mint (from == 0) and burn (to == 0), but block wallet-to-wallet transfers.
        if (from != address(0) && to != address(0)) {
            revert SoulboundTransferBlocked();
        }

        return super._update(to, tokenId, auth);
    }

    function _redemptionAuthorizationDigest(
        uint256 tokenId,
        address ethereumOwner,
        bytes32 fingerprint,
        uint96 snrgAmountNwei,
        bytes32 recipientHash,
        uint64 deadline
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                REDEEM_AUTHORIZATION_TYPEHASH,
                tokenId,
                ethereumOwner,
                fingerprint,
                saleProgramId,
                destinationNetworkIdHash,
                snrgAmountNwei,
                recipientHash,
                deadline
            )
        );
        return _hashTypedDataV4(structHash);
    }

    function _computeClaimId(
        uint256 tokenId,
        address ethereumOwner,
        bytes32 fingerprint,
        uint96 snrgAmountNwei,
        bytes32 recipientHash
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                CLAIM_DOMAIN,
                block.chainid,
                address(this),
                saleProgramId,
                destinationNetworkIdHash,
                tokenId,
                ethereumOwner,
                fingerprint,
                snrgAmountNwei,
                recipientHash
            )
        );
    }

    function _computeFingerprint(MintRequest calldata request) internal view returns (bytes32) {
        return keccak256(
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

    function _computeSaleKey(uint256 paymentChainId, bytes32 saleIdHash) internal pure returns (bytes32) {
        return keccak256(abi.encode(paymentChainId, saleIdHash));
    }

    function _validateMintRequest(MintRequest calldata request) internal pure {
        if (
            request.ledgerId == 0 ||
            request.saleIdHash == bytes32(0) ||
            request.walletAddress == address(0) ||
            request.purchaserAddress == address(0) ||
            request.networkIdHash == bytes32(0) ||
            request.paymentChainId == 0 ||
            request.assetSymbolHash == bytes32(0) ||
            request.snrgAmountNwei == 0 ||
            request.paymentAmountRaw == 0 ||
            request.paymentTxHash == bytes32(0) ||
            request.priceUsdE8 == 0 ||
            request.usdValueE8 == 0 ||
            request.purchaseTimestamp == 0 ||
            request.sourceHash == bytes32(0) ||
            request.statusHash != keccak256(bytes("confirmed")) ||
            !request.processedPaymentTx ||
            request.nftMinted ||
            bytes(request.metadataURI).length == 0
        ) {
            revert InvalidMintRequest();
        }

        if (
            request.stageFrom == 0 ||
            request.stageTo == 0 ||
            request.stageId == 0 ||
            request.stageFrom > request.stageTo ||
            request.stageId < request.stageFrom ||
            request.stageId > request.stageTo
        ) {
            revert InvalidStageRange();
        }

        if (
            request.paymentTokenDecimals == 0 ||
            request.paymentTokenDecimals > MAX_PAYMENT_TOKEN_DECIMALS
        ) {
            revert InvalidPaymentTokenDecimals();
        }

        if (request.vesting.initialUnlockBps > MAX_BPS) revert InvalidVestingTerms();
        if (request.vesting.durationSeconds == 0 && request.vesting.cliffSeconds != 0) {
            revert InvalidVestingTerms();
        }
        if (request.vesting.durationSeconds > 0) {
            if (request.vesting.vestingStart == 0) revert InvalidVestingTerms();
            if (request.vesting.cliffSeconds > request.vesting.durationSeconds) {
                revert InvalidVestingTerms();
            }
        }
    }
}
