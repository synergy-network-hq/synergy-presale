// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

/// @title Presale Migration Registry
/// @author Synergy Network
/// @notice Holds approved historical purchaser, referrer and referral-code data for one presale.
/// @dev Only the verified Treasury Safe can import or rewind rows. Only the immutable deploying
///      presale can seal imports during activation, permanently preventing subsequent edits.
///      This separate immutable helper keeps the presale below Ethereum's runtime code-size limit.
contract PresaleMigrationRegistry {
    /// @notice The deploying presale and only authority allowed to seal approved imports.
    address public immutable presale;
    /// @notice Verified immutable Treasury Safe and only authority allowed to import or rewind history.
    address public immutable treasury;
    /// @notice Approved ordered purchaser manifest; zero represents an empty list.
    bytes32 public immutable purchaserManifestHash;
    /// @notice Approved ordered historical-referrer manifest; zero represents an empty list.
    bytes32 public immutable referrerManifestHash;
    /// @notice Approved ordered legacy code manifest; zero represents an empty list.
    bytes32 public immutable codeManifestHash;
    /// @notice Whether every purchaser must have an explicit historical referrer row before sealing.
    bool public immutable requireCompleteBindings;
    /// @notice True after the presale permanently seals successful imports during activation.
    bool public isSealed;
    /// @notice Running historical purchaser manifest commitment.
    bytes32 public importedPurchaserManifestHash;
    /// @notice Running historical referrer-binding manifest commitment.
    bytes32 public importedReferrerManifestHash;
    /// @notice Running legacy referral-code manifest commitment.
    bytes32 public importedReferralCodeManifestHash;
    /// @notice Last historical purchaser imported in ascending address order.
    address public lastImportedPurchaser;
    /// @notice Last historical buyer whose binding was imported in ascending address order.
    address public lastImportedReferrerBuyer;
    /// @notice Last imported legacy referral code in ascending hash order.
    bytes32 public lastImportedReferralCode;
    /// @notice Imported historical purchase counts.
    mapping(address buyer => uint256 count) public buyerPurchaseCount;
    /// @notice Imported referral eligibility, independent of new sale activity.
    mapping(address account => bool eligible) public referralEligible;
    /// @notice Explicit approved historical buyer-to-referrer bindings.
    mapping(address buyer => address referrer) public assignedReferrer;
    /// @notice Imported legacy referral-code owners.
    mapping(bytes32 codeHash => address owner) public referralCodeOwner;
    /// @notice Imported legacy code assigned to each owner.
    mapping(address owner => bytes32 codeHash) public walletReferralCode;

    /// @dev Shared layout for bounded rollback of any import stream.
    struct ImportCheckpoint {
        bytes32 key;
        bytes32 manifestHash;
    }
    ImportCheckpoint[] private _purchasers;
    ImportCheckpoint[] private _referrers;
    ImportCheckpoint[] private _codes;
    /// @notice Maximum number of trailing rows removable by one rollback transaction.
    uint256 public constant MAX_IMPORT_ROLLBACK = 200;

    /// @notice The caller lacks the immutable Treasury Safe or presale authority required for this operation.
    error Unauthorized();
    /// @notice Imported rows, ordering, counts or approved manifest commitments are inconsistent.
    error InvalidImport();
    /// @notice Imports have been permanently sealed against further mutation.
    error RegistrySealed();

    /// @notice Records a historical purchaser import and its cumulative hash.
    event HistoricalPurchaserImported(
        address indexed purchaser,
        uint256 purchaseCount,
        bool eligible,
        bytes32 cumulativeManifestHash
    );
    /// @notice Records one approved historical referrer binding.
    event HistoricalReferrerImported(
        address indexed buyer,
        address indexed referrer,
        bytes32 cumulativeManifestHash
    );
    /// @notice Records an approved imported legacy code assignment.
    event ReferralCodeRegistered(
        bytes32 indexed codeHash,
        address indexed owner
    );
    /// @notice Records a bounded pre-activation rewind without changing the approved root.
    event ImportRolledBack(
        bytes32 indexed importKind,
        uint256 removedRows,
        bytes32 resultingManifestHash
    );
    /// @notice Records that all approved import streams are permanently frozen.
    event ImportsSealed(
        bytes32 indexed purchasers,
        bytes32 indexed referrers,
        bytes32 indexed codes
    );

    /// @notice Restricts import and rollback to the verified Treasury Safe before permanent sealing.
    /// @dev The presale validates the canonical treasury before creating this immutable registry.
    modifier onlyTreasuryUnsealed() {
        if (msg.sender != treasury) revert Unauthorized();
        if (isSealed) revert RegistrySealed();
        _;
    }

    /// @notice Creates an immutable registry bound to its deploying presale and approved roots.
    /// @dev A zero root explicitly represents an empty manifest; the presale validates history policy.
    /// @param treasurySafe Verified canonical Treasury Safe supplied by the deploying presale.
    /// @param purchasers Approved purchaser hash chain.
    /// @param referrers Approved historical referrer hash chain.
    /// @param codes Approved legacy code hash chain.
    /// @param completeBindings Whether every purchaser must have a binding row at seal time.
    constructor(
        address treasurySafe,
        bytes32 purchasers,
        bytes32 referrers,
        bytes32 codes,
        bool completeBindings
    ) {
        if (treasurySafe == address(0)) revert InvalidImport();
        presale = msg.sender;
        treasury = treasurySafe;
        purchaserManifestHash = purchasers;
        referrerManifestHash = referrers;
        codeManifestHash = codes;
        requireCompleteBindings = completeBindings;
    }

    /// @notice Imports historical purchaser counts and eligibility in strictly ascending address order.
    /// @dev No vouchers or entitlements are minted. Checkpoints permit bounded correction before sealing.
    /// @param accounts Strictly ascending purchaser addresses continuing any earlier batch.
    /// @param counts Positive historical purchase counts.
    /// @param eligible Approved historical referral eligibility flags.
    function importHistoricalPurchasers(
        address[] calldata accounts,
        uint256[] calldata counts,
        bool[] calldata eligible
    ) external onlyTreasuryUnsealed {
        uint256 length = accounts.length;
        if (length == 0 || length != counts.length || length != eligible.length)
            revert InvalidImport();
        address previous = lastImportedPurchaser;
        bytes32 manifest = importedPurchaserManifestHash;
        for (uint256 i; i < length; ++i) {
            address account = accounts[i];
            uint256 count = counts[i];
            bool canRefer = eligible[i];
            if (account <= previous || count == 0) revert InvalidImport();
            previous = account;
            buyerPurchaseCount[account] = count;
            referralEligible[account] = canRefer;
            manifest = keccak256(
                abi.encode(manifest, account, count, canRefer)
            );
            _purchasers.push(
                ImportCheckpoint(bytes32(uint256(uint160(account))), manifest)
            );
            emit HistoricalPurchaserImported(
                account,
                count,
                canRefer,
                manifest
            );
        }
        lastImportedPurchaser = previous;
        importedPurchaserManifestHash = manifest;
    }

    /// @notice Imports approved legacy referral codes in strictly ascending hash order.
    /// @dev A code and its owner may appear only once; both lookup directions are written together.
    /// @param codes Canonical legacy code hashes.
    /// @param owners Corresponding nonzero owners.
    function importReferralCodes(
        bytes32[] calldata codes,
        address[] calldata owners
    ) external onlyTreasuryUnsealed {
        uint256 length = codes.length;
        if (length == 0 || length != owners.length) revert InvalidImport();
        bytes32 previous = lastImportedReferralCode;
        bytes32 manifest = importedReferralCodeManifestHash;
        for (uint256 i; i < length; ++i) {
            bytes32 code = codes[i];
            address owner = owners[i];
            if (
                code <= previous ||
                owner == address(0) ||
                referralCodeOwner[code] != address(0) ||
                walletReferralCode[owner] != bytes32(0)
            ) revert InvalidImport();
            previous = code;
            referralCodeOwner[code] = owner;
            walletReferralCode[owner] = code;
            manifest = keccak256(abi.encode(manifest, code, owner));
            _codes.push(ImportCheckpoint(code, manifest));
            emit ReferralCodeRegistered(code, owner);
        }
        lastImportedReferralCode = previous;
        importedReferralCodeManifestHash = manifest;
    }

    /// @notice Restores approved historical referrer bindings for already-imported purchasers.
    /// @dev Zero referrer explicitly means no prior binding; nonzero self-referrals are rejected.
    /// @param buyers Strictly ascending already-imported purchaser addresses.
    /// @param referrers Their approved prior referrers, including explicit zero values.
    function importHistoricalReferrers(
        address[] calldata buyers,
        address[] calldata referrers
    ) external onlyTreasuryUnsealed {
        uint256 length = buyers.length;
        if (length == 0 || length != referrers.length) revert InvalidImport();
        address previous = lastImportedReferrerBuyer;
        bytes32 manifest = importedReferrerManifestHash;
        for (uint256 i; i < length; ++i) {
            address buyer = buyers[i];
            address referrer = referrers[i];
            if (
                buyer <= previous ||
                buyerPurchaseCount[buyer] == 0 ||
                buyer == referrer
            ) revert InvalidImport();
            previous = buyer;
            assignedReferrer[buyer] = referrer;
            manifest = keccak256(abi.encode(manifest, buyer, referrer));
            _referrers.push(
                ImportCheckpoint(bytes32(uint256(uint160(buyer))), manifest)
            );
            emit HistoricalReferrerImported(buyer, referrer, manifest);
        }
        lastImportedReferrerBuyer = previous;
        importedReferrerManifestHash = manifest;
    }

    /// @notice Returns the number of retained rows in each import stream.
    /// @dev Counts support bounded rollback and approved-manifest reconciliation.
    /// @return purchasers Number of imported historical purchaser rows.
    /// @return referrers Number of imported historical binding rows.
    /// @return codes Number of imported legacy code rows.
    function importRowCounts()
        external
        view
        returns (uint256 purchasers, uint256 referrers, uint256 codes)
    {
        return (_purchasers.length, _referrers.length, _codes.length);
    }

    /// @notice Rolls back a bounded number of trailing rows in one import stream.
    /// @dev Purchasers cannot be rolled back until all historical binding rows have been removed.
    /// @param kind Zero for purchaser rows, one for historical bindings, two for legacy codes.
    /// @param count Positive trailing row count, capped at 200 and the available row count.
    function rollbackImport(
        uint8 kind,
        uint256 count
    ) external onlyTreasuryUnsealed {
        if (kind > 2) revert InvalidImport();
        ImportCheckpoint[] storage checkpoints =
            kind == 0 ? _purchasers : (kind == 1 ? _referrers : _codes);
        uint256 length = checkpoints.length;
        if (count == 0 || count > MAX_IMPORT_ROLLBACK || count > length)
            revert InvalidImport();
        if (kind == 0 && _referrers.length != 0) revert InvalidImport();
        for (uint256 i; i < count; ++i) {
            bytes32 key = checkpoints[checkpoints.length - 1].key;
            address account = address(uint160(uint256(key)));
            if (kind == 0) {
                delete buyerPurchaseCount[account];
                delete referralEligible[account];
            } else if (kind == 1) {
                delete assignedReferrer[account];
            } else {
                delete walletReferralCode[referralCodeOwner[key]];
                delete referralCodeOwner[key];
            }
            checkpoints.pop();
        }
        uint256 remaining = length - count;
        bytes32 lastKey =
            remaining == 0 ? bytes32(0) : checkpoints[remaining - 1].key;
        bytes32 manifest =
            remaining == 0
                ? bytes32(0)
                : checkpoints[remaining - 1].manifestHash;
        bytes32 importKind;
        if (kind == 0) {
            lastImportedPurchaser = address(uint160(uint256(lastKey)));
            importedPurchaserManifestHash = manifest;
            importKind = keccak256("PURCHASERS");
        } else if (kind == 1) {
            lastImportedReferrerBuyer = address(uint160(uint256(lastKey)));
            importedReferrerManifestHash = manifest;
            importKind = keccak256("REFERRERS");
        } else {
            lastImportedReferralCode = lastKey;
            importedReferralCodeManifestHash = manifest;
            importKind = keccak256("CODES");
        }
        emit ImportRolledBack(importKind, count, manifest);
    }

    /// @notice Verifies every approved manifest and permanently prevents further imports or rollback.
    /// @dev The presale invokes this atomically with activation; a later activation failure rolls it back.
    function seal() external {
        if (msg.sender != presale) revert Unauthorized();
        if (isSealed) revert RegistrySealed();
        if (
            importedPurchaserManifestHash != purchaserManifestHash ||
            importedReferrerManifestHash != referrerManifestHash ||
            importedReferralCodeManifestHash != codeManifestHash
        ) revert InvalidImport();
        if (requireCompleteBindings && _referrers.length != _purchasers.length)
            revert InvalidImport();
        isSealed = true;
        emit ImportsSealed(
            importedPurchaserManifestHash,
            importedReferrerManifestHash,
            importedReferralCodeManifestHash
        );
    }
}
