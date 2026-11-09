// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import {SNRGClaimVoucherSoulboundV3 as Voucher} from "./SNRGClaimVoucherSoulboundV3.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {
    SafeERC20,
    IERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {VoucherMetadata} from "./VoucherMetadata.sol";
import {ReferralVoucherAuthorizer} from "./ReferralVoucherAuthorizer.sol";
import {PresaleMigrationRegistry} from "./PresaleMigrationRegistry.sol";

/// @title ETH/USD Price Feed Interface
/// @author Synergy Network
/// @notice Minimal read interface for the canonical Ethereum Chainlink feed.
/// @dev A compatible interface does not prove economic truth; feed identity is an explicit trust boundary.
interface IPriceFeed {
    /// @notice Returns the decimal precision of the quoted USD price.
    /// @dev This sale requires eight decimal places and revalidates that scale on each ETH quote.
    /// @return precision Number of decimal places in each price answer.
    function decimals() external view returns (uint8 precision);

    /// @notice Returns the feed's most recently published round.
    /// @dev The sale checks positivity, completeness, freshness and configured absolute bounds.
    /// @return roundId Identifier of the reported round.
    /// @return answer USD per ETH, multiplied by 1e8.
    /// @return startedAt Time the round began.
    /// @return updatedAt Time the price was last updated.
    /// @return answeredInRound Round in which the answer was finalized.
    function latestRoundData()
        external
        view
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        );
}

/// @title Treasury Safe View Interface
/// @author Synergy Network
/// @notice Reads the configured multisignature treasury's advertised owner set and threshold.
/// @dev These views are compatibility checks; Ethereum production address pinning establishes identity.
interface ISafeView {
    /// @notice Returns the number of owner approvals required by the Safe.
    /// @dev The constructor requires at least two and no more than the number of reported owners.
    /// @return threshold Required owner approvals.
    function getThreshold() external view returns (uint256 threshold);

    /// @notice Returns the Safe's current owner addresses.
    /// @dev Owner membership may change within the externally governed Safe after sale deployment.
    /// @return owners Current owner addresses.
    function getOwners() external view returns (address[] memory owners);
}

/// @title Synergy Presale Relaunch
/// @author Synergy Network
/// @notice Timed Ethereum presale with immutable economics and recoverable referral claim vouchers.
/// @dev Purchases and recorded rewards have 100% initial unlock and no cliff or duration. The
///      Treasury Safe controls activation and emergency pause only; it cannot rewrite earned
///      entitlements or the approved schedule. Bonus mint failures are isolated from paid purchases.
///      This revision requires a newly deployed voucher with sealed canonical issuers. It cannot
///      upgrade an existing immutable voucher or silently migrate historical entitlement records.
///      Issuance is bound to the immutable sale program. Destination configuration and redemption
///      activation occur separately in the voucher after the future network is verifiably ready.
contract SynergyPresaleRelaunch is ReentrancyGuard {
    using SafeERC20 for IERC20;
    using SafeCast for uint256;

    /// @notice Domain tag identifying purchase records whose paymentTxHash field is a typed purchase ID.
    bytes32 public constant PURCHASE_SOURCE = keccak256(
        "SYNERGY_PRESALE_V2_PAYMENT_REFERENCE_IS_PURCHASE_ID"
    );
    /// @notice Domain tag identifying referral records whose payment fields attribute the original purchase.
    bytes32 public constant REWARD_SOURCE = keccak256(
        "SYNERGY_REFERRAL_V2_PAYMENT_FIELDS_ATTRIBUTE_ORIGINAL_PURCHASE_NOT_REVENUE"
    );
    /// @dev Voucher role shared by the two permanently sealed canonical issuers.
    bytes32 private constant MINTER_ROLE = keccak256("MINTER_ROLE");
    /// @notice Reward delivery mode; only VoucherBacked is accepted by this deployment.
    enum RewardMode {
        Unset,
        VoucherBacked,
        NativeLedger
    } // Only VoucherBacked is accepted in this revision
    /// @notice Earned-reward lifecycle; direct SettlementRequested is reserved and unreachable.
    enum RewardState {
        Absent,
        Pending,
        Voucherized,
        SettlementRequested
    }
    /// @notice Inclusive start, exclusive end, USD-E8 price and native-nWei inventory of one timed stage.
    struct Stage {
        uint64 startsAt;
        uint64 endsAt;
        uint128 priceUsdE8;
        uint96 baseInventoryNwei;
    }
    /// @notice Approved wallet-promotion terms; minimumBaseNwei preserves the strict cutoff above 25,000 SNRG.
    /// @dev Wallet eligibility makes no claim that the buyer and referrer represent different people.
    struct ReferralPolicy {
        uint16 buyerBps;
        uint16 referrerBps;
        uint96 minimumBaseNwei;
        uint128 minimumUsdE8;
        uint96 incentiveBudgetNwei;
        bool repeatPurchases;
        RewardMode rewardMode;
    }
    /// @notice Full new-deployment configuration committed by configurationHash and validated before storage.
    struct Config {
        address treasurySafe;
        address voucher;
        address usdc;
        address usdt;
        address ethUsdFeed;
        address usdcUsdFeed;
        address usdtUsdFeed;
        bytes32 referralCodeManifestHash;
        uint256 expectedChainId;
        bytes32 expectedSaleProgramId;
        uint16 maxCombinedBonusBps;
        bytes32 approvalHash;
        bytes32 historicalSnapshotHash;
        bytes32 historicalPurchaserManifestHash;
        bytes32 historicalReferrerManifestHash;
        uint96 historicalPurchasedNwei;
        uint96 historicalOtherEntitlementsNwei;
        uint96 otherNetworkReservationsNwei;
        uint96 networkSupplyCapNwei;
        uint96 minimumPurchaseNwei;
        uint64 firstLedgerId;
        uint64 lastLedgerId;
        uint32 maxOracleAge;
        uint32 maxStablecoinOracleAge;
        uint128 minimumEthUsdE8;
        uint128 maximumEthUsdE8;
        uint128 minimumStablecoinUsdE8;
        uint128 maximumStablecoinUsdE8;
        Stage[8] stages;
        ReferralPolicy policy;
        Voucher.VestingTerms purchaseVesting;
        Voucher.VestingTerms rewardVesting;
    }
    /// @notice Exact purchase requirements signed by the buyer's Ethereum transaction.
    /// @dev Zero bonus minima allow a base-only purchase; nonzero minima protect advertised incentives.
    struct Order {
        uint96 baseAmountNwei;
        uint128 maxPaymentRaw;
        uint8 expectedStage;
        uint128 expectedPriceUsdE8;
        uint64 deadline;
        uint96 minimumBuyerBonusNwei;
        uint96 minimumReferrerBonusNwei;
        address voucherRecipient;
    }
    /// @notice Current stage and rounded collection amounts; a quote does not reserve inventory or bonuses.
    struct Quote {
        uint8 stageId;
        uint64 expiresAt;
        uint128 priceUsdE8;
        uint128 paymentAmountRaw;
        uint128 usdValueE8;
    }
    /// @notice Immutable payment and allocation record; buyer remains the payer even when delivery is redirected.
    struct Purchase {
        address buyer;
        address referrer;
        bytes32 codeHash;
        address paymentToken;
        uint96 baseNwei;
        uint96 buyerBonusNwei;
        uint96 totalNwei;
        uint128 paymentAmountRaw;
        uint128 usdValueE8;
        uint128 priceUsdE8;
        uint64 timestamp;
        uint64 ledgerId;
        uint8 stageId;
        uint256 voucherTokenId;
    }
    /// @notice Earned referral entitlement; Pending reserves one ledger slot until successful voucher issuance.
    struct Reward {
        bytes32 purchaseId;
        address referrer;
        uint96 amountNwei;
        RewardState state;
        uint64 ledgerId;
        uint256 voucherTokenId;
    }

    /// @notice Canonical Treasury Safe that receives proceeds and controls only the sale lifecycle.
    address public immutable treasury;
    /// @notice Newly deployed canonical soulbound voucher with permanently sealed sale issuers.
    Voucher public immutable voucher;
    /// @notice Pinned Ethereum mainnet USDC payment token.
    address public immutable usdc;
    /// @notice Pinned Ethereum mainnet USDT payment token.
    address public immutable usdt;
    /// @notice Pinned Ethereum mainnet ETH/USD oracle.
    IPriceFeed public immutable ethUsdFeed;
    /// @notice Canonical Ethereum USDC/USD feed used for depeg-aware pricing.
    IPriceFeed public immutable usdcUsdFeed;
    /// @notice Canonical Ethereum USDT/USD feed used for depeg-aware pricing.
    IPriceFeed public immutable usdtUsdFeed;
    /// @notice Lowest accepted stablecoin USD price, expressed with eight decimals.
    uint128 public immutable minimumStablecoinUsdE8;
    /// @notice Highest accepted stablecoin USD price, expressed with eight decimals.
    uint128 public immutable maximumStablecoinUsdE8;
    /// @notice Approved maximum buyer-plus-referrer bonus rate, capped at 10,000 basis points.
    /// @dev The combined rate and lifetime incentive budget bound promotion cost across all wallets.
    uint16 public immutable maxCombinedBonusBps;
    /// @notice Maximum new base and incentive entitlements this sale may mint, in nWei.
    uint256 public immutable issuanceCapNwei;
    /// @notice Immutable on-chain renderer created specifically for this sale.
    VoucherMetadata public immutable metadataRenderer;
    /// @notice Maximum acceptable ETH/USD answer age in seconds.
    uint32 public immutable maxOracleAge;
    /// @notice Maximum stablecoin-feed answer age, independently sized for stablecoin feed heartbeats.
    uint32 public immutable maxStablecoinOracleAge;
    /// @notice Lowest accepted ETH/USD answer, with eight decimal places.
    uint128 public immutable minimumEthUsdE8;
    /// @notice Highest accepted ETH/USD answer, with eight decimal places.
    uint128 public immutable maximumEthUsdE8;
    /// @notice Ordinary minimum purchase amount; only an entire final stage remainder may be smaller.
    uint96 public immutable minimumPurchaseNwei;
    /// @notice Approved preexisting purchased supply reserved outside this new sale.
    uint96 public immutable historicalPurchasedNwei;
    /// @notice Approved preexisting non-purchase entitlements reserved outside this sale.
    uint96 public immutable historicalOtherEntitlementsNwei;
    /// @notice All other approved network supply reservations, excluding this sale and its historical amounts.
    uint96 public immutable otherNetworkReservationsNwei;
    /// @notice Global native-SNRG supply ceiling against which all configured obligations are checked.
    uint96 public immutable networkSupplyCapNwei;
    /// @notice Approved off-chain reconciliation snapshot commitment; completeness remains a deployment review duty.
    bytes32 public immutable historicalSnapshotHash;
    /// @notice External governance approval commitment supplied for this deployment.
    bytes32 public immutable approvalHash;
    /// @notice Hash of the exact ABI-encoded constructor Config, including addresses and commercial terms.
    bytes32 public immutable configurationHash;
    /// @notice Keccak-256 of standard ABI encoding of the referral policy followed by maxCombinedBonusBps.
    bytes32 public immutable policyHash;
    /// @notice First ID in the inclusive ledger interval dedicated to this new sale.
    uint64 public immutable firstLedgerId;
    /// @notice Last ID in the inclusive ledger interval; sufficient lifetime capacity is required at construction.
    uint64 public immutable lastLedgerId;
    /// @notice Eight constructor-fixed contiguous sale stages; index zero represents stage one.
    Stage[8] public stages;
    /// @notice Constructor-fixed referral rates, thresholds, incentive budget and repeat-purchase policy.
    ReferralPolicy public referralPolicy;
    /// @notice Ownerless dedicated referral minter created and controlled only by this sale.
    ReferralVoucherAuthorizer public immutable referralAuthorizer;
    /// @notice Historical migration helper permanently sealed during successful activation.
    PresaleMigrationRegistry public immutable migrationRegistry;
    /// @notice Bounded automatic-mint stipend; callers may still retry an unusually expensive receiver separately.
    uint256 public constant AUTO_REWARD_GAS = 3_000_000;
    /// @notice Minimum remaining parent gas before attempting the bounded automatic mint.
    uint256 public constant MIN_AUTOMINT_GAS_LEFT = 3_300_000;
    /// @notice Whether new purchases are paused; this does not erase or reduce existing obligations.
    bool public paused = true;
    /// @notice Whether both automatic and manual referral-voucher issuance are paused.
    bool public claimsPaused;
    /// @notice Whether approved import roots, sealed issuers and payment dependencies have passed activation.
    bool public activated;
    /// @notice Next ledger cursor, shared by new purchases and reserved pending rewards.
    uint64 public nextLedgerId;
    /// @notice Number of successfully completed purchases made through this sale.
    uint256 public purchaseCount;
    /// @notice Total validated payment value received by this sale, in eight-decimal USD units.
    uint256 public newSalesUsdE8;
    /// @notice Lifetime new base allocations sold, excluding all referral bonuses.
    uint256 public newBasePurchasedNwei;
    /// @notice Lifetime buyer bonuses included in successfully minted purchase vouchers.
    uint256 public buyerBonusesIssuedNwei;
    /// @notice Lifetime referrer rewards accrued, including still-pending rewards.
    uint256 public referrerRewardsEarnedNwei;
    /// @notice Lifetime accrued referrer rewards successfully issued as vouchers.
    uint256 public referrerRewardsVoucherizedNwei;
    /// @notice Ledger slots reserved for earned rewards that have not yet minted successfully.
    uint256 public pendingRewardLedgerReservations;
    /// @notice Base allocations consumed from each one-based stage inventory.
    mapping(uint8 stageId => uint96 soldNwei) public baseSoldInStageNwei;
    /// @dev New purchase-count deltas; public getter adds the sealed historical count.
    mapping(address buyer => uint256 count) private _newBuyerPurchaseCount;
    /// @dev Eligibility earned through new purchases; the public getter also consults sealed history.
    mapping(address account => bool eligible) private _newReferralEligible;
    /// @dev New buyer bindings; the public getter falls back to sealed historical assignments.
    mapping(address buyer => address referrer) private _newAssignedReferrer;
    /// @dev New owner-derived code assignments; imported codes remain in the sealed registry.
    mapping(bytes32 codeHash => address owner) private _newReferralCodeOwner;
    /// @dev New owner-to-code assignments; imported owners are resolved through sealed history.
    mapping(address owner => bytes32 codeHash) private _newWalletReferralCode;
    /// @notice Raw ETH, USDC or USDT units paid to the treasury; address(0) denotes ETH.
    mapping(address asset => uint256 rawAmount) public revenueRawByAsset;
    /// @notice Canonical completed purchase data keyed by the domain-separated purchase identifier.
    mapping(bytes32 purchaseId => Purchase purchase) public purchases;
    /// @notice Canonical earned reward ledger; recipient and amount cannot be supplied by a gas sponsor.
    mapping(bytes32 rewardId => Reward reward) public rewards;
    address private _activeMintIssuer;
    bytes32 private _activeMintRequestHash;

    error InvalidConfiguration();
    error Unauthorized();
    error Paused();
    error Closed();
    error StaleQuote();
    error InvalidPurchase();
    error InventoryExceeded();
    error InvalidOracle();
    error InvalidReferral();
    error IncentiveCapExceeded();
    error LedgerExhausted();
    error LedgerCollision(uint64 ledgerId);
    error InvalidReward();
    error TransferFailed();
    error IncentiveExpectationNotMet();
    /// @notice Records a completed paid allocation; the separate voucher event identifies its explicitly selected owner.
    event Purchased(
        bytes32 indexed purchaseId,
        address indexed buyer,
        uint256 indexed voucherTokenId,
        uint64 ledgerId,
        address paymentToken,
        uint128 paymentAmountRaw,
        uint128 usdValueE8,
        uint96 baseNwei,
        uint96 buyerBonusNwei,
        uint96 totalNwei,
        uint8 stageId,
        uint128 priceUsdE8
    );
    /// @notice Records referral attribution and the bonus included in the buyer-selected voucher.
    event BuyerReferralBonus(
        bytes32 indexed purchaseId,
        address indexed referrer,
        bytes32 indexed codeHash,
        uint96 bonusNwei
    );
    /// @notice Records a newly earned referrer entitlement and reserves its incentive supply and ledger capacity.
    event ReferralRewardAccrued(
        bytes32 indexed rewardId,
        bytes32 indexed purchaseId,
        address indexed referrer,
        uint96 amountNwei
    );
    /// @notice Records successful delivery of an already-earned referral entitlement.
    event ReferralRewardVoucherIssued(
        bytes32 indexed rewardId,
        bytes32 indexed purchaseId,
        address indexed referrer,
        uint256 tokenId,
        uint64 ledgerId,
        uint96 amountNwei
    );
    /// @notice Records successful manifest, issuer, dependency and treasury compatibility validation.
    event Activated(bytes32 indexed approvalHash, bytes32 indexed policyHash);
    /// @notice Records independent purchase and referral-issuance pause settings.
    event PauseChanged(bool purchasesPaused, bool rewardClaimsPaused);
    /// @notice Records an imported legacy assignment or a newly registered owner-bound code.
    event ReferralCodeRegistered(
        bytes32 indexed codeHash,
        address indexed owner
    );
    /// @notice Records a skipped or failed automatic attempt while preserving the pending earned entitlement.
    event ReferralMintDeferred(
        bytes32 indexed rewardId,
        bytes32 indexed purchaseId
    );
    /// @notice An otherwise qualifying referral was not accrued because its extra ledger slot was unavailable.
    event ReferralNotAccrued(
        address indexed buyer,
        bytes32 indexed codeHash,
        bytes32 indexed reason
    );
    /// @notice An automatic reward attempt completed successfully inside the purchase transaction.
    event ReferralAutoMintSucceeded(
        bytes32 indexed rewardId,
        uint256 indexed tokenId
    );
    /// @notice The constructor committed the complete configuration for deployment review.
    event ConfigurationCommitted(
        bytes32 indexed configurationHash,
        address indexed treasury,
        address indexed voucher
    );
    /// @notice The earned referrer explicitly selected a different wallet to receive this reward voucher.
    event RewardVoucherRecipientSelected(
        bytes32 indexed rewardId,
        address indexed referrer,
        address indexed recipient
    );

    /// @notice Restricts configuration lifecycle operations to the immutable Treasury Safe.
    /// @dev The constructor verifies that the configured contract advertises a threshold of at least two.
    modifier onlySafe() {
        if (msg.sender != treasury) revert Unauthorized();
        _;
    }

    /// @notice Deploys the sale and its dedicated metadata renderer and referral authorizer.
    /// @dev All commercial inputs are committed at deployment and cannot be changed afterward.
    /// @param c Approved deployment addresses, schedule, manifests, supply budgets and referral policy.
    constructor(Config memory c) {
        if (block.chainid != 1 || c.expectedChainId != 1)
            revert InvalidConfiguration();
        if (
            c.treasurySafe.code.length == 0 ||
            c.voucher.code.length == 0 ||
            c.usdc.code.length == 0 ||
            c.usdt.code.length == 0 ||
            c.ethUsdFeed.code.length == 0 ||
            c.usdcUsdFeed.code.length == 0 ||
            c.usdtUsdFeed.code.length == 0 ||
            c.usdc == c.usdt ||
            c.approvalHash == 0 ||
            c.historicalSnapshotHash == 0 ||
            c.minimumPurchaseNwei == 0 ||
            c.firstLedgerId == 0 ||
            c.lastLedgerId < c.firstLedgerId ||
            c.lastLedgerId == type(uint64).max ||
            c.maxOracleAge == 0 ||
            c.maxOracleAge > 1 days ||
            c.maxStablecoinOracleAge == 0 ||
            c.maxStablecoinOracleAge > 2 days ||
            c.minimumEthUsdE8 == 0 ||
            c.maximumEthUsdE8 < c.minimumEthUsdE8 ||
            c.networkSupplyCapNwei == 0 ||
            c.minimumStablecoinUsdE8 == 0 ||
            c.minimumStablecoinUsdE8 > 1e8 ||
            c.maximumStablecoinUsdE8 < 1e8
        ) revert InvalidConfiguration();
        if (
            c.treasurySafe != 0x72F57B74C0b2D556589CeB393103bea0f631933B ||
            c.usdc != 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 ||
            c.usdt != 0xdAC17F958D2ee523a2206206994597C13D831ec7 ||
            c.ethUsdFeed != 0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419 ||
            c.usdcUsdFeed != 0x8fFfFfd4AfB6115b954Bd326cbe7B4BA576818f6 ||
            c.usdtUsdFeed != 0x3E7d1eAB13ad0104d2750B8863b489D65364e32D
        ) revert InvalidConfiguration();
        uint256 threshold = ISafeView(c.treasurySafe).getThreshold();
        if (
            threshold < 2 ||
            threshold > ISafeView(c.treasurySafe).getOwners().length
        ) revert InvalidConfiguration();
        if (
            IERC20Metadata(c.usdc).decimals() != 6 ||
            IERC20Metadata(c.usdt).decimals() != 6 ||
            IPriceFeed(c.ethUsdFeed).decimals() != 8 ||
            IPriceFeed(c.usdcUsdFeed).decimals() != 8 ||
            IPriceFeed(c.usdtUsdFeed).decimals() != 8 ||
            c.expectedSaleProgramId == 0 ||
            Voucher(c.voucher).saleProgramId() != c.expectedSaleProgramId ||
            Voucher(c.voucher).issuanceSealed() ||
            Voucher(c.voucher).lifetimeIssuedNwei() != 0
        ) revert InvalidConfiguration();
        if (
            c.historicalPurchasedNwei != 0 &&
            c.historicalPurchaserManifestHash == bytes32(0)
        ) revert InvalidConfiguration();
        if (
            c.policy.repeatPurchases &&
            c.historicalPurchasedNwei != 0 &&
            c.historicalReferrerManifestHash == bytes32(0)
        ) revert InvalidConfiguration();
        // Preserve the source's strict >25,000 SNRG floor, while making the configured minimum truthful.
        if (
            (c.policy.buyerBps != 0 || c.policy.referrerBps != 0) &&
            c.policy.minimumBaseNwei <= 25_000 * 1e9
        ) revert InvalidConfiguration();
        if (
            c.purchaseVesting.vestingStart != 0 ||
            c.rewardVesting.vestingStart != 0
        ) revert InvalidConfiguration();
        uint256 maximumObligations =
            uint256(c.historicalPurchasedNwei) +
                c.historicalOtherEntitlementsNwei +
                c.otherNetworkReservationsNwei +
                c.policy.incentiveBudgetNwei;
        uint256 maximumPurchaseCount;
        uint256 newBaseCapacity;
        for (uint256 i; i < 8; ++i) {
            Stage memory s = c.stages[i];
            if (
                s.startsAt >= s.endsAt ||
                s.priceUsdE8 == 0 ||
                s.baseInventoryNwei < c.minimumPurchaseNwei ||
                (i == 0 && s.startsAt <= block.timestamp) ||
                (i > 0 && s.startsAt != c.stages[i - 1].endsAt)
            ) revert InvalidConfiguration();
            stages[i] = s;
            maximumObligations += s.baseInventoryNwei;
            newBaseCapacity += s.baseInventoryNwei;
            maximumPurchaseCount += Math.ceilDiv(
                s.baseInventoryNwei,
                c.minimumPurchaseNwei
            );
            _validateQuoteBounds(
                s,
                c.minimumEthUsdE8,
                c.maximumEthUsdE8,
                c.minimumStablecoinUsdE8,
                c.maximumStablecoinUsdE8
            );
        }
        uint256 requiredLedgerSlots =
            maximumPurchaseCount * (c.policy.referrerBps == 0 ? 1 : 2);
        if (uint256(c.lastLedgerId) - c.firstLedgerId + 1 < requiredLedgerSlots)
            revert InvalidConfiguration();
        issuanceCapNwei = newBaseCapacity + c.policy.incentiveBudgetNwei;
        if (
            maximumObligations > c.networkSupplyCapNwei ||
            c.maxCombinedBonusBps > 10000 ||
            uint256(c.policy.buyerBps) + c.policy.referrerBps >
                c.maxCombinedBonusBps ||
            c.policy.rewardMode != RewardMode.VoucherBacked
        ) revert InvalidConfiguration();
        if (
            (c.policy.buyerBps != 0 || c.policy.referrerBps != 0) &&
            c.policy.incentiveBudgetNwei == 0
        ) revert InvalidConfiguration();
        _validateVesting(c.purchaseVesting);
        _validateVesting(c.rewardVesting);
        if (
            c.purchaseVesting.initialUnlockBps != 10000 ||
            c.purchaseVesting.cliffSeconds != 0 ||
            c.purchaseVesting.durationSeconds != 0 ||
            c.rewardVesting.initialUnlockBps != 10000 ||
            c.rewardVesting.cliffSeconds != 0 ||
            c.rewardVesting.durationSeconds != 0
        ) revert InvalidConfiguration();
        if (Voucher(c.voucher).processedLedgerIds(c.firstLedgerId))
            revert LedgerCollision(c.firstLedgerId);
        treasury = c.treasurySafe;
        voucher = Voucher(c.voucher);
        usdc = c.usdc;
        usdt = c.usdt;
        metadataRenderer = new VoucherMetadata();
        ethUsdFeed = IPriceFeed(c.ethUsdFeed);
        maxOracleAge = c.maxOracleAge;
        maxStablecoinOracleAge = c.maxStablecoinOracleAge;
        usdcUsdFeed = IPriceFeed(c.usdcUsdFeed);
        usdtUsdFeed = IPriceFeed(c.usdtUsdFeed);
        minimumStablecoinUsdE8 = c.minimumStablecoinUsdE8;
        maximumStablecoinUsdE8 = c.maximumStablecoinUsdE8;
        maxCombinedBonusBps = c.maxCombinedBonusBps;
        minimumEthUsdE8 = c.minimumEthUsdE8;
        maximumEthUsdE8 = c.maximumEthUsdE8;
        minimumPurchaseNwei = c.minimumPurchaseNwei;
        historicalPurchasedNwei = c.historicalPurchasedNwei;
        historicalOtherEntitlementsNwei = c.historicalOtherEntitlementsNwei;
        otherNetworkReservationsNwei = c.otherNetworkReservationsNwei;
        networkSupplyCapNwei = c.networkSupplyCapNwei;
        historicalSnapshotHash = c.historicalSnapshotHash;
        approvalHash = c.approvalHash;
        referralPolicy = c.policy;
        policyHash = keccak256(abi.encode(c.policy, c.maxCombinedBonusBps));
        referralAuthorizer = new ReferralVoucherAuthorizer(address(voucher));
        migrationRegistry = new PresaleMigrationRegistry(
            c.treasurySafe,
            c.historicalPurchaserManifestHash,
            c.historicalReferrerManifestHash,
            c.referralCodeManifestHash,
            c.policy.repeatPurchases && c.historicalPurchasedNwei != 0
        );
        firstLedgerId = c.firstLedgerId;
        lastLedgerId = c.lastLedgerId;
        nextLedgerId = c.firstLedgerId;
        configurationHash = keccak256(abi.encode(c));
        emit ConfigurationCommitted(
            configurationHash,
            treasury,
            address(voucher)
        );
    }

    /// @notice Returns historical plus new purchase count for one payer.
    /// @dev Historical counts are immutable after activation; only successful new purchases add to them.
    /// @param buyer Payer address to inspect.
    /// @return count Total approved historical and new purchase count.
    function buyerPurchaseCount(
        address buyer
    ) public view returns (uint256 count) {
        return
            _newBuyerPurchaseCount[buyer] +
            migrationRegistry.buyerPurchaseCount(buyer);
    }

    /// @notice Reports whether imported eligibility or a successful new purchase allows referral registration.
    /// @dev New eligibility never removes eligibility from the approved sealed history.
    /// @param account Participant address to inspect.
    /// @return eligible Whether the account is referral-eligible.
    function referralEligible(
        address account
    ) public view returns (bool eligible) {
        return
            _newReferralEligible[account] ||
            migrationRegistry.referralEligible(account);
    }

    /// @notice Returns the buyer's committed new or historical referrer binding.
    /// @dev An approved historical nonzero binding cannot be replaced by a new qualifying purchase.
    /// @param buyer Payer address to inspect.
    /// @return referrer Bound referrer, or zero if no binding exists.
    function assignedReferrer(
        address buyer
    ) public view returns (address referrer) {
        referrer = _newAssignedReferrer[buyer];
        if (referrer == address(0))
            referrer = migrationRegistry.assignedReferrer(buyer);
    }

    /// @notice Returns the canonical owner of a new or imported referral code.
    /// @dev Registration checks both namespaces before accepting a new owner-derived code.
    /// @param codeHash Referral code to resolve.
    /// @return owner Canonical code owner, or zero for an unregistered code.
    function referralCodeOwner(
        bytes32 codeHash
    ) public view returns (address owner) {
        owner = _newReferralCodeOwner[codeHash];
        if (owner == address(0))
            owner = migrationRegistry.referralCodeOwner(codeHash);
    }

    /// @notice Returns the single new or imported referral code assigned to an owner.
    /// @dev Imported owners cannot register a second code through the post-activation path.
    /// @param owner Referral owner address.
    /// @return codeHash Canonical assigned code, or zero when none exists.
    function walletReferralCode(
        address owner
    ) public view returns (bytes32 codeHash) {
        codeHash = _newWalletReferralCode[owner];
        if (codeHash == bytes32(0))
            codeHash = migrationRegistry.walletReferralCode(owner);
    }

    /// @notice Registers the caller's deterministic owner-bound code after referral eligibility is earned.
    /// @dev New links must use referralCodeFor(owner). Approved imported website codes keep their assignments.
    /// @param codeHash Exact value of referralCodeFor(msg.sender); arbitrary first-writer code claims are rejected.
    function registerReferralCode(bytes32 codeHash) external nonReentrant {
        if (codeHash != referralCodeFor(msg.sender)) revert InvalidReferral();
        if (
            !activated ||
            !referralEligible(msg.sender) ||
            codeHash == bytes32(0) ||
            referralCodeOwner(codeHash) != address(0) ||
            walletReferralCode(msg.sender) != bytes32(0)
        ) revert InvalidReferral();
        _newReferralCodeOwner[codeHash] = msg.sender;
        _newWalletReferralCode[msg.sender] = codeHash;
        emit ReferralCodeRegistered(codeHash, msg.sender);
    }
    /// @notice Computes the only new referral code this deployment will accept for a wallet.
    /// @dev Domain, chain, deployment and owner binding prevents mempool copying from capturing identity.
    ///      Existing imported website codes remain unchanged; new links must use this canonical value.
    /// @param owner Address whose referral identity is being derived.
    /// @return codeHash Unique owner-bound referral code hash.
    function referralCodeFor(
        address owner
    ) public view returns (bytes32 codeHash) {
        if (owner == address(0)) revert InvalidReferral();
        codeHash = keccak256(
            abi.encode(
                keccak256("SYNERGY_REFERRAL_CODE_V2"),
                block.chainid,
                address(this),
                owner
            )
        );
    }

    /// @notice Confirms issuance commitments and opens the sale before its final expiry.
    /// @dev Redemption readiness is independent. Requires exactly 1 wei, returned to the treasury
    ///      as a positive-value compatibility probe. Late activation never extends elapsed stages.
    function activate() external payable nonReentrant onlySafe {
        if (msg.value != 1) revert InvalidConfiguration();
        if (
            activated ||
            block.timestamp >= stages[7].endsAt ||
            !voucher.issuanceSealed() ||
            voucher.sealedPresale() != address(this) ||
            voucher.sealedReferralAuthorizer() != address(referralAuthorizer) ||
            !voucher.hasRole(MINTER_ROLE, address(this)) ||
            !voucher.hasRole(MINTER_ROLE, address(referralAuthorizer)) ||
            voucher.paused()
        ) revert InvalidConfiguration();
        // Reject incompatible or unusable feeds before opening any payment lane.
        _ethPrice();
        _stablecoinPrice(usdc);
        _stablecoinPrice(usdt);
        // The exact 1-wei setup payment is returned immediately to test native settlement compatibility.
        _sendETH(treasury, msg.value);
        migrationRegistry.seal();
        activated = true;
        paused = false;
        emit Activated(approvalHash, policyHash);
        emit PauseChanged(false, claimsPaused);
    }
    /// @notice Sets independent emergency pause states for purchases and referral issuance.
    /// @dev Only the Treasury Safe may call; existing entitlements and the fixed sale schedule remain unchanged.
    /// @param purchasesPaused Whether new purchases should be blocked.
    /// @param rewardsPaused Whether all automatic and manual reward issuance should be blocked.
    function setPaused(
        bool purchasesPaused,
        bool rewardsPaused
    ) external onlySafe {
        if (!activated && !purchasesPaused) revert InvalidConfiguration();
        if (paused == purchasesPaused && claimsPaused == rewardsPaused) return;
        paused = purchasesPaused;
        claimsPaused = rewardsPaused;
        emit PauseChanged(purchasesPaused, rewardsPaused);
    }
    /// @notice Returns the fixed immediate-unlock purchase terms without redundant storage.
    /// @dev This preserves the original getter's static wire layout with zero start, cliff and duration.
    /// @return vestingStart Zero; no future start delay.
    /// @return cliffSeconds Zero; no cliff.
    /// @return durationSeconds Zero; no vesting duration.
    /// @return initialUnlockBps Ten thousand; full initial unlock.
    function purchaseVesting()
        external
        pure
        returns (
            uint64 vestingStart,
            uint32 cliffSeconds,
            uint32 durationSeconds,
            uint16 initialUnlockBps
        )
    {
        return (0, 0, 0, 10000);
    }

    /// @notice Returns the same fixed immediate-unlock terms for earned referral vouchers.
    /// @dev The constructor rejects any different proposed tuple; no vesting schedule is stored.
    /// @return vestingStart Zero; no future start delay.
    /// @return cliffSeconds Zero; no cliff.
    /// @return durationSeconds Zero; no vesting duration.
    /// @return initialUnlockBps Ten thousand; full initial unlock.
    function rewardVesting()
        external
        pure
        returns (
            uint64 vestingStart,
            uint32 cliffSeconds,
            uint32 durationSeconds,
            uint16 initialUnlockBps
        )
    {
        return (0, 0, 0, 10000);
    }

    /// @notice Returns the time-selected stage without advancing on sellout.
    /// @dev Intervals are start-inclusive and end-exclusive; the bounded scan does not require an exact-time transaction.
    /// @return Zero before opening, one through eight during the sale, or nine at or after final expiry.
    function currentStage() public view returns (uint8) {
        if (block.timestamp < stages[0].startsAt) return 0;
        for (uint8 i; i < 8; ++i)
            if (block.timestamp < stages[i].endsAt) return i + 1;
        return 9;
    }
    /// @notice Reports whether the entire immutable sale schedule has expired.
    /// @dev Exhausted stage inventory and paused state do not move the clock.
    /// @return Whether the final stage end has been reached.
    function saleClosed() external view returns (bool) {
        return block.timestamp >= stages[7].endsAt;
    }
    /// @notice Returns uncommitted incentive supply after buyer and referrer bonuses.
    /// @dev Pending earned rewards remain charged to the budget; failed delivery never frees their entitlement.
    /// @return Remaining incentive budget in nWei.
    function remainingReferralIncentivesNwei() public view returns (uint256) {
        return
            uint256(referralPolicy.incentiveBudgetNwei) -
            buyerBonusesIssuedNwei -
            referrerRewardsEarnedNwei;
    }
    /// @notice Returns earned referral amounts that have not yet been voucherized.
    /// @dev The accepted reward mode is always VoucherBacked; amounts remain counted through failed mint attempts.
    /// @return Earned but unissued referral nWei.
    function referrerRewardsAwaitingVoucherNwei()
        external
        view
        returns (uint256)
    {
        return referrerRewardsEarnedNwei - referrerRewardsVoucherizedNwei;
    }
    /// @notice Returns outstanding earned referral obligations.
    /// @dev This revision supports vouchers only and does not permit direct native reward settlement.
    /// @return Outstanding earned referral nWei.
    function referrerRewardsPendingNwei() public view returns (uint256) {
        return referrerRewardsEarnedNwei - referrerRewardsVoucherizedNwei;
    }
    /// @notice Returns historical and new lifetime sale obligations without reusing burned supply.
    /// @dev Native settlement is accounted separately. A source voucher burn does not prove a completed native credit.
    /// @return Historical plus new base and incentive obligations in nWei.
    function totalEntitlementObligationsNwei() public view returns (uint256) {
        return
            uint256(historicalPurchasedNwei) +
            historicalOtherEntitlementsNwei +
            newBasePurchasedNwei +
            buyerBonusesIssuedNwei +
            referrerRewardsEarnedNwei;
    }
    /// @notice Quotes an exact base allocation using a fresh accepted payment-asset price.
    /// @dev Collection rounds upward; referral USD eligibility uses exact nominal stage value separately. The entire final sub-minimum inventory remainder is purchasable.
    /// @param asset Zero for ETH, or the pinned USDC or USDT address.
    /// @param baseAmount Exact desired base allocation in nine-decimal nWei.
    /// @return q Current stage, exclusive stage end, price and required raw payment.
    function quote(
        address asset,
        uint96 baseAmount
    ) public view returns (Quote memory q) {
        uint8 stageId = currentStage();
        if (stageId == 0 || stageId == 9) revert Closed();
        uint256 stageIndex = uint256(stageId) - 1;
        Stage storage s = stages[stageIndex];
        uint256 remaining =
            uint256(s.baseInventoryNwei) - baseSoldInStageNwei[stageId];
        if (
            baseAmount == 0 ||
            (baseAmount < minimumPurchaseNwei && baseAmount != remaining)
        ) revert InvalidPurchase();
        if (baseAmount > remaining) revert InventoryExceeded();
        if (remainingUnreservedLedgerSlots() == 0) revert LedgerExhausted();
        if (voucher.processedLedgerIds(nextLedgerId))
            revert LedgerCollision(nextLedgerId);
        uint256 numerator = uint256(baseAmount) * s.priceUsdE8;
        q.stageId = stageId;
        q.expiresAt = s.endsAt;
        q.priceUsdE8 = s.priceUsdE8;
        if (asset == address(0)) {
            uint256 price = _ethPrice();
            q.paymentAmountRaw = Math
                .mulDiv(numerator, 1e9, price, Math.Rounding.Ceil)
                .toUint128();
            q.usdValueE8 = Math
                .mulDiv(q.paymentAmountRaw, price, 1e18, Math.Rounding.Ceil)
                .toUint128();
        } else {
            if (asset != usdc && asset != usdt) revert InvalidPurchase();
            if (IERC20Metadata(asset).decimals() != 6)
                revert InvalidConfiguration();
            uint256 price = _stablecoinPrice(asset);
            q.paymentAmountRaw = Math
                .ceilDiv(numerator, price * 1e3)
                .toUint128();
            q.usdValueE8 = Math
                .mulDiv(q.paymentAmountRaw, price, 1e6, Math.Rounding.Ceil)
                .toUint128();
        }
    }
    /// @notice Purchases the exact requested allocation with native ETH.
    /// @dev Refunds excess ETH after safely minting the purchase voucher. Only referral mint failure is isolated; failed purchase delivery or payment reverts atomically.
    /// @param o Buyer-approved price, deadline, bonus minima and optional voucher receiver.
    /// @param referralCodeHash Optional canonical referral code; zero disables referral attribution.
    /// @return purchaseId Canonical committed purchase identifier.
    /// @return tokenId New buyer-selected claim voucher identifier.
    function buyWithETH(
        Order calldata o,
        bytes32 referralCodeHash
    )
        external
        payable
        nonReentrant
        returns (bytes32 purchaseId, uint256 tokenId)
    {
        return _buy(address(0), o, referralCodeHash);
    }
    /// @notice Purchases the exact requested allocation with canonical Ethereum USDC.
    /// @dev Requires prior allowance, verified buyer debit and treasury credit, and a fresh peg-bounded USD price.
    /// @param o Buyer-approved price, deadline, bonus minima and optional voucher receiver.
    /// @param referralCodeHash Optional canonical referral code; zero disables referral attribution.
    /// @return purchaseId Canonical committed purchase identifier.
    /// @return tokenId New buyer-selected claim voucher identifier.
    function buyWithUSDC(
        Order calldata o,
        bytes32 referralCodeHash
    ) external nonReentrant returns (bytes32 purchaseId, uint256 tokenId) {
        return _buy(usdc, o, referralCodeHash);
    }
    /// @notice Purchases the exact requested allocation with canonical Ethereum USDT.
    /// @dev SafeERC20 supports the token response convention; exact debit and credit checks reject transfer fees.
    /// @param o Buyer-approved price, deadline, bonus minima and optional voucher receiver.
    /// @param referralCodeHash Optional canonical referral code; zero disables referral attribution.
    /// @return purchaseId Canonical committed purchase identifier.
    /// @return tokenId New buyer-selected claim voucher identifier.
    function buyWithUSDT(
        Order calldata o,
        bytes32 referralCodeHash
    ) external nonReentrant returns (bytes32 purchaseId, uint256 tokenId) {
        return _buy(usdt, o, referralCodeHash);
    }
    /// @notice Executes the shared guarded purchase path and records any funded referral entitlement.
    /// @dev All public callers are nonReentrant. The only self-call is deliberately gas-bounded to preserve the committed paid purchase when bonus minting fails.
    /// @param asset Canonical payment token or zero for ETH.
    /// @param o The buyer-approved order.
    /// @param referralCodeHash Optional referral code.
    /// @return purchaseId Domain-separated purchase ID.
    /// @return tokenId Successfully minted purchase voucher ID.
    function _buy(
        address asset,
        Order calldata o,
        bytes32 referralCodeHash
    ) private returns (bytes32 purchaseId, uint256 tokenId) {
        if (paused || !activated) revert Paused();
        if (block.timestamp > o.deadline || msg.sender == treasury)
            revert InvalidPurchase();
        Quote memory q = quote(asset, o.baseAmountNwei);
        if (
            q.stageId != o.expectedStage ||
            q.priceUsdE8 != o.expectedPriceUsdE8 ||
            q.paymentAmountRaw > o.maxPaymentRaw
        ) revert StaleQuote();
        if (
            asset == address(0) &&
            (msg.value < q.paymentAmountRaw || msg.value > o.maxPaymentRaw)
        ) revert InvalidPurchase();
        (address referrer, uint96 buyerBonus, uint96 referrerBonus) = _referral(
            o.baseAmountNwei,
            q,
            referralCodeHash
        );
        if (
            uint256(buyerBonus) + referrerBonus >
            remainingReferralIncentivesNwei()
        ) revert IncentiveCapExceeded();
        if (referrerBonus != 0 && remainingUnreservedLedgerSlots() < 2) {
            // No entitlement has been accrued yet. Preserve the base purchase at the final free slot.
            emit ReferralNotAccrued(
                msg.sender,
                referralCodeHash,
                keccak256("LEDGER_CAPACITY")
            );
            referrer = address(0);
            buyerBonus = 0;
            referrerBonus = 0;
        }
        if (
            buyerBonus < o.minimumBuyerBonusNwei ||
            referrerBonus < o.minimumReferrerBonusNwei
        ) revert IncentiveExpectationNotMet();
        uint64 ledgerId = _allocateLedger(false);
        purchaseId = keccak256(
            abi.encode(PURCHASE_SOURCE, block.chainid, address(this), ledgerId)
        );
        Purchase memory p = Purchase(
            msg.sender,
            referrer,
            referralCodeHash,
            asset,
            o.baseAmountNwei,
            buyerBonus,
            (uint256(o.baseAmountNwei) + buyerBonus).toUint96(),
            q.paymentAmountRaw,
            q.usdValueE8,
            q.priceUsdE8,
            block.timestamp.toUint64(),
            ledgerId,
            q.stageId,
            0
        );
        purchases[purchaseId] = p;
        baseSoldInStageNwei[q.stageId] += o.baseAmountNwei;
        newBasePurchasedNwei += o.baseAmountNwei;
        buyerBonusesIssuedNwei += buyerBonus;
        referrerRewardsEarnedNwei += referrerBonus;
        ++purchaseCount;
        ++_newBuyerPurchaseCount[msg.sender];
        _newReferralEligible[msg.sender] = true;
        newSalesUsdE8 += q.usdValueE8;
        revenueRawByAsset[asset] += q.paymentAmountRaw;
        if (referrer != address(0)) {
            if (assignedReferrer(msg.sender) == address(0))
                _newAssignedReferrer[msg.sender] = referrer;
            emit BuyerReferralBonus(
                purchaseId,
                referrer,
                referralCodeHash,
                buyerBonus
            );
        }
        if (referrerBonus != 0) {
            ++pendingRewardLedgerReservations;
            bytes32 rewardId = keccak256(
                abi.encode(
                    REWARD_SOURCE,
                    block.chainid,
                    address(this),
                    purchaseId
                )
            );
            rewards[rewardId] = Reward(
                purchaseId,
                referrer,
                referrerBonus,
                RewardState.Pending,
                0,
                0
            );
            emit ReferralRewardAccrued(
                rewardId,
                purchaseId,
                referrer,
                referrerBonus
            );
        }
        if (
            totalEntitlementObligationsNwei() + otherNetworkReservationsNwei >
            networkSupplyCapNwei
        ) revert IncentiveCapExceeded();
        if (asset != address(0)) {
            uint256 beforeBalance = IERC20(asset).balanceOf(treasury);
            uint256 buyerBalanceBefore = IERC20(asset).balanceOf(msg.sender);
            IERC20(asset).safeTransferFrom(
                msg.sender,
                treasury,
                q.paymentAmountRaw
            );
            if (
                IERC20(asset).balanceOf(treasury) !=
                beforeBalance + q.paymentAmountRaw
            ) revert TransferFailed();
            uint256 buyerBalanceAfter = IERC20(asset).balanceOf(msg.sender);
            if (
                buyerBalanceAfter > buyerBalanceBefore ||
                buyerBalanceBefore - buyerBalanceAfter != q.paymentAmountRaw
            ) revert TransferFailed();
        }
        address recipient =
            o.voucherRecipient == address(0) ? msg.sender : o.voucherRecipient;
        Voucher.MintRequest memory purchaseRequest = _mintRequest(
            p,
            purchaseId,
            purchaseId,
            ledgerId,
            recipient,
            p.totalNwei,
            false
        );
        _activeMintIssuer = address(this);
        _activeMintRequestHash = keccak256(abi.encode(purchaseRequest));
        tokenId = voucher.mintReceipt(purchaseRequest);
        delete _activeMintIssuer;
        delete _activeMintRequestHash;
        purchases[purchaseId].voucherTokenId = tokenId;
        if (asset == address(0)) {
            _sendETH(treasury, q.paymentAmountRaw);
            if (msg.value > q.paymentAmountRaw)
                _sendETH(msg.sender, msg.value - q.paymentAmountRaw);
        }
        emit Purchased(
            purchaseId,
            msg.sender,
            tokenId,
            ledgerId,
            asset,
            p.paymentAmountRaw,
            p.usdValueE8,
            p.baseNwei,
            p.buyerBonusNwei,
            p.totalNwei,
            p.stageId,
            p.priceUsdE8
        );
        // Best effort: failure MUST NOT revert a valid paid purchase.
        // The canonical pending entitlement remains in `rewards` for permissionless recovery.
        if (referrerBonus != 0) {
            bytes32 rewardId = keccak256(
                abi.encode(
                    REWARD_SOURCE,
                    block.chainid,
                    address(this),
                    purchaseId
                )
            );
            if (!claimsPaused && gasleft() >= MIN_AUTOMINT_GAS_LEFT) {
                try
                    this.issueRewardForPurchase{gas: AUTO_REWARD_GAS}(rewardId)
                returns (uint256 issuedTokenId) {
                    emit ReferralAutoMintSucceeded(rewardId, issuedTokenId);
                } catch {
                    emit ReferralMintDeferred(rewardId, purchaseId);
                }
            } else {
                emit ReferralMintDeferred(rewardId, purchaseId);
            }
        }
    }
    /// @notice Computes the currently available referral benefits for the transaction sender.
    /// @dev Eligibility is address-based and cannot prove different people control different wallets. Bonuses are subject to funded budget; Order minima protect buyer expectations.
    /// @param base Base purchased amount in nWei.
    /// @param q Execution-time quote containing the immutable stage price.
    /// @param codeHash Optional registered referral code.
    /// @return qualifiedReferrer Qualified code owner, or zero if no referral benefits are available.
    /// @return buyerBonus Funded buyer bonus in nWei.
    /// @return referrerBonus Funded earned-referrer bonus in nWei.
    function _referral(
        uint96 base,
        Quote memory q,
        bytes32 codeHash
    )
        private
        view
        returns (
            address qualifiedReferrer,
            uint96 buyerBonus,
            uint96 referrerBonus
        )
    {
        if (codeHash == bytes32(0)) return (address(0), 0, 0);
        address referrer = referralCodeOwner(codeHash);
        ReferralPolicy storage p = referralPolicy;
        address previousReferrer = assignedReferrer(msg.sender);
        if (
            referrer == address(0) ||
            referrer == msg.sender ||
            !referralEligible(referrer) ||
            (!p.repeatPurchases && buyerPurchaseCount(msg.sender) != 0) ||
            (previousReferrer != address(0) && previousReferrer != referrer) ||
            base < p.minimumBaseNwei ||
            uint256(base) * q.priceUsdE8 < uint256(p.minimumUsdE8) * 1e9
        ) {
            return (address(0), 0, 0);
        }
        uint96 buyer = ((uint256(base) * p.buyerBps) / 10000).toUint96();
        uint96 referral = ((uint256(base) * p.referrerBps) / 10000).toUint96();
        if (uint256(buyer) + referral > remainingReferralIncentivesNwei())
            return (address(0), 0, 0);
        return (referrer, buyer, referral);
    }
    /// @notice Issues an already-recorded reward only through the purchase transaction self-call.
    /// @dev The self-only gate deliberately composes with the outer purchase guard; adding nonReentrant here would always block automatic issuance.
    /// @param rewardId Already-accrued reward ID.
    /// @return tokenId Successfully issued referral voucher ID.
    function issueRewardForPurchase(
        bytes32 rewardId
    ) external returns (uint256 tokenId) {
        if (msg.sender != address(this)) revert Unauthorized();
        return _issueReward(rewardId, rewards[rewardId].referrer);
    }
    /// @notice Lets anyone sponsor issuance of a pending reward to its stored referrer.
    /// @dev The gas sponsor cannot select a different beneficiary or amount; both derive from the canonical reward record.
    /// @param rewardId Already-earned reward to deliver.
    /// @return tokenId Successfully issued referral voucher ID.
    function claimRewardVoucher(
        bytes32 rewardId
    ) external nonReentrant returns (uint256 tokenId) {
        if (claimsPaused) revert Paused();
        return _issueReward(rewardId, rewards[rewardId].referrer);
    }
    /// @notice Lets the earned referrer explicitly choose a compatible reward-voucher receiver.
    /// @dev Only the recorded referrer may redirect delivery. Sponsors retain the original-recipient path.
    /// @param rewardId Canonical already-earned reward identifier.
    /// @param recipient Nonzero address to own the new soulbound claim voucher.
    /// @return tokenId Newly minted reward voucher identifier.
    function claimRewardVoucherTo(
        bytes32 rewardId,
        address recipient
    ) external nonReentrant returns (uint256 tokenId) {
        if (msg.sender != rewards[rewardId].referrer || recipient == address(0))
            revert Unauthorized();
        emit RewardVoucherRecipientSelected(rewardId, msg.sender, recipient);
        return _issueReward(rewardId, recipient);
    }

    /// @notice Atomically consumes a pending reward and its reserved ledger capacity.
    /// @dev Recipient redirection is authorized by the external referrer-only entry point; all other paths use the original referrer. Reverts roll back every reservation and mint marker.
    /// @param rewardId Canonical pending reward ID.
    /// @param recipient Original referrer or the explicitly owner-selected receiver.
    /// @return tokenId Successfully issued referral voucher ID.
    function _issueReward(
        bytes32 rewardId,
        address recipient
    ) private returns (uint256 tokenId) {
        if (claimsPaused) revert Paused();
        Reward storage r = rewards[rewardId];
        if (r.state != RewardState.Pending || r.amountNwei == 0)
            revert InvalidReward();
        uint64 ledgerId = _allocateLedger(true);
        r.state = RewardState.Voucherized;
        r.ledgerId = ledgerId;
        Purchase memory p = purchases[r.purchaseId];
        Voucher.MintRequest memory request = _mintRequest(
            p,
            rewardId,
            r.purchaseId,
            ledgerId,
            recipient,
            r.amountNwei,
            true
        );
        // Effects precede the receiver callback. Any failure rolls back state and the slot reservation.
        referrerRewardsVoucherizedNwei += r.amountNwei;
        _activeMintIssuer = address(referralAuthorizer);
        _activeMintRequestHash = keccak256(abi.encode(request));
        tokenId = referralAuthorizer.issueReferralVoucher(rewardId, request);
        delete _activeMintIssuer;
        delete _activeMintRequestHash;
        r.voucherTokenId = tokenId;
        emit ReferralRewardVoucherIssued(
            rewardId,
            r.purchaseId,
            r.referrer,
            tokenId,
            ledgerId,
            r.amountNwei
        );
    }
    /// @notice Builds the complete canonical voucher payload from a committed purchase.
    /// @dev Referral payment fields are provenance only and do not represent a second payment. Full request hashing prevents other minters from forging this payload.
    /// @param p Committed purchase record.
    /// @param saleId Purchase ID for a purchase or reward ID for a referral.
    /// @param purchaseId Original qualifying purchase ID used as a typed payment reference.
    /// @param ledgerId Allocated global voucher ledger ID.
    /// @param recipient Buyer-approved or referrer-approved voucher owner.
    /// @param amount Exact base-plus-bonus or reward entitlement in nWei.
    /// @param reward Whether this is a referral reward voucher.
    /// @return r Canonical validated mint request with deterministic metadata.
    function _mintRequest(
        Purchase memory p,
        bytes32 saleId,
        bytes32 purchaseId,
        uint64 ledgerId,
        address recipient,
        uint96 amount,
        bool reward
    ) private view returns (Voucher.MintRequest memory r) {
        r.ledgerId = ledgerId;
        r.saleIdHash = saleId;
        r.walletAddress = p.buyer;
        r.purchaserAddress = recipient;
        r.networkIdHash = keccak256("ethereum-mainnet");
        r.paymentChainId = block.chainid;
        r.assetSymbolHash =
            p.paymentToken == address(0)
                ? keccak256("ETH")
                : (
                    p.paymentToken == usdc
                        ? keccak256("USDC")
                        : keccak256("USDT")
                );
        r.snrgAmountNwei = amount;
        r.paymentAmountRaw = p.paymentAmountRaw;
        r.paymentTokenAddress = p.paymentToken;
        r.paymentTokenDecimals = p.paymentToken == address(0) ? 18 : 6;
        // The EVM cannot access its current transaction hash. This is an explicitly typed purchase reference.
        // Receipt event transactionHash supplies the real transaction hash; never invent one.
        r.paymentTxHash = purchaseId;
        r.stageFrom = p.stageId;
        r.stageTo = p.stageId;
        r.stageId = p.stageId;
        r.priceUsdE8 = p.priceUsdE8;
        r.usdValueE8 = p.usdValueE8;
        r.purchaseTimestamp = p.timestamp;
        r.sourceHash = reward ? REWARD_SOURCE : PURCHASE_SOURCE;
        r.statusHash = keccak256("confirmed");
        r.processedPaymentTx = true;
        r.vesting = Voucher.VestingTerms(0, 0, 0, 10000);
        r.metadataURI = metadataRenderer.uri(
            reward,
            ledgerId,
            purchaseId,
            reward ? 0 : p.baseNwei,
            reward ? amount : p.buyerBonusNwei,
            amount
        );
    }
    /// @notice Confirms an exact canonical mint payload only while this sale is issuing that voucher.
    /// @dev The sealed voucher invokes this view; outside the guarded issuance call both slots are zero.
    ///      Full standard ABI encoding includes every field, the vesting tuple and immutable metadata.
    /// @param issuer Presale or dedicated referral-authorizer caller observed by the voucher.
    /// @param requestHash Keccak-256 of abi.encode(request) for the complete MintRequest.
    /// @return authorized Whether both issuer and payload match the active issuance frame.
    function isMintAuthorized(
        address issuer,
        bytes32 requestHash
    ) external view returns (bool authorized) {
        authorized =
            issuer != address(0) &&
            issuer == _activeMintIssuer &&
            requestHash == _activeMintRequestHash;
    }

    /// @notice Returns ledger capacity available to new purchases after protecting earned rewards.
    /// @dev Pending rewards each reserve one slot. A purchase with a new reward needs two free slots.
    /// @return slots Unreserved IDs remaining in the constructor-approved inclusive ledger range.
    function remainingUnreservedLedgerSlots()
        public
        view
        returns (uint256 slots)
    {
        uint64 next = nextLedgerId;
        if (next > lastLedgerId) return 0;
        slots =
            uint256(lastLedgerId) -
            next +
            1 -
            pendingRewardLedgerReservations;
    }

    /// @notice Allocates one globally unique voucher ledger ID within the approved range.
    /// @dev A reward consumes its existing reservation; purchases cannot spend reserved capacity.
    ///      The newly deployed voucher accepts only exact issuance frames from its two sealed sale issuers.
    /// @param consumeRewardReservation True only for issuance of an already accrued pending reward.
    /// @return ledgerId The next unused ledger ID, checked against the voucher's deduplication map.
    function _allocateLedger(
        bool consumeRewardReservation
    ) private returns (uint64 ledgerId) {
        ledgerId = nextLedgerId;
        if (ledgerId > lastLedgerId) revert LedgerExhausted();
        if (consumeRewardReservation) {
            if (pendingRewardLedgerReservations == 0) revert InvalidReward();
            --pendingRewardLedgerReservations;
        } else if (remainingUnreservedLedgerSlots() == 0) {
            revert LedgerExhausted();
        }
        if (voucher.processedLedgerIds(ledgerId))
            revert LedgerCollision(ledgerId);
        nextLedgerId = ledgerId + 1;
    }
    /// @notice Reads a fresh, bounded ETH/USD price from the pinned Ethereum feed.
    /// @dev No untrusted fallback is used; invalid pricing stops only the affected payment lane.
    /// @return price USD per ETH with eight decimals.
    function _ethPrice() private view returns (uint256 price) {
        price = _validatedPrice(
            ethUsdFeed,
            minimumEthUsdE8,
            maximumEthUsdE8,
            maxOracleAge
        );
    }

    /// @notice Reads a fresh, peg-bounded USD price for an approved payment stablecoin.
    /// @dev Actual validated value determines collection and reporting; tokens are not assumed to equal $1.
    /// @param asset Canonical USDC or USDT address.
    /// @return price USD per stablecoin with eight decimals.
    function _stablecoinPrice(
        address asset
    ) private view returns (uint256 price) {
        IPriceFeed feed = asset == usdc ? usdcUsdFeed : usdtUsdFeed;
        price = _validatedPrice(
            feed,
            minimumStablecoinUsdE8,
            maximumStablecoinUsdE8,
            maxStablecoinOracleAge
        );
    }

    /// @notice Validates one configured feed's scale, round, timestamp and accepted price interval.
    /// @dev Canonical source identity is pinned separately; this cannot prove that an oracle is truthful.
    /// @param feed Approved Ethereum USD feed.
    /// @param minimumPrice Lowest accepted positive answer.
    /// @param maximumPrice Highest accepted positive answer.
    /// @param maximumAge Maximum acceptable age of this feed's last answer in seconds.
    /// @return price Validated eight-decimal USD answer.
    function _validatedPrice(
        IPriceFeed feed,
        uint128 minimumPrice,
        uint128 maximumPrice,
        uint32 maximumAge
    ) private view returns (uint256 price) {
        if (feed.decimals() != 8) revert InvalidOracle();
        (uint80 round, int256 answer, , uint256 updated, uint80 answered) = feed
            .latestRoundData();
        if (
            answer <= 0 ||
            round == 0 ||
            answered < round ||
            updated == 0 ||
            updated > block.timestamp ||
            block.timestamp - updated > maximumAge
        ) revert InvalidOracle();
        price = uint256(answer);
        if (price < minimumPrice || price > maximumPrice)
            revert InvalidOracle();
    }

    /// @notice Rejects configurations whose largest legal orders cannot fit the public quote fields.
    /// @dev Rounding is upward for collection. The ETH USD bound uses the maximum possible rounding
    ///      increment across the entire permitted oracle band, without assuming endpoint monotonicity.
    /// @param s Stage to validate.
    /// @param minimumPrice Lowest accepted ETH/USD answer in E8.
    /// @param maximumPrice Highest accepted ETH/USD answer in E8.
    /// @param minimumStablePrice Lowest accepted stablecoin/USD answer in E8.
    /// @param maximumStablePrice Highest accepted stablecoin/USD answer in E8.
    function _validateQuoteBounds(
        Stage memory s,
        uint128 minimumPrice,
        uint128 maximumPrice,
        uint128 minimumStablePrice,
        uint128 maximumStablePrice
    ) private pure {
        uint256 numerator = uint256(s.baseInventoryNwei) * s.priceUsdE8;
        uint256 maximumOutput = type(uint128).max;
        uint256 stablePayment = Math.ceilDiv(
            numerator,
            uint256(minimumStablePrice) * 1e3
        );
        if (stablePayment > maximumOutput) revert InvalidConfiguration();
        if (
            Math.ceilDiv(numerator, 1e9) +
                Math.ceilDiv(uint256(maximumStablePrice), 1e6) >
            maximumOutput
        ) revert InvalidConfiguration();
        uint256 ethPayment = Math.mulDiv(
            numerator,
            1e9,
            minimumPrice,
            Math.Rounding.Ceil
        );
        if (ethPayment > maximumOutput) revert InvalidConfiguration();
        // ceil(numerator / 1e9) plus at most ceil(maximumPrice / 1e18) for payment-rounding dust.
        if (
            Math.ceilDiv(numerator, 1e9) +
                Math.ceilDiv(uint256(maximumPrice), 1e18) >
            maximumOutput
        ) revert InvalidConfiguration();
    }

    /// @notice Checks a vesting tuple before constructor policy requires immediate full unlock.
    /// @dev The constructor separately requires start zero, no cliff, no duration and 100% initial unlock.
    /// @param v Proposed immutable vesting tuple.
    function _validateVesting(Voucher.VestingTerms memory v) private pure {
        if (
            v.initialUnlockBps > 10000 ||
            (v.durationSeconds == 0 &&
                (v.cliffSeconds != 0 || v.initialUnlockBps != 10000)) ||
            (v.durationSeconds > 0 &&
                (v.vestingStart == 0 || v.cliffSeconds > v.durationSeconds))
        ) revert InvalidConfiguration();
    }
    /// @notice Transfers ETH and requires acceptance by the intended recipient.
    /// @dev Only guarded activation and purchase paths use this helper; both treasury and buyer identities are validated upstream.
    /// @param to Treasury or the original paying buyer.
    /// @param amount Exact wei to transfer.
    function _sendETH(address to, uint256 amount) private {
        (bool ok, ) = to.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }
}
