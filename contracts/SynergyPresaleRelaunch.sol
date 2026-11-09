// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

//
//     ▗▄▖                               ▗▄ ▗▖                      ▗▖
//    ▗▛▀▜                               ▐█ ▐▌     ▐▌               ▐▌
//    ▐▙  ▝█ █▌▐▙██▖ ▟█▙ █▟█▌▟█▟▌▝█ █▌   ▐▛▌▐▌ ▟█▙▐████   █ ▟█▙ █▟█▌▐▌▟▛
//     ▜█▙ █▖█ ▐▛ ▐▌▐▙▄▟▌█▘ ▐▛ ▜▌ █▖█    ▐▌█▐▌▐▙▄▟▌▐▌ ▜ █ ▛▐▛ ▜▌█▘  ▐▙█
//       ▜▌▐█▛ ▐▌ ▐▌▐▛▀▀▘█  ▐▌ ▐▌ ▐█▛    ▐▌▐▟▌▐▛▀▀▘▐▌ ▐▙█▟▌▐▌ ▐▌█   ▐▛█▖
//    ▐▄▄▟▘ █▌ ▐▌ ▐▌▝█▄▄▌█  ▝█▄█▌  █▌    ▐▌ █▌▝█▄▄▌▐▙▄▝█ █▘▝█▄█▘█   ▐▌▝▙
//     ▀▀▘  █  ▝▘ ▝▘ ▝▀▀ ▀   ▞▀▐▌  █     ▝▘ ▀▘ ▝▀▀  ▀▀ ▀ ▀  ▝▀▘ ▀   ▝▘ ▀▘
//         █▌                ▜█▛▘ █▌
//     ▗▄▖ ▗▄ ▗▖▗▄▄▖   ▄▄      ▄▄        █          ▗▄▄▖                  ▗▄▖
//    ▗▛▀▜ ▐█ ▐▌▐▛▀▜▌ █▀▀▌    █▀▀▌       ▀          ▐▛▀▜▖                 ▝▜▌
//    ▐▙   ▐▛▌▐▌▐▌ ▐▌▐▌      ▐▛    ▟█▙  ██  ▐▙██▖   ▐▌ ▐▌█▟█▌▟█▙ ▗▟██▖ ▟██▖▐▌  ▟█▙
//     ▜█▙ ▐▌█▐▌▐███ ▐▌▗▄▖   ▐▌   ▐▛ ▜▌  █  ▐▛ ▐▌   ▐██▛ █▘ ▐▙▄▟▌▐▙▄▖▘ ▘▄▟▌▐▌ ▐▙▄▟▌
//       ▜▌▐▌▐▟▌▐▌▝█▖▐▌▝▜▌   ▐▙   ▐▌ ▐▌  █  ▐▌ ▐▌   ▐▌   █  ▐▛▀▀▘ ▀▀█▖▗█▀▜▌▐▌ ▐▛▀▀▘
//    ▐▄▄▟▘▐▌ █▌▐▌ ▐▌ █▄▟▌    █▄▄▌▝█▄█▘▗▄█▄▖▐▌ ▐▌   ▐▌   █  ▝█▄▄▌▐▄▄▟▌▐▙▄█▌▐▙▄▝█▄▄▌
//     ▀▀▘ ▝▘ ▀▘▝▘ ▝▀  ▀▀      ▀▀  ▝▀▘ ▝▀▀▀▘▝▘ ▝▘   ▝▘   ▀   ▝▀▀  ▀▀▀  ▀▀▝▘ ▀▀ ▝▀▀
//    ▗▄▄▖     ▗▄▖                     ▗▖
//    ▐▛▀▜▌    ▝▜▌                     ▐▌
//    ▐▌ ▐▌ ▟█▙ ▐▌  ▟██▖▐▌ ▐▌▐▙██▖ ▟██▖▐▙██▖
//    ▐███ ▐▙▄▟▌▐▌  ▘▄▟▌▐▌ ▐▌▐▛ ▐▌▐▛  ▘▐▛ ▐▌
//    ▐▌▝█▖▐▛▀▀▘▐▌ ▗█▀▜▌▐▌ ▐▌▐▌ ▐▌▐▌   ▐▌ ▐▌
//    ▐▌ ▐▌▝█▄▄▌▐▙▄▐▙▄█▌▐▙▄█▌▐▌ ▐▌▝█▄▄▌▐▌ ▐▌
//    ▝▘ ▝▀ ▝▀▀  ▀▀ ▀▀▝▘ ▀▀▝▘▝▘ ▝▘ ▝▀▀ ▝▘ ▝▘
//
//

import {SNRGClaimVoucherSoulboundV2 as Voucher} from "./SNRGClaimVoucherSoulboundV2.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {SafeERC20, IERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {VoucherMetadata} from "./VoucherMetadata.sol";
import {ReferralVoucherAuthorizer} from "./ReferralVoucherAuthorizer.sol";

interface IPriceFeed {
    function decimals() external view returns (uint8);
    function latestRoundData() external view returns (uint80,int256,uint256,uint256,uint80);
}
interface ISafeView {
    function getThreshold() external view returns (uint256);
    function getOwners() external view returns (address[] memory);
}

/// @notice REVIEW CANDIDATE. Preserves the existing voucher; no production deployment script.
/// @dev No upgrade path, no arbitrary mint, no adjustable earned amounts. Commercial parameters
/// are constructor inputs and immutable after deployment. See docs/CTO_REVIEW.md before integration.
contract SynergyPresaleRelaunch is ReentrancyGuard {
    using SafeERC20 for IERC20;
    using SafeCast for uint256;

    bytes32 public constant PURCHASE_SOURCE = keccak256("SYNERGY_PRESALE_V2_PAYMENT_REFERENCE_IS_PURCHASE_ID");
    bytes32 public constant REWARD_SOURCE = keccak256("SYNERGY_REFERRAL_V2_PAYMENT_FIELDS_ATTRIBUTE_ORIGINAL_PURCHASE_NOT_REVENUE");
    bytes32 private constant MINTER_ROLE = keccak256("MINTER_ROLE");
    enum RewardMode { Unset, VoucherBacked, NativeLedger } // Only VoucherBacked is accepted in this revision
    enum RewardState { Absent, Pending, Voucherized, SettlementRequested }
    struct Stage { uint64 startsAt; uint64 endsAt; uint128 priceUsdE8; uint96 baseInventoryNwei; }
    struct ReferralPolicy {
        uint16 buyerBps;
        uint16 referrerBps;
        uint96 minimumBaseNwei;
        uint128 minimumUsdE8;
        uint96 incentiveBudgetNwei;
        bool repeatPurchases;
        RewardMode rewardMode;
    }
    struct Config {
        address treasurySafe;
        address voucher;
        address usdc;
        address usdt;
        address ethUsdFeed;
        bytes32 referralCodeManifestHash;
        uint256 expectedChainId;
        bytes32 expectedSaleProgramId;
        bytes32 approvalHash;
        bytes32 historicalSnapshotHash;
        bytes32 historicalPurchaserManifestHash;
        uint96 historicalPurchasedNwei;
        uint96 historicalOtherEntitlementsNwei;
        uint96 otherNetworkReservationsNwei;
        uint96 networkSupplyCapNwei;
        uint96 minimumPurchaseNwei;
        uint64 firstLedgerId;
        uint64 lastLedgerId;
        uint32 maxOracleAge;
        uint128 minimumEthUsdE8;
        uint128 maximumEthUsdE8;
        Stage[8] stages;
        ReferralPolicy policy;
        Voucher.VestingTerms purchaseVesting;
        Voucher.VestingTerms rewardVesting;
    }
    struct Order { uint96 baseAmountNwei; uint128 maxPaymentRaw; uint8 expectedStage; uint128 expectedPriceUsdE8; uint64 deadline; }
    struct Quote { uint8 stageId; uint64 expiresAt; uint128 priceUsdE8; uint128 paymentAmountRaw; uint128 usdValueE8; }
    struct Purchase {
        address buyer; address referrer; bytes32 codeHash; address paymentToken;
        uint96 baseNwei; uint96 buyerBonusNwei; uint96 totalNwei;
        uint128 paymentAmountRaw; uint128 usdValueE8; uint128 priceUsdE8;
        uint64 timestamp; uint64 ledgerId; uint8 stageId; uint256 voucherTokenId;
    }
    struct Reward { bytes32 purchaseId; address referrer; uint96 amountNwei; RewardState state; uint64 ledgerId; uint256 voucherTokenId; }

    address public immutable treasury;
    Voucher public immutable voucher;
    address public immutable usdc;
    address public immutable usdt;
    IPriceFeed public immutable ethUsdFeed;
    VoucherMetadata public immutable metadataRenderer;
    uint32 public immutable maxOracleAge;
    uint128 public immutable minimumEthUsdE8;
    uint128 public immutable maximumEthUsdE8;
    uint96 public immutable minimumPurchaseNwei;
    uint96 public immutable historicalPurchasedNwei;
    uint96 public immutable historicalOtherEntitlementsNwei;
    uint96 public immutable otherNetworkReservationsNwei;
    uint96 public immutable networkSupplyCapNwei;
    bytes32 public immutable historicalSnapshotHash;
    bytes32 public immutable historicalPurchaserManifestHash;
    bytes32 public immutable approvalHash;
    bytes32 public immutable policyHash;
    uint64 public immutable firstLedgerId;
    uint64 public immutable lastLedgerId;
    Stage[8] public stages;
    ReferralPolicy public referralPolicy;
    Voucher.VestingTerms public purchaseVesting;
    Voucher.VestingTerms public rewardVesting;
    ReferralVoucherAuthorizer public immutable referralAuthorizer;
    bytes32 public immutable referralCodeManifestHash;
    bytes32 public importedReferralCodeManifestHash;
    bytes32 public lastImportedReferralCode;
    uint256 public constant AUTO_REWARD_GAS = 900_000;
    uint256 public constant MIN_AUTOMINT_GAS_LEFT = 1_200_000;
    bool public paused = true;
    bool public claimsPaused;
    bool public activated;
    bytes32 public importedPurchaserManifestHash;
    address public lastImportedPurchaser;
    uint64 public nextLedgerId;
    uint256 public purchaseCount;
    uint256 public newSalesUsdE8;
    uint256 public newBasePurchasedNwei;
    uint256 public buyerBonusesIssuedNwei;
    uint256 public referrerRewardsEarnedNwei;
    uint256 public referrerRewardsVoucherizedNwei;
    uint256 public referrerRewardsSettlementRequestedNwei;
    mapping(uint8 => uint96) public baseSoldInStageNwei;
    mapping(address => uint256) public buyerPurchaseCount;
    mapping(address => bool) public referralEligible;
    mapping(address => address) public assignedReferrer;
    mapping(bytes32 => address) public referralCodeOwner;
    mapping(address => bytes32) public walletReferralCode;
    mapping(address => uint256) public revenueRawByAsset;
    mapping(bytes32 => Purchase) public purchases;
    mapping(bytes32 => Reward) public rewards;

    error InvalidConfiguration(); error Unauthorized(); error Paused(); error Closed();
    error StaleQuote(); error InvalidPurchase(); error InventoryExceeded(); error InvalidOracle();
    error InvalidReferral(); error IncentiveCapExceeded(); error LedgerExhausted();
    error LedgerCollision(uint64 ledgerId); error InvalidReward(); error TransferFailed();
    event Purchased(bytes32 indexed purchaseId,address indexed buyer,uint256 indexed voucherTokenId,uint64 ledgerId,address paymentToken,uint128 paymentAmountRaw,uint128 usdValueE8,uint96 baseNwei,uint96 buyerBonusNwei,uint96 totalNwei,uint8 stageId,uint128 priceUsdE8);
    event BuyerReferralBonus(bytes32 indexed purchaseId,address indexed referrer,bytes32 indexed codeHash,uint96 bonusNwei);
    event ReferralRewardAccrued(bytes32 indexed rewardId,bytes32 indexed purchaseId,address indexed referrer,uint96 amountNwei);
    event ReferralRewardVoucherIssued(bytes32 indexed rewardId,bytes32 indexed purchaseId,address indexed referrer,uint256 tokenId,uint64 ledgerId,uint96 amountNwei);
    event ReferralRewardSettlementRequested(bytes32 indexed rewardId,address indexed referrer,bytes32 indexed destinationNetworkIdHash,string synergyRecipient,uint96 amountNwei);
    event HistoricalPurchaserImported(address indexed purchaser,uint256 purchaseCount,bool eligible,bytes32 cumulativeManifestHash);
    event Activated(bytes32 indexed approvalHash,bytes32 indexed policyHash);
    event PauseChanged(bool purchasesPaused,bool rewardClaimsPaused);
    event ReferralCodeRegistered(bytes32 indexed codeHash,address indexed owner);
    event ReferralMintDeferred(bytes32 indexed rewardId,bytes32 indexed purchaseId);

    modifier onlySafe() { if (msg.sender != treasury) revert Unauthorized(); _; }

    constructor(Config memory c) {
        if (block.chainid != c.expectedChainId || c.treasurySafe.code.length == 0 ||
            c.voucher.code.length == 0 || c.usdc.code.length == 0 || c.usdt.code.length == 0 ||
            c.ethUsdFeed.code.length == 0 || c.usdc == c.usdt || c.referralCodeManifestHash == bytes32(0) ||
            c.approvalHash == 0 || c.historicalSnapshotHash == 0 || c.minimumPurchaseNwei == 0 ||
            c.firstLedgerId == 0 || c.lastLedgerId < c.firstLedgerId || c.lastLedgerId == type(uint64).max ||
            c.maxOracleAge == 0 || c.maxOracleAge > 1 days || c.minimumEthUsdE8 == 0 ||
            c.maximumEthUsdE8 < c.minimumEthUsdE8 || c.networkSupplyCapNwei == 0) revert InvalidConfiguration();
        if (block.chainid == 1 && (c.voucher != 0xF913ddCe2Bf4FCA896332086c08B90A1A06fc7A9 ||
            c.treasurySafe != 0x72F57B74C0b2D556589CeB393103bea0f631933B ||
            c.usdc != 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 ||
            c.usdt != 0xdAC17F958D2ee523a2206206994597C13D831ec7 ||
            c.ethUsdFeed != 0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419)) revert InvalidConfiguration();
        uint256 threshold = ISafeView(c.treasurySafe).getThreshold();
        if (threshold < 2 || threshold > ISafeView(c.treasurySafe).getOwners().length) revert InvalidConfiguration();
        if (IERC20Metadata(c.usdc).decimals()!=6 || IERC20Metadata(c.usdt).decimals()!=6 ||
            IPriceFeed(c.ethUsdFeed).decimals()!=8 || c.expectedSaleProgramId==0 ||
            Voucher(c.voucher).saleProgramId()!=c.expectedSaleProgramId) revert InvalidConfiguration();
        uint256 maximumObligations = uint256(c.historicalPurchasedNwei) + c.historicalOtherEntitlementsNwei + c.otherNetworkReservationsNwei + c.policy.incentiveBudgetNwei;
        for (uint256 i; i<8; ++i) {
            Stage memory s = c.stages[i];
            if (s.startsAt >= s.endsAt || s.priceUsdE8==0 || s.baseInventoryNwei==0 ||
                (i==0 && s.startsAt<=block.timestamp) || (i>0 && s.startsAt!=c.stages[i-1].endsAt)) revert InvalidConfiguration();
            stages[i]=s;
            maximumObligations += s.baseInventoryNwei;
        }
        if (maximumObligations > c.networkSupplyCapNwei || c.policy.buyerBps>10000 || c.policy.referrerBps>10000 ||
            c.policy.rewardMode!=RewardMode.VoucherBacked) revert InvalidConfiguration();
        if ((c.policy.buyerBps!=0 || c.policy.referrerBps!=0) && c.policy.incentiveBudgetNwei==0) revert InvalidConfiguration();
        _validateVesting(c.purchaseVesting); _validateVesting(c.rewardVesting);
        if(c.purchaseVesting.initialUnlockBps!=10000 || c.purchaseVesting.cliffSeconds!=0 || c.purchaseVesting.durationSeconds!=0 ||
           c.rewardVesting.initialUnlockBps!=10000 || c.rewardVesting.cliffSeconds!=0 || c.rewardVesting.durationSeconds!=0) revert InvalidConfiguration();
        if (Voucher(c.voucher).processedLedgerIds(c.firstLedgerId)) revert LedgerCollision(c.firstLedgerId);
        treasury=c.treasurySafe; voucher=Voucher(c.voucher); usdc=c.usdc; usdt=c.usdt;
        metadataRenderer=new VoucherMetadata();
        ethUsdFeed=IPriceFeed(c.ethUsdFeed); maxOracleAge=c.maxOracleAge;
        minimumEthUsdE8=c.minimumEthUsdE8; maximumEthUsdE8=c.maximumEthUsdE8;
        minimumPurchaseNwei=c.minimumPurchaseNwei;
        historicalPurchasedNwei=c.historicalPurchasedNwei;
        historicalOtherEntitlementsNwei=c.historicalOtherEntitlementsNwei;
        otherNetworkReservationsNwei=c.otherNetworkReservationsNwei; networkSupplyCapNwei=c.networkSupplyCapNwei;
        historicalSnapshotHash=c.historicalSnapshotHash; historicalPurchaserManifestHash=c.historicalPurchaserManifestHash;
        approvalHash=c.approvalHash; referralPolicy=c.policy; policyHash=keccak256(abi.encode(c.policy));
        purchaseVesting=c.purchaseVesting; rewardVesting=c.rewardVesting;
        referralCodeManifestHash=c.referralCodeManifestHash;
        referralAuthorizer=new ReferralVoucherAuthorizer(address(voucher));
        firstLedgerId=c.firstLedgerId; lastLedgerId=c.lastLedgerId; nextLedgerId=c.firstLedgerId;
    }

    /// @notice Safe-only ordered import before activation; includes all historical buyers for repeat rules.
    /// Hash chain must equal the approved manifest. This never mints or changes historical entitlements.
    function importHistoricalPurchasers(address[] calldata accounts,uint256[] calldata counts,bool[] calldata eligible) external onlySafe {
        if (activated || accounts.length==0 || accounts.length!=counts.length || counts.length!=eligible.length) revert InvalidConfiguration();
        for(uint256 i;i<accounts.length;++i) {
            if(accounts[i]<=lastImportedPurchaser || counts[i]==0) revert InvalidConfiguration();
            lastImportedPurchaser=accounts[i]; buyerPurchaseCount[accounts[i]]=counts[i]; referralEligible[accounts[i]]=eligible[i];
            importedPurchaserManifestHash=keccak256(abi.encode(importedPurchaserManifestHash,accounts[i],counts[i],eligible[i]));
            emit HistoricalPurchaserImported(accounts[i],counts[i],eligible[i],importedPurchaserManifestHash);
        }
    }
    /// @notice One-time Safe migration of canonical existing website referral codes.
    /// @dev Codes MUST be sorted strictly ascending. Verify full migration manifest prior to activation.
    function importReferralCodes(bytes32[] calldata codes,address[] calldata owners) external onlySafe {
        if(activated || codes.length==0 || codes.length!=owners.length) revert InvalidConfiguration();
        for(uint256 i;i<codes.length;++i) {
            if(codes[i]<=lastImportedReferralCode || owners[i]==address(0) ||
               referralCodeOwner[codes[i]]!=address(0) || walletReferralCode[owners[i]]!=bytes32(0)) revert InvalidConfiguration();
            lastImportedReferralCode=codes[i];
            referralCodeOwner[codes[i]]=owners[i]; walletReferralCode[owners[i]]=codes[i];
            importedReferralCodeManifestHash=keccak256(abi.encode(importedReferralCodeManifestHash,codes[i],owners[i]));
            emit ReferralCodeRegistered(codes[i],owners[i]);
        }
    }
    /// @notice After initial purchase, users may register a unique code on-chain.
    /// @dev Frontend must check this registry before advertising new referral links.
    function registerReferralCode(bytes32 codeHash) external {
        if(!activated || !referralEligible[msg.sender] || codeHash==bytes32(0) ||
           referralCodeOwner[codeHash]!=address(0) || walletReferralCode[msg.sender]!=bytes32(0)) revert InvalidReferral();
        referralCodeOwner[codeHash]=msg.sender;
        walletReferralCode[msg.sender]=codeHash;
        emit ReferralCodeRegistered(codeHash,msg.sender);
    }
    function activate() external onlySafe {
        if(activated || block.timestamp>=stages[0].startsAt || importedPurchaserManifestHash!=historicalPurchaserManifestHash ||
            importedReferralCodeManifestHash!=referralCodeManifestHash ||
            !voucher.hasRole(MINTER_ROLE,address(this)) ||
            !voucher.hasRole(MINTER_ROLE,address(referralAuthorizer)) || voucher.paused()) revert InvalidConfiguration();
        activated=true; paused=false; emit Activated(approvalHash,policyHash);
    }
    function setPaused(bool purchasesPaused,bool rewardsPaused) external onlySafe {
        if(!activated && !purchasesPaused) revert InvalidConfiguration();
        paused=purchasesPaused; claimsPaused=rewardsPaused; emit PauseChanged(paused,claimsPaused);
    }
    /// @return 0 before opening, 1..8 during stages, 9 at/after final expiration. Sellout never advances time.
    function currentStage() public view returns(uint8) {
        if(block.timestamp<stages[0].startsAt) return 0;
        for(uint8 i;i<8;++i) if(block.timestamp<stages[i].endsAt) return i+1;
        return 9;
    }
    function saleClosed() external view returns(bool) { return block.timestamp>=stages[7].endsAt; }
    function remainingReferralIncentivesNwei() public view returns(uint256) {
        return uint256(referralPolicy.incentiveBudgetNwei)-buyerBonusesIssuedNwei-referrerRewardsEarnedNwei;
    }
    function referrerRewardsAwaitingVoucherNwei() external view returns(uint256) {
        return referralPolicy.rewardMode==RewardMode.VoucherBacked ? referrerRewardsEarnedNwei-referrerRewardsVoucherizedNwei : 0;
    }
    function referrerRewardsPendingNwei() public view returns(uint256) {
        return referrerRewardsEarnedNwei-referrerRewardsVoucherizedNwei-referrerRewardsSettlementRequestedNwei;
    }
    /// @notice Conservatively reserved lifetime obligations. A burn is NOT proof of native settlement.
    /// No release/reuse of supply occurs here; native settled/outstanding balances are reconciled off-chain.
    function totalEntitlementObligationsNwei() public view returns(uint256) {
        return uint256(historicalPurchasedNwei)+historicalOtherEntitlementsNwei+newBasePurchasedNwei+buyerBonusesIssuedNwei+referrerRewardsEarnedNwei;
    }
    function quote(address asset,uint96 baseAmount) public view returns(Quote memory q) {
        uint8 stageId=currentStage(); if(stageId==0 || stageId==9) revert Closed();
        Stage memory s=stages[stageId-1];
        if(baseAmount<minimumPurchaseNwei) revert InvalidPurchase();
        if(baseAmount>uint256(s.baseInventoryNwei)-baseSoldInStageNwei[stageId]) revert InventoryExceeded();
        uint256 numerator=uint256(baseAmount)*s.priceUsdE8;
        q.stageId=stageId; q.expiresAt=s.endsAt; q.priceUsdE8=s.priceUsdE8;
        if(asset==address(0)) {
            uint256 price=_ethPrice();
            q.paymentAmountRaw=Math.mulDiv(numerator,1e9,price,Math.Rounding.Ceil).toUint128();
            q.usdValueE8=Math.mulDiv(q.paymentAmountRaw,price,1e18,Math.Rounding.Ceil).toUint128();
        } else {
            if(asset!=usdc && asset!=usdt) revert InvalidPurchase();
            q.paymentAmountRaw=Math.ceilDiv(numerator,1e11).toUint128();
            q.usdValueE8=(uint256(q.paymentAmountRaw)*100).toUint128();
        }
    }
    function buyWithETH(Order calldata o,bytes32 referralCodeHash) external payable nonReentrant returns(bytes32,uint256) {
        return _buy(address(0),o,referralCodeHash);
    }
    function buyWithUSDC(Order calldata o,bytes32 referralCodeHash) external nonReentrant returns(bytes32,uint256) {
        return _buy(usdc,o,referralCodeHash);
    }
    function buyWithUSDT(Order calldata o,bytes32 referralCodeHash) external nonReentrant returns(bytes32,uint256) {
        return _buy(usdt,o,referralCodeHash);
    }
    function _buy(address asset,Order calldata o,bytes32 referralCodeHash) private returns(bytes32 purchaseId,uint256 tokenId) {
        if(paused || !activated) revert Paused();
        if(block.timestamp>o.deadline || msg.sender==treasury) revert InvalidPurchase();
        Quote memory q=quote(asset,o.baseAmountNwei);
        if(q.stageId!=o.expectedStage || q.priceUsdE8!=o.expectedPriceUsdE8 || q.paymentAmountRaw>o.maxPaymentRaw) revert StaleQuote();
        if(asset==address(0) && (msg.value<q.paymentAmountRaw || msg.value>o.maxPaymentRaw)) revert InvalidPurchase();
        (address referrer,uint96 buyerBonus,uint96 referrerBonus)=_referral(o.baseAmountNwei,q,referralCodeHash);
        if(uint256(buyerBonus)+referrerBonus>remainingReferralIncentivesNwei()) revert IncentiveCapExceeded();
        uint64 ledgerId=_allocateLedger();
        purchaseId=keccak256(abi.encode(PURCHASE_SOURCE,block.chainid,address(this),ledgerId));
        Purchase memory p=Purchase(msg.sender,referrer,referralCodeHash,asset,o.baseAmountNwei,buyerBonus,
            (uint256(o.baseAmountNwei)+buyerBonus).toUint96(),q.paymentAmountRaw,q.usdValueE8,q.priceUsdE8,
            uint64(block.timestamp),ledgerId,q.stageId,0);
        purchases[purchaseId]=p;
        baseSoldInStageNwei[q.stageId]+=o.baseAmountNwei; newBasePurchasedNwei+=o.baseAmountNwei;
        buyerBonusesIssuedNwei+=buyerBonus; referrerRewardsEarnedNwei+=referrerBonus;
        ++purchaseCount; ++buyerPurchaseCount[msg.sender]; referralEligible[msg.sender]=true;
        newSalesUsdE8+=q.usdValueE8; revenueRawByAsset[asset]+=q.paymentAmountRaw;
        if(referrer!=address(0)) {
            assignedReferrer[msg.sender]=referrer;
            emit BuyerReferralBonus(purchaseId,referrer,referralCodeHash,buyerBonus);
        }
        if(referrerBonus!=0) {
            bytes32 rewardId=keccak256(abi.encode(REWARD_SOURCE,block.chainid,address(this),purchaseId));
            rewards[rewardId]=Reward(purchaseId,referrer,referrerBonus,RewardState.Pending,0,0);
            emit ReferralRewardAccrued(rewardId,purchaseId,referrer,referrerBonus);
        }
        if(totalEntitlementObligationsNwei()+otherNetworkReservationsNwei>networkSupplyCapNwei) revert IncentiveCapExceeded();
        if(asset!=address(0)) {
            uint256 beforeBalance=IERC20(asset).balanceOf(treasury);
            IERC20(asset).safeTransferFrom(msg.sender,treasury,q.paymentAmountRaw);
            if(IERC20(asset).balanceOf(treasury)!=beforeBalance+q.paymentAmountRaw) revert TransferFailed();
        }
        tokenId=voucher.mintReceipt(_mintRequest(p,purchaseId,purchaseId,ledgerId,msg.sender,p.totalNwei,false));
        purchases[purchaseId].voucherTokenId=tokenId;
        if(asset==address(0)) {
            _sendETH(treasury,q.paymentAmountRaw);
            if(msg.value>q.paymentAmountRaw) _sendETH(msg.sender,msg.value-q.paymentAmountRaw);
        }
        emit Purchased(purchaseId,msg.sender,tokenId,ledgerId,asset,p.paymentAmountRaw,p.usdValueE8,p.baseNwei,p.buyerBonusNwei,p.totalNwei,p.stageId,p.priceUsdE8);
        // Best effort: failure MUST NOT revert a valid paid purchase.
        // The canonical pending entitlement remains in `rewards` for permissionless recovery.
        if(referrerBonus!=0) {
            bytes32 rewardId=keccak256(abi.encode(REWARD_SOURCE,block.chainid,address(this),purchaseId));
            if(gasleft()>=MIN_AUTOMINT_GAS_LEFT) {
                try this.issueRewardForPurchase{gas:AUTO_REWARD_GAS}(rewardId) returns(uint256) {
                    // Success is emitted by issueRewardForPurchase.
                } catch { emit ReferralMintDeferred(rewardId,purchaseId); }
            } else { emit ReferralMintDeferred(rewardId,purchaseId); }
        }
    }
    /// @dev Invalid/unqualified codes yield no rewards; they never cancel a legitimate purchase.
    function _referral(uint96 base,Quote memory q,bytes32 codeHash) private view returns(address,uint96,uint96) {
        if(codeHash==bytes32(0)) return(address(0),0,0);
        address referrer=referralCodeOwner[codeHash];
        ReferralPolicy memory p=referralPolicy;
        if(referrer==address(0) || referrer==msg.sender || !referralEligible[referrer] ||
           (!p.repeatPurchases && buyerPurchaseCount[msg.sender]!=0) ||
           (assignedReferrer[msg.sender]!=address(0) && assignedReferrer[msg.sender]!=referrer) ||
           base<=25_000 * 1e9 || base<p.minimumBaseNwei || q.usdValueE8<p.minimumUsdE8) {
            return(address(0),0,0);
        }
        uint96 buyer=(uint256(base)*p.buyerBps/10000).toUint96();
        uint96 referral=(uint256(base)*p.referrerBps/10000).toUint96();
        if(uint256(buyer)+referral>remainingReferralIncentivesNwei()) return(address(0),0,0);
        return(referrer,buyer,referral);
    }
    /// @notice Only used through a self-call from the original purchase, so failure is catchable.
    function issueRewardForPurchase(bytes32 rewardId) external returns(uint256 tokenId) {
        if(msg.sender!=address(this)) revert Unauthorized();
        return _issueReward(rewardId);
    }
    /// @notice Permissionless retry: any wallet can sponsor gas, recipient is fixed on-chain.
    function claimRewardVoucher(bytes32 rewardId) external nonReentrant returns(uint256 tokenId) {
        if(claimsPaused) revert Paused();
        return _issueReward(rewardId);
    }
    function _issueReward(bytes32 rewardId) private returns(uint256 tokenId) {
        Reward storage r=rewards[rewardId];
        if(r.state!=RewardState.Pending || r.amountNwei==0) revert InvalidReward();
        uint64 ledgerId=_allocateLedger();
        r.state=RewardState.Voucherized; r.ledgerId=ledgerId;
        Purchase memory p=purchases[r.purchaseId];
        Voucher.MintRequest memory request=_mintRequest(p,rewardId,r.purchaseId,ledgerId,r.referrer,r.amountNwei,true);
        tokenId=referralAuthorizer.issueReferralVoucher(rewardId,request);
        r.voucherTokenId=tokenId;
        referrerRewardsVoucherizedNwei+=r.amountNwei;
        emit ReferralRewardVoucherIssued(rewardId,r.purchaseId,r.referrer,tokenId,ledgerId,r.amountNwei);
    }
    function _mintRequest(Purchase memory p,bytes32 saleId,bytes32 purchaseId,uint64 ledgerId,address recipient,uint96 amount,bool reward) private view returns(Voucher.MintRequest memory r) {
        r.ledgerId=ledgerId; r.saleIdHash=saleId; r.walletAddress=p.buyer; r.purchaserAddress=recipient;
        r.networkIdHash=keccak256("ethereum-mainnet"); r.paymentChainId=block.chainid;
        r.assetSymbolHash=p.paymentToken==address(0)?keccak256("ETH"):(p.paymentToken==usdc?keccak256("USDC"):keccak256("USDT"));
        r.snrgAmountNwei=amount; r.paymentAmountRaw=p.paymentAmountRaw; r.paymentTokenAddress=p.paymentToken;
        r.paymentTokenDecimals=p.paymentToken==address(0)?18:6;
        // The EVM cannot access its current transaction hash. This is an explicitly typed purchase reference.
        // Receipt event transactionHash supplies the real transaction hash; never invent one.
        r.paymentTxHash=purchaseId; r.stageFrom=p.stageId; r.stageTo=p.stageId; r.stageId=p.stageId;
        r.priceUsdE8=p.priceUsdE8; r.usdValueE8=p.usdValueE8; r.purchaseTimestamp=p.timestamp;
        r.sourceHash=reward?REWARD_SOURCE:PURCHASE_SOURCE; r.statusHash=keccak256("confirmed"); r.processedPaymentTx=true;
        r.vesting=reward?rewardVesting:purchaseVesting;
        r.metadataURI=metadataRenderer.uri(reward,ledgerId,purchaseId,reward?0:p.baseNwei,reward?amount:p.buyerBonusNwei,amount);
    }
    function _allocateLedger() private returns(uint64 ledgerId) {
        ledgerId=nextLedgerId; if(ledgerId>lastLedgerId) revert LedgerExhausted();
        if(voucher.processedLedgerIds(ledgerId)) revert LedgerCollision(ledgerId);
        nextLedgerId=ledgerId+1;
    }
    function _ethPrice() private view returns(uint256) {
        (uint80 round,int256 answer,,uint256 updated,uint80 answered)=ethUsdFeed.latestRoundData();
        if(answer<=0 || round==0 || answered<round || updated==0 || updated>block.timestamp ||
            block.timestamp-updated>maxOracleAge || uint256(answer)<minimumEthUsdE8 || uint256(answer)>maximumEthUsdE8) revert InvalidOracle();
        return uint256(answer);
    }
    function _validateVesting(Voucher.VestingTerms memory v) private pure {
        if(v.initialUnlockBps>10000 || (v.durationSeconds==0 && (v.cliffSeconds!=0 || v.initialUnlockBps!=10000)) ||
            (v.durationSeconds>0 && (v.vestingStart==0 || v.cliffSeconds>v.durationSeconds))) revert InvalidConfiguration();
    }
    function _sendETH(address to,uint256 amount) private { (bool ok,)=to.call{value:amount}(""); if(!ok) revert TransferFailed(); }
}
