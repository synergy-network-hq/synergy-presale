// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import {SNRGClaimVoucherSoulboundV3 as Voucher} from "./SNRGClaimVoucherSoulboundV3.sol";

/// @title Synergy Referral Voucher Authorizer
/// @author Synergy Network
/// @notice Issues the exact referral allocations authorized by its immutable presale.
/// @dev The presale records and reserves every entitlement before calling this contract.
///      There is no operator signer, owner, discretionary mint method, or payment custody.
///      The voucher's sealed issuer policy independently verifies the complete mint request.
contract ReferralVoucherAuthorizer {
    /// @notice Domain separating referral allocations from paid purchase allocations.
    bytes32 public constant REWARD_SOURCE = keccak256(
        "SYNERGY_REFERRAL_V2_PAYMENT_FIELDS_ATTRIBUTE_ORIGINAL_PURCHASE_NOT_REVENUE"
    );

    /// @notice Presale that deployed this authorizer and is its only permitted caller.
    address public immutable presale;

    /// @notice Voucher contract bound permanently at construction.
    Voucher public immutable voucher;

    /// @notice Completed voucher token ID plus one; zero means not issued.
    /// @dev One is a temporary in-progress marker during the external mint.
    ///      All effects roll back if minting or its receiver callback fails.
    mapping(bytes32 rewardId => uint256 tokenIdPlusOne)
        public issuedTokenPlusOne;

    /// @notice Records issuance to the presale-authorized receiving address.
    /// @param rewardId Canonical entitlement identifier.
    /// @param beneficiary Owner receiving the soulbound voucher.
    /// @param ledgerId Unique ledger row in this voucher deployment.
    /// @param tokenId Newly minted voucher ID.
    /// @param snrgAmountNwei Entitlement in 9-decimal native SNRG base units.
    event ReferralVoucherMinted(
        bytes32 indexed rewardId,
        address indexed beneficiary,
        uint64 ledgerId,
        uint256 tokenId,
        uint96 snrgAmountNwei
    );

    /// @notice The caller is not the immutable presale.
    error Unauthorized();
    /// @notice A dependency or reward payload is invalid or already being issued.
    error InvalidReward();

    /// @notice Binds this authorizer to its deploying presale and deployed voucher.
    /// @dev A separately deployed authorizer is not accepted by the voucher's issuer seal.
    /// @param voucherAddress Address of the deployed voucher contract.
    constructor(address voucherAddress) {
        if (voucherAddress == address(0)) revert InvalidReward();
        if (voucherAddress.code.length == 0) revert InvalidReward();
        presale = msg.sender;
        voucher = Voucher(voucherAddress);
    }

    /// @notice Mints one presale-authorized referral allocation exactly once.
    /// @dev Sets an in-progress marker before interacting with the voucher. The voucher
    ///      also checks the presale's active hash of the complete request. Payment fields
    ///      identify the qualifying purchase and do not represent additional revenue.
    /// @param rewardId Canonical reward ID recorded by the presale.
    /// @param request Exact payload authorized for this issuer by the presale.
    /// @return tokenId Newly issued voucher token ID.
    function issueReferralVoucher(
        bytes32 rewardId,
        Voucher.MintRequest calldata request
    ) external returns (uint256 tokenId) {
        if (msg.sender != presale) revert Unauthorized();
        if (rewardId == bytes32(0)) revert InvalidReward();
        if (issuedTokenPlusOne[rewardId] != 0) revert InvalidReward();
        if (request.saleIdHash != rewardId) revert InvalidReward();
        if (request.sourceHash != REWARD_SOURCE) revert InvalidReward();
        if (request.snrgAmountNwei == 0) revert InvalidReward();
        if (request.walletAddress == address(0)) revert InvalidReward();
        if (request.purchaserAddress == address(0)) revert InvalidReward();
        if (request.paymentAmountRaw == 0) revert InvalidReward();
        if (request.usdValueE8 == 0) revert InvalidReward();
        if (request.ledgerId == 0) revert InvalidReward();
        if (!request.processedPaymentTx || request.nftMinted)
            revert InvalidReward();
        if (request.vesting.initialUnlockBps != 10_000) revert InvalidReward();
        if (request.vesting.vestingStart != 0) revert InvalidReward();
        if (request.vesting.cliffSeconds != 0) revert InvalidReward();
        if (request.vesting.durationSeconds != 0) revert InvalidReward();
        issuedTokenPlusOne[rewardId] = 1;
        tokenId = voucher.mintReceipt(request);
        issuedTokenPlusOne[rewardId] = tokenId + 1;
        emit ReferralVoucherMinted(
            rewardId,
            request.purchaserAddress,
            request.ledgerId,
            tokenId,
            request.snrgAmountNwei
        );
    }
}
