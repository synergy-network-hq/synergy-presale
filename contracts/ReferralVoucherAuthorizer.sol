// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import {SNRGClaimVoucherSoulboundV2 as Voucher} from "./SNRGClaimVoucherSoulboundV2.sol";

/// @title Synergy Referral Voucher Authorizer
/// @notice Ownerless, immutable, restricted minter of already recorded presale referral entitlements.
/// @dev The presale remains the canonical entitlement ledger and maintains the global ledger cursor.
///      This contract never receives funds or accepts arbitrary user-provided reward claims.
///      It must be granted MINTER_ROLE on the existing voucher by the Treasury Safe.
contract ReferralVoucherAuthorizer {
    bytes32 public constant REWARD_SOURCE = keccak256("SYNERGY_REFERRAL_V2_PAYMENT_FIELDS_ATTRIBUTE_ORIGINAL_PURCHASE_NOT_REVENUE");
    address public immutable presale;
    Voucher public immutable voucher;
    mapping(bytes32 => uint256) public issuedTokenPlusOne;
    event ReferralVoucherMinted(bytes32 indexed rewardId,address indexed beneficiary,uint64 ledgerId,uint256 tokenId,uint96 snrgAmountNwei);
    error Unauthorized();
    error InvalidReward();

    constructor(address voucherAddress) {
        if(voucherAddress.code.length == 0) revert InvalidReward();
        presale=msg.sender; // Deployed by presale constructor, not by an operator EOA.
        voucher=Voucher(voucherAddress);
    }

    /// @dev The caller MUST be the immutable presale contract. Entitlement legitimacy is checked
    /// by the presale against its stored Reward record before calling this function.
    function issueReferralVoucher(bytes32 rewardId,Voucher.MintRequest calldata request) external returns(uint256 tokenId) {
        if(msg.sender!=presale) revert Unauthorized();
        if(rewardId==bytes32(0) || issuedTokenPlusOne[rewardId]!=0 ||
           request.saleIdHash!=rewardId || request.sourceHash!=REWARD_SOURCE ||
           request.snrgAmountNwei==0 || request.purchaserAddress==address(0) ||
           request.paymentAmountRaw==0 || request.usdValueE8==0 ||
           request.ledgerId==0 || !request.processedPaymentTx ||
           request.vesting.initialUnlockBps!=10000 || request.vesting.cliffSeconds!=0 ||
           request.vesting.durationSeconds!=0) revert InvalidReward();
        tokenId=voucher.mintReceipt(request);
        issuedTokenPlusOne[rewardId]=tokenId+1;
        emit ReferralVoucherMinted(rewardId,request.purchaserAddress,request.ledgerId,tokenId,request.snrgAmountNwei);
    }
}
