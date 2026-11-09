// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

/// @title Synergy Claim Voucher Metadata
/// @author Synergy Network
/// @notice Formats self-contained JSON and SVG metadata for purchase and referral vouchers.
/// @dev Rendering proves no issuance or ownership. Consumers must verify the official voucher
///      contract and token ID and read its tokenURI. There is no external hosting dependency,
///      user-controlled text, cryptographic packed encoding, or mutable artwork.
contract VoucherMetadata {
    using Strings for uint256;

    /// @notice The displayed allocation does not satisfy the metadata invariants.
    error InvalidMetadata();

    /// @notice Renders metadata for an internally consistent allocation.
    /// @dev The presale supplies authoritative values and enforces immediate unlock. All
    ///      fragments are fixed text or generated numeric/hexadecimal representations.
    ///      This utility does not authenticate an allocation or establish a claim.
    /// @param reward True for a referral reward; false for a purchase with any buyer bonus.
    /// @param ledgerId Nonzero canonical ledger row.
    /// @param purchaseId Nonzero qualifying purchase ID, not an Ethereum transaction hash.
    /// @param base Purchased SNRG in nWei; zero for a standalone referral reward.
    /// @param bonus Referral entitlement in nWei.
    /// @param total Sum of base and bonus, expressed in nWei.
    /// @return metadataURI Base64 JSON data URI containing embedded SVG artwork.
    function uri(
        bool reward,
        uint64 ledgerId,
        bytes32 purchaseId,
        uint96 base,
        uint96 bonus,
        uint96 total
    ) external pure returns (string memory metadataURI) {
        if (ledgerId == 0) revert InvalidMetadata();
        if (purchaseId == bytes32(0)) revert InvalidMetadata();
        if (total == 0) revert InvalidMetadata();
        if (uint256(base) + bonus != total) revert InvalidMetadata();
        if (reward && base != 0) revert InvalidMetadata();
        string memory kind = reward ? "Referral Reward" : "Purchase";
        string memory svg = string.concat(
            '<svg xmlns="http://www.w3.org/2000/svg" width="800" height="800" viewBox="0 0 800 800">',
            '<rect width="800" height="800" fill="#101828"/><circle cx="400" cy="310" r="180" fill="none" stroke="#53e0bb" stroke-width="12"/>',
            '<text x="400" y="330" text-anchor="middle" fill="white" font-family="sans-serif" font-size="68">SNRG</text>',
            '<text x="400" y="590" text-anchor="middle" fill="#53e0bb" font-family="sans-serif" font-size="34">',
            kind,
            '</text><text x="400" y="650" text-anchor="middle" fill="white" font-family="sans-serif" font-size="24">Soulbound claim voucher</text></svg>'
        );
        string memory json = string.concat(
            '{"name":"Synergy SNRG ',
            kind,
            " Voucher #",
            uint256(ledgerId).toString(),
            '","description":"',
            reward
                ? "Earned referral entitlement. Payment fields reference the qualifying purchase; no new payment or revenue. "
                : "Purchased SNRG and any qualifying buyer referral bonus. ",
            'The recorded allocation is authoritative. SNRG uses 9 decimals. No vesting applies. Redeemable for native SNRG when mainnet redemption is activated. Verify the official voucher contract and token ID.",',
            '"image":"data:image/svg+xml;base64,',
            Base64.encode(bytes(svg)),
            '","attributes":[{"trait_type":"Kind","value":"',
            kind,
            '"},{"trait_type":"Qualifying purchase ID","value":"',
            Strings.toHexString(uint256(purchaseId), 32),
            '"},{"trait_type":"Base purchased nwei","value":"',
            uint256(base).toString(),
            '"},{"trait_type":"Bonus nwei","value":"',
            uint256(bonus).toString(),
            '"},{"trait_type":"Total entitlement nwei","value":"',
            uint256(total).toString(),
            '"}]}'
        );
        metadataURI = string.concat(
            "data:application/json;base64,",
            Base64.encode(bytes(json))
        );
    }
}
