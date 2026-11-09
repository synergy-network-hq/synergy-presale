// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

/// @title Synergy Protected-Wallet Recipient Codec
/// @author Synergy Network
/// @notice Decodes only the exact canonical SYNW_HEX_EIP55_V1 display profile.
/// @dev The address is the lowercase literal "synw" followed by 40 checksummed hexadecimal
///      characters. The checksum hashes the lowercase hexadecimal body only, using Keccak-256.
///      This codec proves syntax, not native account existence, control, or settlement eligibility.
library RecipientCodec {
    /// @notice Versioned profile whose implementation must also be activated on the destination.
    bytes32 internal constant SYNW_PROFILE_ID = keccak256("SYNW_HEX_EIP55_V1");

    /// @notice The recipient is not the exact canonical representation of a nonzero protected wallet.
    error InvalidSynergyRecipient();

    /// @notice Decodes a canonical protected-wallet recipient without accepting case aliases.
    /// @dev Unlike permissive Ethereum address parsers, uniform case has no checksum exemption.
    ///      Legacy Bech32m, proposed account classes, unresolved names, and Unicode are rejected.
    /// @param canonicalRecipient Exactly 44 ASCII bytes in the activated SYNW display profile.
    /// @return account Native 20-byte account identifier; this is not an Ethereum ownership assertion.
    function decode(
        string calldata canonicalRecipient
    ) internal pure returns (bytes20 account) {
        bytes calldata encoded = bytes(canonicalRecipient);
        if (encoded.length != 44) revert InvalidSynergyRecipient();
        if (
            encoded[0] != "s" ||
            encoded[1] != "y" ||
            encoded[2] != "n" ||
            encoded[3] != "w"
        ) revert InvalidSynergyRecipient();

        bytes memory lowercaseBody = new bytes(40);
        uint160 decoded;
        for (uint256 i; i < 40; ++i) {
            uint8 character = uint8(encoded[i + 4]);
            uint8 nibble;
            if (character >= 48 && character <= 57) {
                nibble = character - 48;
            } else if (character >= 65 && character <= 70) {
                nibble = character - 55;
                character += 32;
            } else if (character >= 97 && character <= 102) {
                nibble = character - 87;
            } else {
                revert InvalidSynergyRecipient();
            }
            lowercaseBody[i] = bytes1(character);
            decoded = (decoded << 4) | uint160(nibble);
        }
        if (decoded == 0) revert InvalidSynergyRecipient();

        bytes32 checksum = keccak256(lowercaseBody);
        for (uint256 i; i < 40; ++i) {
            uint8 character = uint8(lowercaseBody[i]);
            if (character >= 97) {
                uint8 hashByte = uint8(checksum[i / 2]);
                uint8 hashNibble = i % 2 == 0 ? hashByte >> 4 : hashByte & 15;
                if (hashNibble >= 8) character -= 32;
                if (encoded[i + 4] != bytes1(character))
                    revert InvalidSynergyRecipient();
            }
        }
        return bytes20(decoded);
    }

    /// @notice Hashes the typed raw identity used by V3 evidence leaves and attempt identifiers.
    /// @dev bytes20 is ABI right-padded. Replacing it with address changes the encoding and hash.
    /// @param account Nonzero raw account already accepted by decode.
    /// @return recipientHash Hash of the profile identifier and the exact 20-byte account.
    function identityHash(
        bytes20 account
    ) internal pure returns (bytes32 recipientHash) {
        return keccak256(abi.encode(SYNW_PROFILE_ID, account));
    }
}
