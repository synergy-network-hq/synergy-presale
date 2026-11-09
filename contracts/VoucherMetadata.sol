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
//      ▄▄ ▗▄▖        █          ▗▖ ▗▖              ▗▖               ▗▄ ▄▖                ▗▖              
//     █▀▀▌▝▜▌        ▀          ▝█ █▘              ▐▌               ▐█ █▌     ▐▌         ▐▌      ▐▌      
//    ▐▛    ▐▌  ▟██▖ ██  ▐█▙█▖    █ █ ▟█▙ ▐▌ ▐▌ ▟██▖▐▙██▖ ▟█▙ █▟█▌   ▐███▌ ▟█▙▐███ ▟██▖ ▟█▟▌ ▟██▖▐███ ▟██▖
//    ▐▌    ▐▌  ▘▄▟▌  █  ▐▌█▐▌    █ █▐▛ ▜▌▐▌ ▐▌▐▛  ▘▐▛ ▐▌▐▙▄▟▌█▘     ▐▌█▐▌▐▙▄▟▌▐▌  ▘▄▟▌▐▛ ▜▌ ▘▄▟▌ ▐▌  ▘▄▟▌
//    ▐▙    ▐▌ ▗█▀▜▌  █  ▐▌█▐▌    ▐█▌▐▌ ▐▌▐▌ ▐▌▐▌   ▐▌ ▐▌▐▛▀▀▘█      ▐▌▀▐▌▐▛▀▀▘▐▌ ▗█▀▜▌▐▌ ▐▌▗█▀▜▌ ▐▌ ▗█▀▜▌
//     █▄▄▌ ▐▙▄▐▙▄█▌▗▄█▄▖▐▌█▐▌    ▐█▌▝█▄█▘▐▙▄█▌▝█▄▄▌▐▌ ▐▌▝█▄▄▌█      ▐▌ ▐▌▝█▄▄▌▐▙▄▐▙▄█▌▝█▄█▌▐▙▄█▌ ▐▙▄▐▙▄█▌
//      ▀▀   ▀▀ ▀▀▝▘▝▀▀▀▘▝▘▀▝▘    ▝▀▘ ▝▀▘  ▀▀▝▘ ▝▀▀ ▝▘ ▝▘ ▝▀▀ ▀      ▝▘ ▝▘ ▝▀▀  ▀▀ ▀▀▝▘ ▝▀▝▘ ▀▀▝▘  ▀▀ ▀▀▝▘
//                                                                                                        
//                                                                                                        

import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

/// @notice Deterministic metadata with embedded artwork; no mutable hosting dependency.
contract VoucherMetadata {
    using Strings for uint256;

    function uri(bool reward, uint64 ledgerId, bytes32 purchaseId, uint96 base, uint96 bonus, uint96 total)
        external pure returns (string memory)
    {
        string memory kind = reward ? "Referral Reward" : "Purchase";
        string memory svg = string.concat(
            '<svg xmlns="http://www.w3.org/2000/svg" width="800" height="800" viewBox="0 0 800 800">',
            '<rect width="800" height="800" fill="#101828"/><circle cx="400" cy="310" r="180" fill="none" stroke="#53e0bb" stroke-width="12"/>',
            '<text x="400" y="330" text-anchor="middle" fill="white" font-family="sans-serif" font-size="68">SNRG</text>',
            '<text x="400" y="590" text-anchor="middle" fill="#53e0bb" font-family="sans-serif" font-size="34">',kind,
            '</text><text x="400" y="650" text-anchor="middle" fill="white" font-family="sans-serif" font-size="24">Soulbound claim voucher</text></svg>'
        );
        bytes memory json = abi.encodePacked(
            '{"name":"Synergy SNRG ',kind,' Voucher #',uint256(ledgerId).toString(),
            '","description":"', reward
                ? 'Earned referral entitlement. Payment fields attribute the qualifying purchase; no new payment or revenue. '
                : 'Purchased SNRG and any qualifying buyer referral bonus. ',
            'Immutable voucher allocation is authoritative. SNRG uses 9 decimals. Native settlement is subject to the recorded vesting terms.",',
            '"image":"data:image/svg+xml;base64,',Base64.encode(bytes(svg)),
            '","attributes":[{"trait_type":"Kind","value":"',kind,
            '"},{"trait_type":"Qualifying purchase ID","value":"',Strings.toHexString(uint256(purchaseId),32),
            '"},{"trait_type":"Base purchased nwei","value":"',uint256(base).toString(),
            '"},{"trait_type":"Bonus nwei","value":"',uint256(bonus).toString(),
            '"},{"trait_type":"Total entitlement nwei","value":"',uint256(total).toString(),'"}]}'
        );
        return string.concat('data:application/json;base64,',Base64.encode(json));
    }
}
