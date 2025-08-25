// SPDX-License-Identifier: MIT
// Compatible with OpenZeppelin Contracts ^5.4.0
pragma solidity ^0.8.27;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @custom:security-contact yahayasalisu162@gmail.com
contract FlashUSD is ERC20, Ownable {
    constructor(address initialOwner)
        ERC20("flashUSD", "fUSD")
        Ownable(initialOwner)
    {}
}