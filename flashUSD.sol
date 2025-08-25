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
   uint256 public constant EXPIRATION_PERIOD = 7 days;

    struct MintInfo {
        uint256 amount;
        uint256 timestamp;
    }

    mapping(address => MintInfo) public mintInfo;

    /**
     * @notice Deposit collateral and Mint new MUSD tokens to a specified address.
     * @dev Only callable whenNotPaused
     * @param to The address to receive the minted tokens.
     * @param collateralToken The collateral token to be deposited.
     * @param collateralAmount The amount of collateral token.
     */
    function mint(address to, address collateralToken, uint256 collateralAmount) external payable whenNotPaused {
        if (collateralToken == address(0)) {
        // Minting with ETH
        require(msg.value > 0, "CannotSendZeroETH()");
        uint256 mintAmount = (msg.value * 1e18) / COLLATERAL_RATIO;

        // Store ETH deposit
        collateralDeposits[msg.sender] += msg.value;
    } else {
        require(collateralAmount > 0, "InvalidMintAmount()");
        IERC20(collateralToken).transferFrom(msg.sender, address(this), collateralAmount);
        uint256 mintAmount = (collateralAmount * 1e18) / COLLATERAL_RATIO;
        // supply cap check
        if (totalSupply() + mintAmount > MAX_SUPPLY) {
            revert MaxSupplyExceeded();
        }
        // mint MUSD to user
        _mint(to, mintAmount);
        // store ERC20 deposit
        collateralDeposits[msg.sender] += collateralAmount;
        mintedTokens[msg.sender] += mintAmount;
        emit Mint(msg.sender, to, mintAmount);
      }
    }
    /**
     * @notice Withdraw collateral and burn MUSD tokens from a specified address.
     * @dev Only callable whenNotPaused
     * @param collateralToken The collateral token to withdraw.
     * @param burnAmount The amount of MUSD tokens to burn.
     */
    function burn(address collateralToken,
        uint256 burnAmount
    ) external whenNotPaused {
        require(burnAmount > 0, "InvalidBurnAmount()");
        require(mintedTokens[msg.sender] >= burnAmount, "NotEnoughMUSD");
        // Update MUSD storage
        mintedTokens[msg.sender] -= burnAmount;
        _burn(msg.sender, burnAmount);

        // calculate collateral token to send to user based on burnAmount
        uint256 collateralToReturn = (burnAmount * COLLATERAL_RATIO) / 1e18;
        require(collateralDeposits[msg.sender] >= collateralToReturn, "NotEnoughCollateral()");

        // Update collateral storage
        collateralDeposits[msg.sender] -= collateralToReturn;
        // Transfer collateral
        if (collateralToken == address(0)) {
        payable(msg.sender).transfer(collateralToReturn);
        } else {
        IERC20(collateralToken).transfer(msg.sender, collateralToReturn);
        }
        emit Burn(msg.sender, address(0), burnAmount);
    }
}