// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract GoldVault is ERC4626, Ownable {
    ICustodian public custodian;
    IOracle public oracle;
    bytes32 public assetId;

    constructor(
        IERC20 asset_,
        ICustodian custodian_,
        IOracle oracle_,
        bytes32 assetId_
    )
        ERC20("Gold Vault Share", "gSHARE")
        ERC4626(asset_)
    {
        custodian = custodian_;
        oracle = oracle_;
        assetId = assetId_;
    }

    function totalAssets() public view override returns (uint256) {
        if (!custodian.isAssetBacked(assetId)) return 0;
        return oracle.getLatestAssetValue(assetId);
    }

    function _deposit(
        address caller,
        address receiver,
        uint256 assets,
        uint256 shares
    ) internal override {
        require(custodian.isAssetBacked(assetId), "Not backed");
        super._deposit(caller, receiver, assets, shares);
    }
}