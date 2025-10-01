// SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

interface IOracle {
    function getLatestAssetValue(bytes32 assetId) external view returns (uint256);
}