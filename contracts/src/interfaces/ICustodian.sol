// SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

interface ICustodian {
    function isAssetBacked(bytes32 assetId) external view returns (bool);
}