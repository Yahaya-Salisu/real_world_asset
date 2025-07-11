### [H-03] removeAsset() function leads to permanent loss of funds and interest for depositors

Yahaya Salisu 

_Severity:_ High

_Source:_ reserveLogic.sol#84-91 and validationLogic.sol#


#### Summary:
The `removeAsset()` function deletes a lending reserve without returning deposits or accrued interest to users. This will always cause a permanent loss of funds and breaks the accounting structure of the protocol. Users can not withdraw or earn interest from the protocol, and their history of accounting (debt, unrealized interest, vault data) is silently deleted.



#### Description:
In the  `Lender.sol` a user that wants to withdraw funds calls `removeAsset()`, and this function verifies the asset to withdraw first, then makes an external call to `ReserveLogic.sol` to perform major actions.
 ```solidity
// lender.sol
   /// @inheritdoc ILender
    function removeAsset(address _asset) external checkAccess(this.removeAsset.selector) {
        if (_asset == address(0)) revert ZeroAddressNotValid();
        ReserveLogic.removeAsset(getLenderStorage(), _asset);
    }
```
And the second `removeAsset()` function in the `ReserveLogic.sol` makes another external calls to `ValidationLogic.sol` after result is returned from `ValidationLogic`, the function will permanently delete all withdrawal data without sending assets to the user or refund it to the protocol.
```
    /// @notice Remove asset from lending when there is no borrows
    /// @param $ Lender storage
    /// @param _asset Asset address
    function removeAsset(ILender.LenderStorage storage $, address _asset) external {
// External call 
        ValidationLogic.validateRemoveAsset($, _asset);

        $.reservesList[$.reservesData[_asset].id] = address(0);
// Permanently deleting reserve data without sending assets to the user
        delete $.reservesData[_asset];

        emit ReserveAssetRemoved(_asset);
    }
```
The last `removeAsset()` function from the `ValidationLogic.sol` is only checking if a user has unpaid debts, the function does not accrue interests, and it does not check if a user has sufficient balance to withdraw even if he has active debts.
```solidity
// validationLogic.sol

    /// @notice Validate dropping an asset as a reserve
    /// @dev All principal borrows must be repaid, interest is ignored
    /// @param $ Lender storage
    /// @param _asset Asset to remove
    function validateRemoveAsset(ILender.LenderStorage storage $, address _asset) external view {
// This will revert if a user has active debts 
        if (IERC20($.reservesData[_asset].debtToken).totalSupply() != 0) revert VariableDebtSupplyNotZero(); 
    }
```
The worse part of the issue is, wether the user has sufficient balance to remove or he doesn't have, it will always revert as long as he has an active debts, and if the function revert/returned the result to second `removeAsset()` in the `ReserveLogic.sol` This second function will permanently delete all withdrawal funds and data and even the active debts that user is holding, both users and protocol will lose their funds.



#### Impact:
Users who deposited to the protocol will lose all their funds during withdrawals in the `removeAsset()`, and all interest earned is deleted without accrued.

Also, no withdrawal path remains after `removeAsset()`, and a malicious or careless admin can rug-pull the entire reserve, and no validation is done on supplier balance before deletion.



#### Recommendation: