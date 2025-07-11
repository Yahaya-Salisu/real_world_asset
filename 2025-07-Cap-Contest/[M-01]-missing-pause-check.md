### [M-02] Missing pause checking in addAsset() allows asset operations during paused state

Yahaya Salisu

_Severity:_ Medium

_Source:_ https://github.com/sherlock-audit/2025-07-cap-Yahaya-Salisu/blob/main/cap-contracts%2Fcontracts%2FlendingPool%2Flibraries%2FValidationLogic.sol#L98-L106



#### Summary:
The protocol introduces a `pauseAsset()` mechanism intended to stop interaction of specific asset during emergency time. `borrow()` function checks paused via `ValidationLogic.validateBorrow()`, but critical function like `addAsset()` does not perform any pause checking, making it possible to call it even when the asset is paused.



#### Description:
Call to `ValidationLogic.validateBorrow()` In `borrow()` function checks pause status properly.
```solidity
    function validateBorrow(ILender.LenderStorage storage $, ILender.BorrowParams memory params) external view {
        if (params.amount < $.reservesData[params.asset].minBorrow) revert MinBorrowAmount();
        if (params.receiver == address(0) || params.asset == address(0)) revert ZeroAddressNotValid();

// Pause check
        if ($.reservesData[params.asset].paused) revert ReservePaused();

        ... Existing code ...
        }
    }
```


Also `addAsset()` function calls `validationLogic.validateAddAsset()` but this validation does not check pause status
```solidity
// There's no pause check in validateAddAsset at all
    function validateAddAsset(ILender.LenderStorage storage $, ILender.AddAssetParams memory params) external view {
        if (params.asset == address(0) || params.vault == address(0)) revert ZeroAddressNotValid();
        if (params.interestReceiver == address(0)) revert InterestReceiverNotSet();
        if (params.debtToken == address(0)) revert DebtTokenNotSet();
        if ($.reservesData[params.asset].vault != address(0)) revert ReserveAlreadyInitialized();
    }
```



#### Impact:
If the admin pauses an asset using `pauseAsset(asset, true)`, users should not be able to interact with that asset except withdraw or maybe repay in certain emergency situations.

But since there's no pause check, that means any user can still `addAsset` in a paused asset, and this undermines the protocol’s pause mechanism, which may be relied on during critical incidents or exploits.



#### Proof of Concept:
A. Admin pauses USDC asset, `lender.pauseAsset(address(usdc), true);`


B. Attacker calls, `lender.addAsset(usdc, 1000e6);`

In this case, no revert will occur, meaning that the asset was interacted even though, the asset is paused.


#### Recommendation:
Make sure `validateAddAsset()` check pause status or apply modifier design like `onlyWhenNotPaused(asset)` to maintain consistency.

```solidity
    function validateAddAsset(ILender.LenderStorage storage $, ILender.AddAssetParams memory params) external view {
        if (params.asset == address(0) || params.vault == address(0)) revert ZeroAddressNotValid();
        if (params.interestReceiver == address(0)) revert InterestReceiverNotSet();
        if (params.debtToken == address(0)) revert DebtTokenNotSet();

// Check pause status 
        if ($.reservesData[params.asset].paused) revert ReservePaused();
        if ($.reservesData[params.asset].vault != address(0)) revert ReserveAlreadyInitialized();
    }
```


#### Tools Used:
Manual Code Review