### [M-02] Premature fee deduction in DexSwap.sol may lead to unrecoverable token loss if swap fails

_Severity:_ Medium

#### Source:https://github.com/sherlock-audit/2025-07-debank/blob/main/swap-router-v1%2Fsrc%2FaggregatorRouter%2FDexSwap.sol#L116-L139


### Summary: 
Similar to `M-01 (found in router/Router.sol)`, this issue occurs in `AggregatorRouter/DexSwap.sol`, using a separate execution path...

The `_swap()` function in `DexSwap.sol` deducts feeAmount using `_chargeFee()` before attempting to transfer `fromTokenAmount` to the swap executor, and If this transfer fails (e.g. insufficient allowance), the entire swap will revert but fee is already deducted, leading to unrecoverable user loss.

```solidity
        function swap(SwapParams memory params) external payable whenNotPaused nonReentrant {
        _swap(params);
    }

    function _swap(SwapParams memory params) internal {
        Adapter storage adapter = adapters[params.aggregatorId];

        // 1. check params
        _validateSwapParams(params, adapter);

        uint256 feeAmount;
        uint256 receivedAmount;

        // 2. charge fee on fromToken if needed
        if (params.feeOnFromToken) {
            (params.fromTokenAmount, feeAmount) = _chargeFee(
                params.fromToken, params.feeOnFromToken, params.fromTokenAmount, params.feeRate, params.feeReceiver
            );
        }

        // 3. transfer fromToken
        if (params.fromToken != UniversalERC20.ETH) {
            IERC20(params.fromToken).safeTransferFrom(msg.sender, address(spender), params.fromTokenAmount);
        }
```

Fee is charged, and feeReceiver balance is already updated, also there's no fee refund mechanism.
```solidity
    function _chargeFee(address token, bool feeOnFromToken, uint256 amount, uint256 feeRate, address feeReceiver)
        internal
        returns (uint256, uint256)
    {
        uint256 feeAmount = amount.decimalMul(feeRate);
        if (feeRate > 0) {
            if (feeOnFromToken) {
                IERC20(token).universalTransferFrom(msg.sender, payable(feeReceiver), feeAmount);
            } else {
                IERC20(token).universalTransfer(payable(feeReceiver), feeAmount);
            }
        }
        return (amount -= feeAmount, feeAmount);
    }
```

Though the logic looks very similar in the `router/Router.sol`, but this issue is distinct from M-01 as it resides in `DexSwap.sol`, affecting a different execution path `(spender.swap)` through separate contract architecture.


### Description:
The `swap()` function calls `_chargeFee()` first before performing token swap, and if swap fails e.g the second transferFrom may fail due to insufficient allowance, and this can lead to a situation where the fee is deducted, but the main `transferFrom()` reverts, leaving the user with reduced balance and no refund mechanism.


### Example:
A. User approves $1000 to the contract.

B. feeRate = 5%, feeOnFromToken = true (feeAmount = $50).

C. The swap function first deducts $50 as a fee using chargeFee().

D. Remaining balance becomes $950.

E. Then it attempts to transfer $1000 to the executor using `transferFrom()`, and this will fail due to insufficient allowance.

F. The entire swap reverts but the fee was already deducted and sent to the feeReceiver.

G. User ends up losing $50 with no refund.



### Impact:
User can lose funds (fee) since there's no fee refund mechanism if swap did not proceed



### Proof of concept:
A. Approve feeAmount only.

B. Call swap.

C. Observe feeReceiver gets tokens.

D. Swap reverts before actual execution and user lost feeAmount.



### Recommendation: 
A. Avoid calling `_chargeFee()` until token transfer and swap parameters are validated.

B. Consider collecting total `fromTokenAmount`, then internally split into fee + swap amount to avoid double `transferFrom()` risk.

C. If fee must be collected early, introduce a try-catch or revert-proof refund path for `feeAmount` on failure.



### Tools Used:
Manual Code review.