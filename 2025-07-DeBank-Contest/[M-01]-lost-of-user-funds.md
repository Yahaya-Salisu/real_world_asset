### [M-01] Fee is charged even if swap failed, leading to permanent tokens loss 

_Severity:_ Medium

### Source: https://github.com/sherlock-audit/2025-07-debank/blob/main/swap-router-v1%2Fsrc%2Frouter%2FRouter.sol#L71-L74



### Summary: 
Calling `chargeFee()` before ensuring that if `fromTokenAmount` will be successfully transfered to the executor, can lead to permanent loss of user feeAmount if `transferFrom()` failed after fee deduction.

```solidity
    function swap(
        address fromToken,
        uint256 fromTokenAmount,
        address toToken,
        uint256 minAmountOut,
        bool feeOnFromToken,
        uint256 feeRate,
        address feeReceiver,
        Utils.MultiPath[] calldata paths
    ) external payable whenNotPaused nonReentrant {

         ... existing code ...

        // chargeFee() deducts feeAmount before ensuring if the fromTokenAmount will be successfully transferred to the executor contract.
        if (feeOnFromToken) {
            (fromTokenAmount, feeAmount) = chargeFee(fromToken, feeOnFromToken, fromTokenAmount, feeRate, feeReceiver);
        }
        // deposit to executor
        if (fromToken != UniversalERC20.ETH) {

// This transferFrom may failed, and user will permanently lose his funds (feeAmount).   IERC20(fromToken).safeTransferFrom(msg.sender, address(executor), fromTokenAmount);
        }
```



### Description:
When performing a token swap, the user is required to approve `fromTokenAmount` to the contract. However, the `swap()` function charges the fee by calling `chargeFee()` before ensuring that the `fromTokenAmount` will be successfully transferred to the executor.

This can lead to a situation where the fee is deducted, but the main `transferFrom()` reverts, leaving the user with reduced balance and no refund mechanism.

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
A. Only call `chargeFee()` after ensuring all following steps will succeed.

B. Collect fromTokenAmount first, then distribute feeAmount and swapAmount internally.

C. Provide fee refund mechanism that can refund the feeAmount to user whenever the swap failed.



### Tools Used:
Manual Code review.