### [M-01] Fee is charged even if swap failed, leading to permanent tokens loss 

_Severity:_ Medium
#### Source: https://github.com/sherlock-audit/2025-07-debank/blob/main/swap-router-v1%2Fsrc%2Frouter%2FRouter.sol#L71-L74

#### Summary: 
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

        // chargeFee() deducts feeAmount before ensuring if the swap will succeed.
        if (feeOnFromToken) {
            (fromTokenAmount, feeAmount) = chargeFee(fromToken, feeOnFromToken, fromTokenAmount, feeRate, feeReceiver);
        }
        // deposit to executor
        if (fromToken != UniversalERC20.ETH) {
// If this transferFrom failed, the user will lose his funds (feeAmount) permanently.   IERC20(fromToken).safeTransferFrom(msg.sender, address(executor), fromTokenAmount);
        }
```
#### Description:
When swapping, user has to approve allowance to the executor contract, and the swap function calls chargeFee() first, before ensuring if the fromTokenAmount will be successfully transferred to the executor contract.

Is this case, user may lose feeAmount permanently.

For example:
A. user approved $1000 allowance to the executor contract.
B. FeeRate = 5% ($50) and  feeOnFromToken = true.
C. The swap calls chargeFee() first and deducted $50 (5%), remaining $950.
D. Then swap calls second transferFrom, fromTokenAmount = $1000.
E. The transferFrom will revert since there's no enough allowance, while the fee is already diducted and the feeReceiver balance is updated, current user balance = $950 instead of $1000, user lost his fee.

#### Impact:
User can lose funds (fee) since there's no fee refund mechanism if swap did not proceed

#### Proof of concept:
a. Approve feeAmount only
b. Call swap
c. Observe feeReceiver gets tokens
d. Swap reverts before actual execution and user lost feeAmount.

#### Recommendation: 
a. Only call `chargeFee()` after ensuring all following steps will succeed.
b. Collect fromTokenAmount first, then distribute feeAmount and swapAmount internally.
c. Provide fee refund mechanism that can refund the feeAmount to user whenever the swap failed.

#### Tools Used:
Manual Code review.