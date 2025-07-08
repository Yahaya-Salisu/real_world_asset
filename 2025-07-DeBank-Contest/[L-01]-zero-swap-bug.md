| ID                                                                                                               | Title                                                                                                        |
| ---------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| [L-01](#l-01-Missing-zero-amount-protection-may-lead-to-gas-wastage-or-unexpected-executor-calls)                       |  Missing zero-amount protection may lead to gas wastage or unexpected executor calls.                               |
| [L-02](#l-02-Missing-zero-swap-check-may-lead-to-gas-wastage-or-unexpected-executor-calls)                              | Missing zero-swap check may lead to gas wastage or unexpected executor calls



### [L-01] Missing zero-amount protection may lead to gas wastage or unexpected executor calls

Yahaya Salisu.

_Severity:_ Low

_Target:_ https://github.com/sherlock-audit/2025-07-debank/blob/main/swap-router-v1%2Fsrc%2Frouter%2FRouter.sol#L56-L100

#### Summary:

The `swap()` function in `Router.sol` lacks a validation to prevent zero-amount swaps. If `fromTokenAmount == 0`, the function proceeds normally and calls the external `executeMegaSwap()` function on the executor contract.

This can result in unnecessary gas consumption and potential unexpected behavior within the executor, depending on its internal handling of zero-value swaps.

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

// no check for fromTokenAmount > 0
executor.executeMegaSwap{value: fromToken == UniversalERC20.ETH ? fromTokenAmount : 0}(
    IERC20(fromToken),
    IERC20(toToken),
    paths
); // could be called with 0 amount
```

Even though underflows are prevented in Solidity ^0.8.0, the function allows execution with `fromTokenAmount = 0`, which might affect gas estimation or third-party integrations relying on expected behavior.


### Impact:
a. Unnecessary gas costs for the user and contract.

b. May cause unexpected behavior depending on how 'executor.executeMegaSwap()' handles 0-amount input.


### Recommendation:
Add a check to prevent zero-amount swaps before proceeding with transfer and execution.
```solidity
require(fromTokenAmount > 0, "Router: zero amount");
```
Place the check before any fee logic or external calls (especially transferFrom or executeMegaSwap) to ensure safe and intentional execution.


### Tools Used:
Manual Code review.






### [L-02] Missing zero-swap check may lead to gas wastage or unexpected executor calls


_Severity:_ Low

#### Source: https://github.com/sherlock-audit/2025-07-debank/blob/main/swap-router-v1%2Fsrc%2FaggregatorRouter%2FDexSwap.sol#L174-L182

#### Summary:
Swap function in `aggregatorRouter/DexSwap.sol` calls `_validateSwapParams()` and this function does not check 0 amount swap.

#### Description:
The role of _validateSwapParams is to validate the authenticity of swap parameters such as,
A. feeReceiver != address(this)
B. maxFeeRate > feeRate
C. fromToken != toToken
D. universalETH or ERC tokens.
But the function does not check 0 amount, that means if a user calls swap of zero-amount, the swap will still proceed.
```solidity
// Swap function calls _validateSwapParams()
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
            (params.fromTokenAmount, feeAmount) = _chargeFee()


// _validateSwapParams() does not check 0 amount swap
    function _validateSwapParams(SwapParams memory params, Adapter storage adapter) internal view {
        if (params.feeReceiver == address(this)) revert RouterError.IncorrectFeeReceiver();
        if (params.feeRate > maxFeeRate) revert RouterError.FeeRateTooBig();
        if (params.fromToken == params.toToken) revert RouterError.TokenPairInvalid();
        if (!adapter.isRegistered) revert RouterError.AdapterDoesNotExist();
        if (msg.value != (params.fromToken == UniversalERC20.ETH ? params.fromTokenAmount : 0)) {
            revert RouterError.IncorrectMsgValue();
        }
    }
```
Similar to `M-01 (found in router/Router.sol)`, this issue occurs in `AggregatorRouter/DexSwap.sol`, using a separate execution path...


### Impact:
A. Unnecessary gas costs for the user and contract.

B. May cause unexpected behavior depending on how 'spender.swap()' handles 0-amount input.


### Recommendation:
```solidity
if (
    (params.fromToken == UniversalERC20.ETH && msg.value != params.fromTokenAmount) ||
    (params.fromToken != UniversalERC20.ETH && msg.value != 0)
) {
    revert RouterError.IncorrectMsgValue();
}
```
#### Tools Used:
Manual Code review.
