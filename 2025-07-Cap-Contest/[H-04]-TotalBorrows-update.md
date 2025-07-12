[H-04] Updating totalBorrows balance before transferFrom may allow users to be free from repaying their debts

_Severity:_ High 

_Source:_ https://github.com/sherlock-audit/2025-07-cap-Yahaya-Salisu/blob/main/cap-contracts%2Fcontracts%2Fvault%2Flibraries%2FVaultLogic.sol#L202-L210


### Summary:
The `repay()` function updates totalBorrows balance before ensuring if a use has actually approved enough allowance to pay the `amount` he intended to repay.

### Description:
The style of Check-Effects-Interaction varies between `borrow()` and `repay()` in borrow function totalBorrows has to update balance before sending assets to the borrower to prevent reentrancy from borrower, like this

```solidity
    function borrow(IVault.VaultStorage storage $, IVault.BorrowParams memory params)
        external
        whenNotPaused($, params.asset)
        updateIndex($, params.asset)
    {
        _verifyBalance($, params.asset, params.amount);

        $.totalBorrows[params.asset] += params.amount;
        IERC20(params.asset).safeTransfer(params.receiver, params.amount);

        emit Borrow(msg.sender, params.asset, params.amount);
    }
```
But in the `repay()` function, totalBorrows balance should never be updated before transferring assets from borrower to the protocol in any way.

The vulnerability is here in repay function where a totalBorrows balance is updated before performing `transferFrom()`
```solidity
function repay(IVault.VaultStorage storage $, IVault.RepayParams memory params)
        external
        updateIndex($, params.asset)
    {
 // BUG: ⚠️ totalBorrows reduced `amount` from borrower's debts without ensuring if a borrower has actually approved the `amount`
       $.totalBorrows[params.asset] -= params.amount;
    
 // After balance update, then the function attempts to call transferFrom() and this may revert if amount > allowance.
IERC20(params.asset).safeTransferFrom(msg.sender, address(this), params.amount);

        emit Repay(msg.sender, params.asset, params.amount);
    }
```

### Internal Pre-conditions
1. `Vault.repay()` is called from a user facing contract like `Lender.sol` that passes borrower controlled `params.amount`.

2. Borrower has a loan in `$.totalBorrows[params.asset];`.

3. The vault does not verify `IERC20.allowance(msg.sender, address(this))` before updating the balance.

4. And if `amount > allowance`, the `safeTransferFrom()` can revert due to insufficient allowance or insufficient balance.

### External Pre-conditions
1. Borrower/Attacker has an open loan from the vault with some nonzero totalBorrows

2. Borrower/Attacker sets `allowance < params.amount`, or has insufficient token balance

3. Borrower/Attacker calls `repay()` with `amount > allowance` or `amount > balance`.

### Attack Path
1. Borrower/Attacker borrowed 1,000 USDC from the vault.

2. Vault sets `totalBorrows[USDC] = 1000;`.

3. Borrower/Attacker calls `repay(USDC, 1000);` with only 1 USDC approved or no tokens at all.

4. Function immediately reduced `totalBorrows[USDC] -= 1000;`

5. After that, `safeTransferFrom()` reverts due to insufficient allowance or balance.

6. There's no rollback on balance update and totalBorrows is already reduced

7. Borrower/Attacker walks away with a cleared debt they never paid.

### Impact
If `transferFrom()` failed due to insufficient allowance or balance, the borrower's debts is already reduced, and this will cause the debt forgiveness where borrower can repaid the debts without actually sending assets.

Again, this will cause accounting mismatch because protocol’s internal debt record becomes inaccurate.

And this will be result in protocol loss because the vault may report less outstanding debt than what is actually owed.

And there's DoS vector If the borrower is Attacker, because Attacker may repeatedly attempt failed repayments to clear debts.

In short, this issue leads to permanent inconsistency in debt tracking and financial losses to the protocol.

### Proof of concept:

_No response_

### Recommendation 
```solidity
function repay(IVault.VaultStorage storage $, IVault.RepayParams memory params)
        external
        updateIndex($, params.asset)
    {
        
  // Transfer amount from borrower first
  IERC20(params.asset).safeTransferFrom(msg.sender, address(this), params.amount);

 // Then update totalBorrows balance if transferFrom successfully transferred the amount 
   $.totalBorrows[params.asset] -= params.amount;

    emit Repay(msg.sender, params.asset, params.amount);
    }
```