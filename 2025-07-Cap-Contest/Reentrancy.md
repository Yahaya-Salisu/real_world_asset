### [H-02] Reentrancy vulnerability in repay() due to external calls after state changes

Yahaya Salisu

_Severity:_ High

_Source:_ https://github.com/sherlock-audit/2025-07-cap-Yahaya-Salisu/blob/main/cap-contracts%2Fcontracts%2FlendingPool%2Flibraries%2FBorrowLogic.sol#L118-L151



#### Summary:
The repay() function makes multiple external calls after updating internal state like reducing `reserve.debt` and `reserve.unrealizedInterest`, because of that if any of these external contracts especially `$.delegation` or `reserve.vault` is malicious or untrusted, they can reenter back to the protocol and perform unauthorized actions.



#### Description:
The `repay()` function includes the following unsafe pattern:

```solidity
// State changes 
reserve.unrealizedInterest[params.agent] -= restakerRepaid;
reserve.totalUnrealizedInterest -= restakerRepaid;

// External call to untrusted contract (possible attacker)
IERC20(params.asset).safeTransfer($.delegation, restakerRepaid);
IDelegation($.delegation).distributeRewards(params.agent, params.asset);
```

The same issue occurs here

```solidity
// Balance update 
reserve.debt -= vaultRepaid;
IERC20(params.asset).forceApprove(reserve.vault, vaultRepaid);

// External call
IVault(reserve.vault).repay(params.asset, vaultRepaid);
```

These external calls after state updates violate the Checks-Effects-Interactions pattern, opening the door to reentrancy if any of these contracts are compromised, upgraded (UUPS), or have token callbacks, and even if the project trusts the current implementations, contracts like IDelegation or IVault can be upgradeable, and future implementations may introduce malicious reentrant logic.



#### Impact:
An attacker can reenter the protocol after balances have been updated, before the flow completes, and allows unauthorized calls like reentering to repay(), and this may cause manipulation of internal accounting or improper debt forgiving or draining assets indirectly through repeated calls.



#### Proof of Concept:



#### Output:



#### Recommendation:
A. Apply the Checks-Effects-Interactions pattern strictly and re-arrange the state updates to occur after all external calls or consider using reentrancy guard modifier.

##### For example:
```solidity
uint256 vaultRepaid = Math.min(remaining, reserve.debt);
if (vaultRepaid > 0) {
   
// External calls first IERC20(params.asset).forceApprove(reserve.vault, vaultRepaid);
    IVault(reserve.vault).repay(params.asset, vaultRepaid);
    
    // Then update the states after 
    reserve.debt -= vaultRepaid;
}
```



#### Tools Used:
Manual code review.