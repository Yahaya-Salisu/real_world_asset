#### [H-01] repay() function allows arbitrary third-party to repay on behalf of agent without authorization

Yahaya Salisu.

_Severity:_ High 

_Source:_ https://github.com/sherlock-audit/2025-07-cap-Yahaya-Salisu/blob/main/cap-contracts%2Fcontracts%2FlendingPool%2Flibraries%2FBorrowLogic.sol#L99-L127



#### Summary:
The caller will always repay the debt of agent even if he's not the agent because `repay() function` realizeRestakerInterest of an agent and it fetches the balanceOf agent everytime, meaning that even if the caller of the `repay()` function is not the agent, the agent's debt will unintentionally be paid by someone.



#### Description:
`repay()` function is supposed to realizeRestakerInterest of caller and also fetch the balanceOf caller, wether the caller is an agent or a user, but instead, it always realizeRestakerInterest of agent and also fetch the balanceOf agent and get repaid  from caller (even if the caller is not the agent).

```solidity
    function repay(ILender.LenderStorage storage $, ILender.RepayParams memory params)
        external
        returns (uint256 repaid)
    {
        /// Realize restaker interest before repaying
@audit-bug--> realizeRestakerInterest($, params.agent, params.asset); // This updates the interest of agent 

        ILender.ReserveData storage reserve = $.reservesData[params.asset];

        /// Can only repay up to the amount owed
@audit-bug--> uint256 agentDebt = IERC20(reserve.debtToken).balanceOf(params.agent); // And this always fetches the balanceOf agent
        repaid = Math.min(params.amount, agentDebt);

        uint256 remainingDebt = agentDebt - repaid;
        if (remainingDebt > 0 && remainingDebt < reserve.minBorrow) {
            // Limit repayment to maintain minimum debt if not full repayment
            repaid = agentDebt - reserve.minBorrow;
        }

        @audit-bug--> IERC20(params.asset).safeTransferFrom(params.caller, address(this), repaid); // but this transfers repaid amount from any caller (not only agent)

        uint256 remaining = repaid;
        uint256 interestRepaid;
        uint256 restakerRepaid;

        if (repaid > reserve.unrealizedInterest[params.agent] + reserve.debt) {
            interestRepaid = repaid - (reserve.debt + reserve.unrealizedInterest[params.agent]);
            remaining -= interestRepaid;
        }
```

The issue is occurred here in this logic where `repay()` updates interest of an agent and always fetches the balanceOf agent even if the caller of the `repay()` is not the agent.

```solidity
/// Realize restaker interest before repaying
@audit-bug--> realizeRestakerInterest($, params.agent, params.asset); // This updates the interest of agent 

        ILender.ReserveData storage reserve = $.reservesData[params.asset];

        /// Can only repay up to the amount owed
@audit-bug--> uint256 agentDebt = IERC20(reserve.debtToken).balanceOf(params.agent); // And this always fetches the balanceOf agent
```
Even if the caller of `repay()` is not the agent, the function will clear the agent's debt because the parameters between `balanceOf()` and `transferFrom()` are totally not the same.

```solidity
IERC20(params.asset).safeTransferFrom(params.caller, address(this), repaid); // This transfers repaid amount from the caller, but it repays the balance of agent.
```
This clearly shows that the agent's debt can be paid by anyone because, anyone can be a caller but not anyone is an agent.


#### Proof of concept:
A. Agent has borrowed 1000 tokens and caller borrowed 2000 tokens
B. Later the caller wants to repay his debt, but `repay()` updates agent's interest and fetches the balanceOf agent even though the caller is not the agent.
C. The balance of agent cleared while the caller loses their funds.



#### Impact:




#### Output:


#### Recommendation:
The function should fetch the balanceOf caller whether he is an agent or a caller. Not always balanceOf agent.

```
    function repay(ILender.LenderStorage storage $, ILender.RepayParams memory params)
        external
        returns (uint256 repaid)
    {
        /// Realize restaker interest before repaying
        realizeRestakerInterest($, params.caller, params.asset); // Realize interest restaker interest of caller

        ILender.ReserveData storage reserve = $.reservesData[params.asset];

        /// Can only repay up to the amount owed
        uint256 agentDebt = IERC20(reserve.debtToken).balanceOf(params.caller); // Fetch the balance of caller whether he's an agent or not.
        repaid = Math.min(params.amount, agentDebt);

        uint256 remainingDebt = agentDebt - repaid;
        if (remainingDebt > 0 && remainingDebt < reserve.minBorrow) {
            // Limit repayment to maintain minimum debt if not full repayment
            repaid = agentDebt - reserve.minBorrow;
        }

        IERC20(params.asset).safeTransferFrom(params.caller, address(this), repaid); // Then repay the balance of caller.

        uint256 remaining = repaid;
        uint256 interestRepaid;
        uint256 restakerRepaid;

        if (repaid > reserve.unrealizedInterest[params.agent] + reserve.debt) {
            interestRepaid = repaid - (reserve.debt + reserve.unrealizedInterest[params.agent]);
            remaining -= interestRepaid;
        }
```
