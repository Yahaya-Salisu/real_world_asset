#### [H-01] repay() function allows arbitrary third-party to repay on behalf of agent without authorization

Yahaya Salisu

_Severity:_ High 

_Source:_ https://github.com/sherlock-audit/2025-07-cap-Yahaya-Salisu/blob/main/cap-contracts%2Fcontracts%2FlendingPool%2Flibraries%2FBorrowLogic.sol#L99-L127



#### Summary:
borrowParams in `borrow()` function addressed `agent` as a msg.sender.
```solidity
BorrowParams({
                agent: msg.sender, // agent is a msg.sender
                asset: _asset,
                amount: _amount,
                receiver: _receiver,
                maxBorrow: _amount == type(uint256).max
            })
```

But in `repay()` function the msg.sender is a `caller` not `agent`
```solidity
RepayParams({
            agent: _agent, // agent is not msg.sender
            asset: _asset, 
            amount: _amount,
            caller: msg.sender // caller is a msg.sender
            })
```

This means the caller (msg.sender) will always repay the debt of the `agent`, even if they are not the same person. The function incorrectly assumes that `caller` intends to repay on behalf of `agent`, without requiring any approval.



#### Description:
Since the caller is a msg.sender, the `repay()` function is supposed to realize Restaker Interest of the caller (msg.sender) and also fetch the balanceOf caller, wether the caller is an agent or not, but instead, it always realizes Restaker Interest of an agent and also fetch the balanceOf agent and get repaid  from caller (even though the caller is not the agent ).

The issue occurs in `repay()` where the function

1. Updates the interest of `params.agent`,

2. Fetches the debt balance of `params.agent`,

3. Transfers tokens from `params.caller`.

This allows an arbitrary third party (caller) to repay the debt of any agent, without restriction.

```solidity
// updates interest of agent
@audit-bug--> realizeRestakerInterest($, params.agent, params.asset); 

        ILender.ReserveData storage reserve = $.reservesData[params.asset];

// And this always fetches the balanceOf agent
@audit-bug--> uint256 agentDebt = IERC20(reserve.debtToken).balanceOf(params.agent); 

// Then transfers repaid amount from the caller (msg.sender)
IERC20(params.asset).safeTransferFrom(params.caller, address(this), repaid);
```

#### Impact:

Any third-party user can repay the debt of any agent, even without permission or relation.

This breaks user isolation and may cause griefing attacks where a malicious actor forcefully repays a user's debt.

Loss of funds from unsuspecting users or automation bots and potential for bribe style attacks where off chain agreements exploit the lack of authorization checks.

C. In multi protocol systems, such forced repayment may trigger unexpected cross protocol consequences like unlocking of collateral or loss of farming position.



#### Proof of concept:
A. Agent and caller have both borrowed from protocol

B. Later the caller (msg.sender) wants to repay his debt, but `repay()` updates agent's interest and fetches the balanceOf agent even though the caller is not the agent.

C. The balance of agent is cleared and the caller loses their funds.

```solidity
```


#### Output:


#### Recommendation:
The function should update the msg.sender's interest and fetch the balanceOf caller whether he is an agent or not.

```solidity
// Use caller for interest calculation and debt fetching to ensure only self-repayment is allowed
    function repay(ILender.LenderStorage storage $, ILender.RepayParams memory params)
        external
        returns (uint256 repaid)
    {
       
// Realize restaker interest of caller (not agent)
        realizeRestakerInterest($, params.caller, params.asset); 

        ILender.ReserveData storage reserve = $.reservesData[params.asset];

   
// Fetch the balance of caller (msg.sender) whether he's an agent or not.     
        uint256 agentDebt = IERC20(reserve.debtToken).balanceOf(params.caller); 
        repaid = Math.min(params.amount, agentDebt);

        uint256 remainingDebt = agentDebt - repaid;
        if (remainingDebt > 0 && remainingDebt < reserve.minBorrow) {
            // Limit repayment to maintain minimum debt if not full repayment
            repaid = agentDebt - reserve.minBorrow;
        }

    // Then transfer repaid from caller (msg.sender) IERC20(params.asset).safeTransferFrom(params.caller, address(this), repaid);

        uint256 remaining = repaid;
        uint256 interestRepaid;
        uint256 restakerRepaid;

        if (repaid > reserve.unrealizedInterest[params.agent] + reserve.debt) {
            interestRepaid = repaid - (reserve.debt + reserve.unrealizedInterest[params.agent]);
            remaining -= interestRepaid;
        }
```


#### Tools Used:
Manual code review
