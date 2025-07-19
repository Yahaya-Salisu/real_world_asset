### [H-01] Over-Redeem in redeem() Function Allows Users to Drain Vault Funds

_Severity:_ High

_Source:_ https://github.com/sherlock-audit/2025-07-mellow-flexible-vaults-Yahaya-Salisu/blob/main/flexible-vaults%2Fsrc%2Fqueues%2FRedeemQueue.sol#L87-L125

### Summary
The `redeem()` function does not validate whether the caller owns enough shares before burning them. It immediately calls `shareManager_.burn(caller, shares);` without checking the user’s share balance.

And the `burn()` function is expected to handle this check internally since the `redeem()` fails to do, but it also forwards the call to `_burnShares()` which is an unimplemented virtual function in the provided code, this means that there's no safeguard that checks the caller's balance before burn. And his allows an attacker to redeem more shares than owned and potentially drain the funds.

```solidity
    /// @inheritdoc IRedeemQueue
    function redeem(uint256 shares) external nonReentrant {
        if (shares == 0) {
            revert ZeroValue();
        }
        address caller = _msgSender();

        address vault_ = vault();
        if (IShareModule(vault_).isPausedQueue(address(this))) {
            revert QueuePaused();
        }
        IShareManager shareManager_ = IShareManager(IShareModule(vault_).shareManager());

      // ⚠️ BUG: there's no check to verify if the caller owns enough shares before burning them
        shareManager_.burn(caller, shares);
        {
            IFeeManager feeManager = IShareModule(vault_).feeManager();
            uint256 fees = feeManager.calculateRedeemFee(shares);
            if (fees > 0) {
                shareManager_.mint(feeManager.feeRecipient(), fees);
                shares -= fees;
            }
        }
       ...
    }
```

The burn function also does not check if caller shares balance is enough.

```solidity
// ShareManager.sol

    /// @inheritdoc IShareManager
    function burn(address account, uint256 value) external onlyQueue {
        if (value == 0) {
            revert ZeroValue();
        }
        _burnShares(account, value);
        emit Burn(account, value);
    }
```

### Internal Preconditions
1. The `redeem()` and `burn()` do not perform balance check.

2. And the `_burnShares()` is left abstract, so there's no guarantee if it performs this validation.


### External Preconditions
1. Attacker owns a small amount of shares e.g 1 shares.

2. Attacker calls `redeem(10,000)` to redeem shares they do not own.


### Attacker Path
1. Attacker deposits a small amount of assets and receives 1 share for example.

2. Then calls `redeem(10_000)` or any large number of shares.

3. Vault proceeds with the redemption logic, calculate and deducts fees, and sent the request to the `redeem queue`, and once the request is completed, the attacker will claim the funds more than deserved.


### Impact
1. Potential total loss of funds in the pool if attacker redeems repeatedly.

2.Loss of trust in the system's integrity and accounting, and unauthorized extraction of vault assets.


### Recommendation:
Check that the caller owns enough shares before burning
```solidity
    /// @inheritdoc IRedeemQueue
    function redeem(uint256 shares) external nonReentrant {
        if (shares == 0) {
            revert ZeroValue();
        }
        address caller = _msgSender();

        address vault_ = vault();
        if (IShareModule(vault_).isPausedQueue(address(this))) {
            revert QueuePaused();
        }
        IShareManager shareManager_ = IShareManager(IShareModule(vault_).shareManager());

      // make sure user owns enough shares before burn
        if (shareManager_.balanceOf(caller) < shares) revert InsufficientBalance();
        shareManager_.burn(caller, shares);
        {
            IFeeManager feeManager = IShareModule(vault_).feeManager();
            uint256 fees = feeManager.calculateRedeemFee(shares);
            if (fees > 0) {
                shareManager_.mint(feeManager.feeRecipient(), fees);
                shares -= fees;
            }
        }
            ...
    }
```