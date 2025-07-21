### [M-01] Updating withdrawalInfo balance before transferring user shares to the vault, allows false withdrawals in _processWithdraw() function

_Severity:_ Medium

_Target:_ https://github.com/OpenEdenHQ/openeden.vault.audit/blob/main/contracts%2FOpenEdenVaultV4Impl.sol#L837-L859


### Summary:
The `_processWithdraw()` function updates the `withdrawalInfo` before actually transferring the corresponding shares from the user. This allows users to request withdrawals for amounts greater than their actual balance, causing `withdrawalQueue` to register the request even if the share transfer fails or is reverted.


### Description:
When a user initiates a withdrawal via `withdrawIns()`, the `_processWithdrawIns()`, function transfers the corresponding shares first, from user and then proceed the assets redemption.
```solidity
    function _processWithdrawIns(
        address _sender,
        address _receiver,
        uint256 _shares,
        uint256 _assets, // USDC
        uint256 _totalFee
    ) internal returns (uint256) {

        // transfer shares from sender to vault first!
        _transfer(_sender, address(this), _shares);

        // there may have some rounding error, so add 1e6 to avoid it
        uint256 usdcReceived = redemptionContract.redeem(_assets + 1e6);
```

But the `_processWithdraw()` function first updates the `withdrawalInfo` mapping and pushes data to the `withdrawalQueue`, and then attempts to transfer shares from the user.

```solidity
    function _processWithdraw(
        address _sender,
        address _receiver,
        uint256 _shares
    ) internal {

// ⚠️ BUG: this function updates balance first
        withdrawalInfo[_receiver] += _shares;

        bytes32 id = keccak256(
            abi.encode(
                _sender,
                _receiver,
                _shares,
                block.timestamp,
                withdrawalQueue.length()
            )
        );

        bytes memory data = abi.encode(_sender, _receiver, _shares, id);
        withdrawalQueue.pushBack(data);

// Then transfer shares from user after
        _transfer(_sender, address(this), _shares);
        emit AddToWithdrawalQueue(_sender, _receiver, _shares, id);
    }
```

This flow is risky because it does not validate that the user actually owns the specified `_shares` before updating internal accounting, and If the share transfer fails or reverts, the `withdrawalInfo` and `queue` remain updated, causing an inconsistency between state and actual share balance.


### Impact:
If a user has 100 shares for example, and calls withdraw of 1000 shares, the `withdrawalInfo[]` will add this 1000 shares to the balance without knowing that a user has only 100 shares, this could lead to a double accounting of assets.

Any later logic that uses `withdrawalInfo` to determine actual withdrawable assets could allow over-withdrawal, leading to vault insolvency or double accounting bugs.

And this may not result in immediate asset theft, but it breaks accounting assumptions and could be exploited indirectly if `withdrawalInfo` is used for settlements.


### PoC:
I don't have an access/experience of ts-based test environment.


### Recommendation:
Update the order of operations in `_processWithdraw()` to validate the transfer before mutating internal state.

```solidity
    function _processWithdraw(
        address _sender,
        address _receiver,
        uint256 _shares
    ) internal {

// transfer shares from user first, before balance update
        _transfer(_sender, address(this), _shares);
        bytes32 id = keccak256(
            abi.encode(
                _sender,
                _receiver,
                _shares,
                block.timestamp,
                withdrawalQueue.length()
            )
        );

        bytes memory data = abi.encode(_sender, _receiver, _shares, id);
        withdrawalQueue.pushBack(data);

// Then update withdrawalInfo[] after 
        withdrawalInfo[_receiver] += _shares;
        emit AddToWithdrawalQueue(_sender, _receiver, _shares, id);
    }
```





### [M-02] totalFee is charged before totalSupplyCap validation in _processDeposit() function, leading to loss of totalFee for depositors if the totalSupply + shares > totalSupplyCap.

_Severity_ Medium 

_Target_ https://github.com/OpenEdenHQ/openeden.vault.audit/blob/main/contracts%2FOpenEdenVaultV4Impl.sol#L797-L815

### Summary
The _processDeposit() function sends totalFee to the treasury before confirming whether the deposit will exceed totalSupplyCap. If the cap is exceeded, the transaction reverts but the fee remains with the treasury, resulting in an irreversible loss for the user. This issue can be triggered by any user near the cap, and could result in griefing or unintentional fund loss.


### Description
Since the _processDeposit() function transfers totalFee from the sender to oplTreasury before any validation, that means if totalSupply + corresponding shares of deposit > totalSupplyCap, the transaction will revert, but the oplTreasury has already received the totalFee and the Fee is irreversible even if the deposit revert due totalSupplyCap limit or any error that can make the deposit reverted after totalFee deduction.
```solidty
    /**
     * @notice Handles the deposit logic, converting assets into shares, managing fees, and updating relevant state.
     * @param _sender The sender of the assets.
     * @param _receiver The receiver of the shares.
     * @param _assets Amount of assets being deposited.
     */
    function _processDeposit(
        address _sender,
        address _receiver,
        uint256 _assets
    ) internal {
        (uint256 oeFee, int256 pFee, uint256 totalFee) = txsFee(
            ActionType.DEPOSIT,
            _sender,
            _assets
        );

        // collect the fee
        if (totalFee > 0) {

     // ⚠️ BUG: totalFee is sent to oplTreasury before totalSupplyCap validation 
SafeERC20Upgradeable.safeTransferFrom(
                IERC20Upgradeable(underlying),
                _sender,
                oplTreasury,
                totalFee
            );
        }

        uint256 trimmedAssets = _assets - totalFee;
        uint256 shares = _convertToShares(trimmedAssets);
     
    // this totalSupplyCap validation should be done before totalFee deduction 
        if (totalSupply() + shares > totalSupplyCap)
            revert TotalSupplyCapExceeded(
                totalSupply(),
                shares,
                totalSupplyCap
            );

        _deposit(_sender, _receiver, trimmedAssets, shares, treasury);
        emit ProcessDeposit(
        );
    }
```

### Impact
This could lead to loss of depositors totalFee whenever the deposit() revert due to totalSupplyCap limit or any reason, the totalFee will not return to user, and this could be griefed, because malicious users repeatedly try to deposit above cap to trigger user loss if combined with front-running or bad UX.


### Recommendation 
Check totalSupplyCap first before transferring totalFee to oplTreasury because if the totalSupplyCap limit is reached or exceeds, the deposit will simply revert before the fee deduction.
```solidity
    function _processDeposit(
        address _sender,
        address _receiver,
        uint256 _assets
    ) internal {
// FIX: check totalSupplyCap first before transferring totalFee 
        if (totalSupply() + shares > totalSupplyCap)
            revert TotalSupplyCapExceeded(
                totalSupply(),
                shares,
                totalSupplyCap
            );

        (uint256 oeFee, int256 pFee, uint256 totalFee) = txsFee(
            ActionType.DEPOSIT,
            _sender,
            _assets
        );

        // collect the fee
        if (totalFee > 0) {
            SafeERC20Upgradeable.safeTransferFrom(
                IERC20Upgradeable(underlying),
                _sender,
                oplTreasury,
                totalFee
            );
        }

        uint256 trimmedAssets = _assets - totalFee;
        uint256 shares = _convertToShares(trimmedAssets);
        _deposit(_sender, _receiver, trimmedAssets, shares, treasury);
        emit ProcessDeposit(
```