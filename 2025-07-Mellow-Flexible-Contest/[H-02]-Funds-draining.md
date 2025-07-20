### [H-02] Missing validation of requested amount allows over-redeem in redeem() function

_Severity:_ High

_Source:_ https://github.com/sherlock-audit/2025-07-mellow-flexible-vaults-Yahaya-Salisu/blob/main/flexible-vaults%2Fsrc%2Fqueues%2FSignatureRedeemQueue.sol#L13-L28


### Summary
The `redeem()` function in `signatureRedeemQueue.sol` extents `signatureQueue` to enable instant share redemption from a vault without the usual delay of on-chain oracle processing.

The function calls `validateOrder()` and both of the functions do not check if the `requested > ordered`, meaning that if a user calls `redeem()` with a requested amount that exceeds ordered amount, the redemption will still proceed even if the `requested > ordered`, this allows users to potentially drain the vaults

```solidity
    function redeem(Order calldata order, IConsensus.Signature[] calldata signatures) external payable nonReentrant {
        validateOrder(order, signatures);
        _signatureQueueStorage().nonces[order.caller]++;
        IShareModule vault_ = IShareModule(vault());

  // ⚠️ BUG: there's no check to ensure requested <= ordered
        if (order.requested > vault_.getLiquidAssets()) {
            revert InsufficientAssets(order.requested, vault_.getLiquidAssets());
        }

// burns the shares without checking if requested > ordered
        vault_.shareManager().burn(order.recipient, order.ordered);

           ...

        emit OrderExecuted(order, signatures);
    }
```

This bug is similar in nature to `[H-01]` found in `RedeemQueue.sol`, but due to the separation of contract logic and exploit surface, this report addresses a distinct instance.


### Internal Preconditions
If a trusted party like admin or validator has signed a message granting a user an ordered amount, which can be redeemed via SignatureRedeemQueue.redeem().


### External Preconditions
A user has to get signed ordered amount first and then calls `redeem()` with a `requested > ordered`.


### Attacker Path
1. A user got a valid signed order for `1,000`.
2. And then modifies requested amount to `10,000` even though, the signed ordered is `1000`.
3. And the user calls `redeem()` with valid signatures and redemption succeeds as long as vault has >= 10,000 in liquid assets.


### Impact:
This vulnerability allows a user to redeem more assets than they are allowed to redeem, and inflating their authorized withdrawal by exploiting a missing validation. This leads to permanent imbalance in the vault, dilution of shares, and potential loss of funds for other users.


### Proof of concept:
```solidity

```

### Recommendation:
```solidity
    function redeem(Order calldata order, IConsensus.Signature[] calldata signatures) external payable nonReentrant {
        validateOrder(order, signatures);
        _signatureQueueStorage().nonces[order.caller]++;
        IShareModule vault_ = IShareModule(vault());

// FIX: after checking vault liquidAsset, check if requested > ordered 
        if (order.requested > vault_.getLiquidAssets(), || order.requested > order.ordered) {
            revert InsufficientAssets(order.requested, vault_.getLiquidAssets());
        }

        vault_.shareManager().burn(order.recipient, order.ordered);
      ...
        emit OrderExecuted(order, signatures);
    }
```