# QuantDEX

A constant-product AMM (automated market maker) DEX built in Solidity. Supports multi-pool token swaps, liquidity provision, and LP share tracking — all governed by the `x * y = k` invariant with a 0.3% swap fee.

Rebuilt from my original 2017 DEX experiment — same vision, now with constant-product AMM and proper test coverage.

## How it works

### Pool state

Each token pair maps to a pool via `keccak256(abi.encodePacked(tokenA, tokenB))`. The pool stores `reserveA`, `reserveB`, and `totalShares`.

### Adding liquidity

`addLiquidity(tokenA, tokenB, amountA, amountB)` pulls both tokens from the caller and mints LP shares proportional to the deposit. The first deposit bootstraps the pool at the geometric mean (`sqrt(amountA * amountB)`). Subsequent deposits must respect the existing ratio — the contract mints shares based on the lesser of the two pro-rata amounts.

### Removing liquidity

`removeLiquidity(tokenA, tokenB, shares)` burns LP shares and returns a pro-rata slice of both reserves to the caller.

### Swapping

`swap(tokenIn, tokenOut, amountIn, minAmountOut)` routes through the pool in either direction. The output amount is computed as:

```
amountOut = (amountIn * 997 * reserveOut) / (reserveIn * 1000 + amountIn * 997)
```

The 0.3% fee stays in the pool, accruing to LPs. The `minAmountOut` parameter acts as a slippage guard — the call reverts if the output falls below it.

## Stack

- Solidity `^0.8.20`
- [Foundry](https://book.getfoundry.sh/)

## Build

```bash
forge build
```

## Test

```bash
forge test -vv
```

Tests cover:
- Bootstrap liquidity (`addLiquidity`)
- Second-deposit liquidity at existing ratio
- Full `removeLiquidity` round-trip
- Swap A→B and B→A
- Slippage revert
- Constant-product invariant holds after swap (`k_after >= k_before`)
