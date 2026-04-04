# QuantDEX Security Reference

> **Status: UNAUDITED — educational use only.**  
> This contract is designed as a security reference implementation, not production infrastructure.

## Attack Surface Map

| Attack Vector | SWC ID | CWE | Affected Function | Mitigation | Test |
|---|---|---|---|---|---|
| Reentrancy | SWC-107 | CWE-841 | `swap`, `removeLiquidity`, `addLiquidity` | `ReentrancyGuard` + CEI pattern | `QuantDEX.t.sol::testReentrancyProtection` |
| Share inflation (1st deposit) | — | CWE-682 | `addLiquidity` | Geometric-mean bootstrap `sqrt(A*B)` | `Attacks.t.sol::testDonationAttack` |
| Sandwich / front-running | SWC-114 | CWE-362 | `swap` | `amountOutMin` slippage guard | `Attacks.t.sol::testSandwichAttackSetup` |
| Price oracle manipulation | SWC-120 | CWE-330 | N/A (no oracle) | No oracle exposed; document limitation | `Attacks.t.sol::testPriceManipulation` |
| Integer overflow/underflow | SWC-101 | CWE-190 | All math | Solidity 0.8.x checked arithmetic | N/A |
| Token ordering / duplicate pool | — | CWE-706 | `_poolKey` | Canonical sort: always `token0 < token1` | `QuantDEX.t.sol::testPoolSymmetry` |
| Donation attack (reserve donation) | — | CWE-682 | `addLiquidity` | Geometric-mean limits inflation cost | `Attacks.t.sol::testDonationAttack` |
| Dust / zero-share mint | — | CWE-682 | `addLiquidity` | `require(sharesMinted > 0)` | `QuantDEX.t.sol::testAddLiquidity` |

---

## Attack Details

### 1. Reentrancy (SWC-107)
**What it is:** A malicious token's `transferFrom` or `transfer` re-enters the DEX mid-execution before state is updated, allowing double-withdrawal or duplicate minting.

**Mitigation:**
1. `ReentrancyGuard` — all external functions are `nonReentrant`. A second call reverts immediately.
2. CEI (Checks-Effects-Interactions) pattern — state is updated *before* external calls wherever possible. Even if the guard were absent, state would be correct on re-entry.

**In code:** `QuantDEX.sol` L9, L79, L143, L189 (`nonReentrant`). State writes at L133-136, L164-167, L218-223 all precede external calls.

---

### 2. Share Inflation (First Deposit)
**What it is:** Without a geometric-mean bootstrap, a first depositor can:
1. Deposit 1 wei of each token → receive 1 share
2. Donate a large amount directly to the contract
3. Force the pool's "price per share" to enormous value
4. Next depositor's `shares = deposit / inflated_value` rounds to 0 → they lose all tokens

**Mitigation:** `sharesMinted = sqrt(amountA * amountB)` for the first deposit. The attacker must donate O(N²) tokens to inflate 1 share to value N — quadratic cost makes large-scale inflation infeasible.

**In code:** `QuantDEX.sol` L99 — bootstrap via `_sqrt`.

**Residual risk:** A careful attacker can still cause the second depositor to receive slightly fewer shares. The geometric-mean does NOT fully eliminate dilution — it makes it expensive. Production AMMs (Uniswap v2) burn `MINIMUM_LIQUIDITY` (1000 shares) to lock them permanently, further hardening this. This contract does not burn minimum liquidity — a known simplification.

---

### 3. Sandwich Attack (SWC-114)
**What it is:** An attacker observing the mempool front-runs a victim's swap to move the price, then back-runs to capture profit. The victim receives worse execution.

**Partial mitigation:** `amountOutMin` — the victim specifies the minimum acceptable output. A tight slippage tolerance causes the tx to revert if the sandwiched output is too low.

**NOT mitigated:** The fundamental sandwich vector exists as long as txs are public in the mempool. Full mitigation requires private mempool (Flashbots) or batch auction execution (CoW Protocol).

**Guidance for users:** Always set `amountOutMin` to ~98-99% of the quoted output. `amountOutMin = 0` provides zero protection.

**In code:** `QuantDEX.sol` L213 — `require(amountOut >= amountOutMin, "SLIPPAGE")`.

---

### 4. Price Oracle Manipulation
**What it is:** This contract intentionally has NO price oracle. If another contract reads `pool.reserveA` / `pool.reserveB` as a spot price, an attacker can manipulate it in a single transaction.

**Mitigation:** Do not use this contract's reserves as a price oracle. For production use, implement a TWAP oracle (Uniswap v2's cumulative price mechanism) or integrate Chainlink.

**In code:** No oracle functions exposed — by design.

---

### 5. Donation Attack (Reserve Inflation)
**What it is:** Tokens sent directly to the contract (not via `addLiquidity`) inflate the reserves without minting new shares. This dilutes existing LP positions marginally but cannot be used to steal funds.

**Mitigation:** The contract tracks reserves independently of `balanceOf`. It does NOT use `IERC20(token).balanceOf(address(this))` as its reserve source — it uses its own accounting (`pool.reserveA`, `pool.reserveB`). Donated tokens are permanently locked and accrue to remaining LPs on exit.

**Note:** Uniswap v2 uses a `sync()` function to reconcile `balanceOf` with reserves. This contract does not — balanceOf drift is harmless here because we never read it.

---

## Known Limitations (By Design)

| Limitation | Impact | Production Fix |
|---|---|---|
| No TWAP oracle | Spot price is manipulable | Cumulative price tracking (Uniswap v2 style) |
| No MINIMUM_LIQUIDITY burn | First-deposit share inflation slightly easier | Burn 1000 shares to zero address at bootstrap |
| No factory / CREATE2 | No trustless pair discovery | Factory contract with deterministic addresses |
| No flash loans | Limits composability | Add `flash()` callback (but adds attack surface) |
| No multi-hop routing | No indirect swaps | Router contract computing optimal paths |
| Single fee tier (0.3%) | Suboptimal for low-volatility pairs | Dynamic fees or concentrated liquidity |

---

---

## Wake Static Analysis Findings

Detected with `wake detect all --min-impact medium` on `src/QuantDEX.sol`:

| Severity | Detector | Finding | Status |
|---|---|---|---|
| HIGH (impact) / MEDIUM (confidence) | `reentrancy` | `swap()` — two external token calls before state update is complete | **Mitigated** by `nonReentrant` guard + CEI pattern |
| HIGH (impact) / LOW (confidence) | `reentrancy` | `addLiquidity()`, `removeLiquidity()` — token transfers before/after state writes | **Mitigated** by `nonReentrant` guard |
| HIGH (impact) / MEDIUM (confidence) | `unchecked-return-value` | Raw `IERC20.transferFrom()` / `transfer()` calls ignore bool return | **Known limitation** — non-compliant tokens silently fail |
| MEDIUM (impact) / HIGH (confidence) | `unsafe-erc20-call` | Direct ERC-20 calls without SafeERC20 wrapper | **Known limitation** — production should use OZ SafeERC20 |

### Explanation of findings

**Reentrancy (mitigated):** Wake's detector flags the token transfer sites because they technically appear before/after state writes in the control flow. However, these are protected by `ReentrancyGuard.nonReentrant` which reverts any recursive call. The CEI pattern is also followed in `swap()` and `removeLiquidity()` — state is updated before interactions.

**Unchecked return values / unsafe ERC-20 (known, educational):** The IERC20 interface calls do not check the bool return value from `transfer()` / `transferFrom()`. Non-standard tokens (e.g., USDT, BNB) do not return a bool — these calls will silently succeed even if the transfer fails. Production code should use OpenZeppelin's `SafeERC20.safeTransfer()` which adds a return-value check and compatibility shim.

```solidity
// Current (educational):
IERC20(token).transferFrom(caller, address(this), amount);

// Production fix:
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
using SafeERC20 for IERC20;
IERC20(token).safeTransferFrom(caller, address(this), amount);
```

---

## Test Coverage

```
forge test -vv                                              # all unit + attack tests
forge test --match-contract InvariantTest --fuzz-runs 1000  # property tests
wake test tests/test_amm_wake.py -v                         # Wake Python fuzz tests
wake detect all --min-impact medium                         # Static analysis
```

## Resources

- [SWC Registry](https://swcregistry.io)
- [Uniswap v2 Whitepaper](https://uniswap.org/whitepaper.pdf)
- [Uniswap v2 Core Security Review](https://github.com/Uniswap/v2-core/blob/master/audits/)
- [Trail of Bits AMM Report](https://github.com/trailofbits/publications)
- [Damn Vulnerable DeFi](https://www.damnvulnerabledefi.xyz) — practice exploiting similar contracts
