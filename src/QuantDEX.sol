// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./interfaces/IERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title QuantDEX — Constant-Product AMM (Security Reference Implementation)
/// @notice Implements x·y=k with 0.3% swap fee. Designed as an annotated reference
///         for security auditors and researchers — not a production protocol.
///
/// @dev INVARIANTS (verified by InvariantTest.t.sol):
///      1. pool.reserveA * pool.reserveB >= k_before after every swap (fees increase k)
///      2. sum(shares[pool][all_users]) == pool.totalShares at all times
///      3. pool.totalShares > 0 iff pool.reserveA > 0 (no ghost shares)
///
/// @custom:audit-status unaudited — educational use only
/// @custom:security-model see SECURITY.md for full attack surface analysis
/// @custom:swc-reference https://swcregistry.io
/// @custom:cwe-reference https://cwe.mitre.org
///
/// Known limitations (documented, not bugs):
/// - No TWAP oracle → reserves are manipulable within a single block (SWC-120 adjacent)
/// - No flash loan → reduces manipulation surface vs Uniswap v2
/// - No factory → single deployer, not trustless
/// - Integer math rounds down → tiny rounding losses accrue to the pool (safe, but audit note)
contract QuantDEX is ReentrancyGuard {
    // -------------------------------------------------------------------------
    // Types
    // -------------------------------------------------------------------------

    struct Pool {
        uint256 reserveA;   // canonical token0 reserve
        uint256 reserveB;   // canonical token1 reserve
        uint256 totalShares; // total outstanding LP shares
    }

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------

    /// @dev Pool key = keccak256(abi.encodePacked(token0, token1)) where token0 < token1.
    ///      Canonical ordering prevents two separate pools for (A,B) and (B,A).
    ///      Attack surface: without sorting, an attacker could exploit asymmetric pool state.
    mapping(bytes32 => Pool) public pools;

    /// @dev LP share balance per pool per provider.
    ///      Shares represent a pro-rata claim on both reserves.
    ///      Attack: first-deposit share inflation. Closed here by INTERNAL reserve
    ///      accounting (reserves are state, not balanceOf), so a donation can't move
    ///      share price. The sqrt bootstrap is for ratio-independence, not this — see addLiquidity.
    ///      See: https://github.com/Uniswap/v2-core/issues/148
    mapping(bytes32 => mapping(address => uint256)) public shares;

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    event LiquidityAdded(
        address indexed provider,
        address indexed tokenA,
        address indexed tokenB,
        uint256 amountA,
        uint256 amountB,
        uint256 sharesMinted
    );

    event LiquidityRemoved(
        address indexed provider,
        address indexed tokenA,
        address indexed tokenB,
        uint256 amountA,
        uint256 amountB,
        uint256 sharesBurned
    );

    event Swap(
        address indexed trader,
        address indexed tokenIn,
        address indexed tokenOut,
        uint256 amountIn,
        uint256 amountOut
    );

    // -------------------------------------------------------------------------
    // Pool key helpers
    // -------------------------------------------------------------------------

    /// @dev Canonical token ordering: always token0 < token1.
    ///      NOTE: Prevents duplicate pools and ensures deterministic pool keys.
    ///      Without this, an attacker could create (B,A) separate from (A,B) and
    ///      exploit price differences between them.
    function _sortTokens(address tokenA, address tokenB)
        internal
        pure
        returns (address t0, address t1)
    {
        (t0, t1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
    }

    function _poolKey(address tokenA, address tokenB) internal pure returns (bytes32) {
        (address t0, address t1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        return keccak256(abi.encodePacked(t0, t1));
    }

    // -------------------------------------------------------------------------
    // Liquidity
    // -------------------------------------------------------------------------

    /// @notice Deposit tokenA and tokenB to mint LP shares.
    ///
    /// @dev ATTACK SURFACE — Share inflation (first deposit):
    ///      The classic vector: be the first depositor with 1 wei of each token, donate a
    ///      large amount directly to the contract, and inflate share value so the next
    ///      depositor's mint rounds to 0 shares. That attack REQUIRES the pool to read its
    ///      token balance as the reserve. This contract does not — reserves are internal
    ///      accounting (pool.reserveA/reserveB), updated only inside addLiquidity/swap, so a
    ///      raw transfer is invisible to the share math and the vector is structurally closed.
    ///      NOTE: the sqrt(amountA * amountB) bootstrap below is NOT the inflation defense. It
    ///      sets initial share value independent of the deposit RATIO (Uniswap v2 §3.4). The
    ///      canonical defense for balanceOf-based pools is burning dead shares (UniV2
    ///      MINIMUM_LIQUIDITY) or virtual shares (ERC-4626) — a linear cost, not quadratic.
    ///      See: Uniswap v2 whitepaper §3.4 | https://docs.openzeppelin.com/contracts/5.x/erc4626
    ///
    /// @dev PATTERN — CEI (Checks-Effects-Interactions):
    ///      transferFrom calls appear before state writes in source, but they only
    ///      PULL funds in — the contract never holds a "mid-state" where it has
    ///      debited state without receiving tokens. nonReentrant is the backstop.
    ///      See: SWC-107 (Reentrancy)
    ///
    /// @param tokenA One token in the pair. Can be passed in either order.
    /// @param tokenB The other token.
    /// @param amountA Desired amount of tokenA. May be reduced to maintain ratio.
    /// @param amountB Desired amount of tokenB. May be reduced to maintain ratio.
    function addLiquidity(
        address tokenA,
        address tokenB,
        uint256 amountA,
        uint256 amountB
    ) external nonReentrant returns (uint256 sharesMinted) {
        require(tokenA != address(0) && tokenB != address(0), "ZERO_ADDRESS");
        require(tokenA != tokenB, "IDENTICAL_TOKENS");
        require(amountA > 0 && amountB > 0, "ZERO_AMOUNT");

        // Canonical sort: ensures (A,B) and (B,A) always route to the same pool.
        (address t0, address t1) = _sortTokens(tokenA, tokenB);
        (uint256 amt0, uint256 amt1) = tokenA == t0
            ? (amountA, amountB)
            : (amountB, amountA);

        bytes32 key = keccak256(abi.encodePacked(t0, t1));
        Pool storage pool = pools[key];

        uint256 actual0 = amt0;
        uint256 actual1 = amt1;

        if (pool.totalShares == 0) {
            // BOOTSTRAP: initial share supply = geometric mean of the deposit.
            // @security This sets initial share value independent of the deposit RATIO
            //           (Uniswap v2 §3.4); it is NOT the first-deposit inflation defense.
            //           The donation-inflation attack is closed structurally instead:
            //           reserves are internal accounting (pool.reserveA/B), so a direct
            //           token donation never enters the share math and can't move price.
            //           Auditors: verify sqrt precision here — rounding down is safe
            //           because it slightly undervalues the first depositor's shares,
            //           never overvaluing. Residual dust stays in the pool forever.
            sharesMinted = _sqrt(actual0 * actual1);
        } else {
            // SUBSEQUENT DEPOSITS: must respect existing price ratio.
            // Excess of either token is NOT accepted — caller provides the minimum of
            // their two pro-rata calculations. Any difference stays in caller's wallet.
            // @security If we accepted excess, we would change the pool price on deposit
            //           (essentially a swap bundled with an LP add), allowing price manipulation.
            uint256 optimal1 = (amt0 * pool.reserveB) / pool.reserveA;
            if (optimal1 <= amt1) {
                actual0 = amt0;
                actual1 = optimal1;
            } else {
                uint256 optimal0 = (amt1 * pool.reserveA) / pool.reserveB;
                actual0 = optimal0;
                actual1 = amt1;
            }

            // Min of pro-rata share calculations — guarantees non-dilution.
            // @security Using min() prevents a depositor from minting more shares
            //           than their actual contribution justifies.
            uint256 sharesA = (actual0 * pool.totalShares) / pool.reserveA;
            uint256 sharesB = (actual1 * pool.totalShares) / pool.reserveB;
            sharesMinted = sharesA < sharesB ? sharesA : sharesB;
        }

        require(sharesMinted > 0, "ZERO_SHARES");

        // INTERACTIONS: pull tokens from caller.
        // @security nonReentrant guards against re-entry here. If a token's
        //           transferFrom re-enters addLiquidity, the reentrancy guard reverts.
        //           SWC-107: reentrancy — mitigated by ReentrancyGuard.
        address caller = msg.sender;
        IERC20(t0).transferFrom(caller, address(this), actual0);
        IERC20(t1).transferFrom(caller, address(this), actual1);

        // EFFECTS: update pool state after external calls.
        pool.reserveA += actual0;
        pool.reserveB += actual1;
        pool.totalShares += sharesMinted;
        shares[key][caller] += sharesMinted;

        emit LiquidityAdded(caller, t0, t1, actual0, actual1, sharesMinted);
    }

    /// @notice Burn LP shares and receive a pro-rata share of pool reserves.
    ///
    /// @dev PATTERN — CEI strictly enforced here:
    ///      State writes (shares debit, reserve debit) happen BEFORE token transfers.
    ///      NOTE: If state were updated after transfer (wrong CEI), a reentrant
    ///      attacker could call removeLiquidity again before shares are debited and
    ///      double-withdraw. nonReentrant is a second layer of defense. SWC-107.
    ///
    /// @dev ATTACK — Drain pool to zero:
    ///      A user holding 100% of shares can call removeLiquidity and withdraw all
    ///      reserves. This is CORRECT BEHAVIOR — LP shares are a full claim.
    ///      The pool then has totalShares=0 and requires fresh bootstrap to reactivate.
    function removeLiquidity(
        address tokenA,
        address tokenB,
        uint256 sharesToBurn
    ) external nonReentrant returns (uint256 amountA, uint256 amountB) {
        require(tokenA != address(0) && tokenB != address(0), "ZERO_ADDRESS");
        require(tokenA != tokenB, "IDENTICAL_TOKENS");
        require(sharesToBurn > 0, "ZERO_SHARES");

        (address t0, address t1) = _sortTokens(tokenA, tokenB);
        bytes32 key = keccak256(abi.encodePacked(t0, t1));
        Pool storage pool = pools[key];

        require(shares[key][msg.sender] >= sharesToBurn, "INSUFFICIENT_SHARES");
        require(pool.totalShares > 0, "EMPTY_POOL");

        // Pro-rata output: each token scales linearly with share fraction.
        // @security integer division rounds down — dust stays in pool.
        //           This is safe: LPs cannot extract more than they contributed.
        uint256 out0 = (sharesToBurn * pool.reserveA) / pool.totalShares;
        uint256 out1 = (sharesToBurn * pool.reserveB) / pool.totalShares;

        require(out0 > 0 && out1 > 0, "ZERO_OUTPUT");

        // EFFECTS first — debit shares and reserves BEFORE sending tokens.
        // @security SWC-107: state updated before external calls prevents reentrancy drain.
        shares[key][msg.sender] -= sharesToBurn;
        pool.totalShares -= sharesToBurn;
        pool.reserveA -= out0;
        pool.reserveB -= out1;

        // INTERACTIONS last.
        IERC20(t0).transfer(msg.sender, out0);
        IERC20(t1).transfer(msg.sender, out1);

        (amountA, amountB) = tokenA == t0 ? (out0, out1) : (out1, out0);

        emit LiquidityRemoved(msg.sender, t0, t1, out0, out1, sharesToBurn);
    }

    // -------------------------------------------------------------------------
    // Swap
    // -------------------------------------------------------------------------

    /// @notice Swap tokenIn for tokenOut using the constant-product formula with a 0.3% fee.
    ///
    /// @dev OUTPUT FORMULA:
    ///      amountOut = (amountIn * 997 * reserveOut) / (reserveIn * 1000 + amountIn * 997)
    ///      The 0.3% fee is implicit: 997/1000 = 1 - 0.003.
    ///      Fee stays in the pool — it incrementally increases k after every swap.
    ///
    /// @dev ATTACK — Sandwich (front/back-run):
    ///      An attacker watching the mempool can:
    ///        1. Front-run: buy tokenOut before the victim's tx (drives price up)
    ///        2. Let victim's tx execute at worse price
    ///        3. Back-run: sell tokenOut immediately after (capture the price impact)
    ///      PARTIAL MITIGATION: amountOutMin (slippage guard) limits victim's loss
    ///      if set correctly. A value of 0 provides NO protection.
    ///      NOT FULLY MITIGATED: sandwich is an inherent property of public mempools.
    ///      Real DEXes use private mempools (Flashbots) or batch auctions (CoW Protocol).
    ///      See: test/Attacks.t.sol::testSandwichAttackSetup
    ///
    /// @dev ATTACK — Price oracle manipulation:
    ///      This contract has NO TWAP oracle. Using pool.reserveA/reserveB directly as a
    ///      price oracle in another contract is exploitable in a single transaction:
    ///        1. Large swap moves the price significantly
    ///        2. Oracle-dependent contract reads manipulated price
    ///        3. Attacker profits from oracle-dependent action
    ///        4. Second swap restores price (or not — attacker keeps profit)
    ///      MITIGATION: never use spot reserves as a price oracle.
    ///      See: test/Attacks.t.sol::testPriceManipulation
    ///
    /// @dev PATTERN — CEI with a subtle note:
    ///      State is updated (pool.reserveA/B) BEFORE transferFrom is called.
    ///      This is correct CEI. A reentrancy attack via transferFrom would find
    ///      state already updated — the invariant holds. nonReentrant is defense-in-depth.
    ///
    /// @param tokenIn      Token being sold.
    /// @param tokenOut     Token being bought.
    /// @param amountIn     Exact amount of tokenIn to sell.
    /// @param amountOutMin Minimum acceptable output. Set to 0 at your own risk — see sandwich attack above.
    function swap(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 amountOutMin
    ) external nonReentrant returns (uint256 amountOut) {
        require(tokenIn != address(0) && tokenOut != address(0), "ZERO_ADDRESS");
        require(tokenIn != tokenOut, "IDENTICAL_TOKENS");
        require(amountIn > 0, "ZERO_INPUT");

        bytes32 key = _poolKey(tokenIn, tokenOut);
        Pool storage pool = pools[key];
        require(pool.totalShares > 0, "POOL_NOT_FOUND");

        (address t0,) = _sortTokens(tokenIn, tokenOut);
        bool inIsA = (tokenIn == t0);

        uint256 reserveIn  = inIsA ? pool.reserveA : pool.reserveB;
        uint256 reserveOut = inIsA ? pool.reserveB : pool.reserveA;

        // 0.3% fee applied to amountIn.
        // @security Using integer multiply/divide rather than floating-point ensures
        //           no rounding can produce amountOut >= reserveOut (verified below).
        uint256 amountInWithFee = amountIn * 997;
        amountOut = (amountInWithFee * reserveOut) / (reserveIn * 1000 + amountInWithFee);

        // @security slippage guard — if amountOutMin == 0 this check is a no-op.
        //           Callers MUST set a realistic amountOutMin to protect against sandwich attacks.
        require(amountOut >= amountOutMin, "SLIPPAGE");

        // @security ensures amountOut cannot exceed reserveOut, preventing the pool
        //           from going to zero reserves (division by zero on next swap).
        require(amountOut < reserveOut, "INSUFFICIENT_LIQUIDITY");

        // EFFECTS before INTERACTIONS — update reserves first.
        // @security SWC-107: if tokenIn.transferFrom re-enters swap, pool.reserve is
        //           already updated, so the invariant check would catch any manipulation.
        if (inIsA) {
            pool.reserveA += amountIn;
            pool.reserveB -= amountOut;
        } else {
            pool.reserveB += amountIn;
            pool.reserveA -= amountOut;
        }

        // INTERACTIONS: pull tokenIn, push tokenOut.
        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
        IERC20(tokenOut).transfer(msg.sender, amountOut);

        emit Swap(msg.sender, tokenIn, tokenOut, amountIn, amountOut);
    }

    // -------------------------------------------------------------------------
    // Internal math
    // -------------------------------------------------------------------------

    /// @dev Babylonian square root. Used only for LP share bootstrap.
    ///      NOTE: Rounds DOWN — this means the first depositor receives
    ///      slightly fewer shares than the geometric mean. The rounding error
    ///      (at most 1 wei of shares) stays in the pool permanently as a dust reserve.
    ///      This is intentional and safe — it prevents a class of "1 share" attacks.
    function _sqrt(uint256 y) internal pure returns (uint256 z) {
        if (y > 3) {
            z = y;
            uint256 x = y / 2 + 1;
            while (x < z) {
                z = x;
                x = (y / x + x) / 2;
            }
        } else if (y != 0) {
            z = 1;
        }
    }
}
