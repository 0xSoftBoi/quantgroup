// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./interfaces/IERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title QuantDEX — Constant-product AMM
/// @notice x * y = k with 0.3% swap fee. Security-hardened.
contract QuantDEX is ReentrancyGuard {
    struct Pool {
        uint256 reserveA;
        uint256 reserveB;
        uint256 totalShares;
    }

    /// @dev pool key = keccak256(abi.encodePacked(tokenA, tokenB)) where tokenA < tokenB
    mapping(bytes32 => Pool) public pools;

    /// @dev LP shares per pool per provider
    mapping(bytes32 => mapping(address => uint256)) public shares;

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

    /// @dev Always sorts so that the lower address is tokenA, preventing (A,B)/(B,A) duplicates.
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
    /// @dev Tokens are sorted internally; callers may pass in either order.
    ///      First liquidity sets the price. Subsequent deposits are adjusted to
    ///      match the current ratio and any excess is returned to the caller.
    function addLiquidity(
        address tokenA,
        address tokenB,
        uint256 amountA,
        uint256 amountB
    ) external nonReentrant returns (uint256 sharesMinted) {
        require(tokenA != address(0) && tokenB != address(0), "ZERO_ADDRESS");
        require(tokenA != tokenB, "IDENTICAL_TOKENS");
        require(amountA > 0 && amountB > 0, "ZERO_AMOUNT");

        // Enforce canonical ordering so (A,B) and (B,A) map to the same pool.
        (address t0, address t1) = _sortTokens(tokenA, tokenB);
        // Align the amounts to the sorted token order.
        (uint256 amt0, uint256 amt1) = tokenA == t0
            ? (amountA, amountB)
            : (amountB, amountA);

        bytes32 key = keccak256(abi.encodePacked(t0, t1));
        Pool storage pool = pools[key];

        uint256 actual0 = amt0;
        uint256 actual1 = amt1;

        if (pool.totalShares == 0) {
            // Bootstrap — geometric mean of initial deposit
            sharesMinted = _sqrt(actual0 * actual1);
        } else {
            // Calculate optimal amounts to maintain current ratio.
            // Try to use full amt0 and compute optimal amt1.
            uint256 optimal1 = (amt0 * pool.reserveB) / pool.reserveA;
            if (optimal1 <= amt1) {
                actual0 = amt0;
                actual1 = optimal1;
            } else {
                // amt1 is the limiting side; compute optimal amt0.
                uint256 optimal0 = (amt1 * pool.reserveA) / pool.reserveB;
                actual0 = optimal0;
                actual1 = amt1;
            }

            uint256 sharesA = (actual0 * pool.totalShares) / pool.reserveA;
            uint256 sharesB = (actual1 * pool.totalShares) / pool.reserveB;
            sharesMinted = sharesA < sharesB ? sharesA : sharesB;
        }

        require(sharesMinted > 0, "ZERO_SHARES");

        // Pull tokens from caller (CEI: external calls before state writes only
        // for the pull; state is updated right after).
        address caller = msg.sender;
        if (tokenA == t0) {
            IERC20(t0).transferFrom(caller, address(this), actual0);
            IERC20(t1).transferFrom(caller, address(this), actual1);
        } else {
            IERC20(t0).transferFrom(caller, address(this), actual0);
            IERC20(t1).transferFrom(caller, address(this), actual1);
        }

        // Effects — update state after external calls that only pull funds in.
        pool.reserveA += actual0;
        pool.reserveB += actual1;
        pool.totalShares += sharesMinted;
        shares[key][caller] += sharesMinted;

        emit LiquidityAdded(caller, t0, t1, actual0, actual1, sharesMinted);
    }

    /// @notice Burn LP shares and receive a pro-rata share of pool reserves.
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

        uint256 out0 = (sharesToBurn * pool.reserveA) / pool.totalShares;
        uint256 out1 = (sharesToBurn * pool.reserveB) / pool.totalShares;

        require(out0 > 0 && out1 > 0, "ZERO_OUTPUT");

        // Effects first (CEI)
        shares[key][msg.sender] -= sharesToBurn;
        pool.totalShares -= sharesToBurn;
        pool.reserveA -= out0;
        pool.reserveB -= out1;

        // Interactions last
        IERC20(t0).transfer(msg.sender, out0);
        IERC20(t1).transfer(msg.sender, out1);

        // Map sorted outputs back to the caller's token order for the return values.
        (amountA, amountB) = tokenA == t0 ? (out0, out1) : (out1, out0);

        emit LiquidityRemoved(msg.sender, t0, t1, out0, out1, sharesToBurn);
    }

    // -------------------------------------------------------------------------
    // Swap
    // -------------------------------------------------------------------------

    /// @notice Swap tokenIn for tokenOut using the constant-product formula with a 0.3% fee.
    /// @param tokenIn      Token being sold.
    /// @param tokenOut     Token being bought.
    /// @param amountIn     Exact amount of tokenIn to sell.
    /// @param amountOutMin Minimum acceptable output (slippage guard).
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

        // Determine which side of the pool is which using stored reserves.
        (address t0,) = _sortTokens(tokenIn, tokenOut);
        bool inIsA = (tokenIn == t0);

        uint256 reserveIn  = inIsA ? pool.reserveA : pool.reserveB;
        uint256 reserveOut = inIsA ? pool.reserveB : pool.reserveA;

        // 0.3% fee: multiply amountIn by 997, denominator by 1000
        uint256 amountInWithFee = amountIn * 997;
        amountOut = (amountInWithFee * reserveOut) / (reserveIn * 1000 + amountInWithFee);

        require(amountOut >= amountOutMin, "SLIPPAGE");
        require(amountOut < reserveOut, "INSUFFICIENT_LIQUIDITY");

        // Effects BEFORE interactions (CEI)
        if (inIsA) {
            pool.reserveA += amountIn;
            pool.reserveB -= amountOut;
        } else {
            pool.reserveB += amountIn;
            pool.reserveA -= amountOut;
        }

        // Interactions
        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
        IERC20(tokenOut).transfer(msg.sender, amountOut);

        emit Swap(msg.sender, tokenIn, tokenOut, amountIn, amountOut);
    }

    // -------------------------------------------------------------------------
    // Internal math
    // -------------------------------------------------------------------------

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
