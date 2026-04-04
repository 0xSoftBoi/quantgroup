// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./interfaces/IERC20.sol";

/// @title QuantDEX — Constant-product AMM
/// @notice x * y = k with 0.3% swap fee. Rebuilt from the original 2017 DEX experiment.
contract QuantDEX {
    struct Pool {
        uint256 reserveA;
        uint256 reserveB;
        uint256 totalShares;
    }

    /// @dev pool key = keccak256(abi.encodePacked(tokenA, tokenB))
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

    function _poolKey(address tokenA, address tokenB) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(tokenA, tokenB));
    }

    // -------------------------------------------------------------------------
    // Liquidity
    // -------------------------------------------------------------------------

    /// @notice Deposit tokenA and tokenB to mint LP shares.
    /// @dev First liquidity sets the price. Subsequent deposits must match the
    ///      current ratio; excess is NOT returned — callers should compute the
    ///      correct amounts off-chain before calling.
    function addLiquidity(
        address tokenA,
        address tokenB,
        uint256 amountA,
        uint256 amountB
    ) external returns (uint256 sharesMinted) {
        require(amountA > 0 && amountB > 0, "ZERO_AMOUNT");

        bytes32 key = _poolKey(tokenA, tokenB);
        Pool storage pool = pools[key];

        IERC20(tokenA).transferFrom(msg.sender, address(this), amountA);
        IERC20(tokenB).transferFrom(msg.sender, address(this), amountB);

        if (pool.totalShares == 0) {
            // Bootstrap — geometric mean of initial deposit
            sharesMinted = _sqrt(amountA * amountB);
        } else {
            // Pro-rata — use the lesser of the two ratios to protect existing LPs
            uint256 sharesA = (amountA * pool.totalShares) / pool.reserveA;
            uint256 sharesB = (amountB * pool.totalShares) / pool.reserveB;
            sharesMinted = sharesA < sharesB ? sharesA : sharesB;
        }

        require(sharesMinted > 0, "ZERO_SHARES");

        pool.reserveA += amountA;
        pool.reserveB += amountB;
        pool.totalShares += sharesMinted;
        shares[key][msg.sender] += sharesMinted;

        emit LiquidityAdded(msg.sender, tokenA, tokenB, amountA, amountB, sharesMinted);
    }

    /// @notice Burn LP shares and receive a pro-rata share of pool reserves.
    function removeLiquidity(
        address tokenA,
        address tokenB,
        uint256 sharesToBurn
    ) external returns (uint256 amountA, uint256 amountB) {
        require(sharesToBurn > 0, "ZERO_SHARES");

        bytes32 key = _poolKey(tokenA, tokenB);
        Pool storage pool = pools[key];

        require(shares[key][msg.sender] >= sharesToBurn, "INSUFFICIENT_SHARES");
        require(pool.totalShares > 0, "EMPTY_POOL");

        amountA = (sharesToBurn * pool.reserveA) / pool.totalShares;
        amountB = (sharesToBurn * pool.reserveB) / pool.totalShares;

        require(amountA > 0 && amountB > 0, "ZERO_OUTPUT");

        shares[key][msg.sender] -= sharesToBurn;
        pool.totalShares -= sharesToBurn;
        pool.reserveA -= amountA;
        pool.reserveB -= amountB;

        IERC20(tokenA).transfer(msg.sender, amountA);
        IERC20(tokenB).transfer(msg.sender, amountB);

        emit LiquidityRemoved(msg.sender, tokenA, tokenB, amountA, amountB, sharesToBurn);
    }

    // -------------------------------------------------------------------------
    // Swap
    // -------------------------------------------------------------------------

    /// @notice Swap tokenIn for tokenOut using the constant-product formula with a 0.3% fee.
    /// @param tokenIn   Token being sold.
    /// @param tokenOut  Token being bought.
    /// @param amountIn  Exact amount of tokenIn to sell.
    /// @param minAmountOut  Minimum acceptable output (slippage guard).
    function swap(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 minAmountOut
    ) external returns (uint256 amountOut) {
        require(amountIn > 0, "ZERO_INPUT");

        // Determine which side of the pool is which
        bytes32 keyAB = _poolKey(tokenIn, tokenOut);
        bytes32 keyBA = _poolKey(tokenOut, tokenIn);

        Pool storage pool;
        bool inIsA;

        if (pools[keyAB].totalShares > 0) {
            pool = pools[keyAB];
            inIsA = true;
        } else if (pools[keyBA].totalShares > 0) {
            pool = pools[keyBA];
            inIsA = false;
        } else {
            revert("POOL_NOT_FOUND");
        }

        uint256 reserveIn  = inIsA ? pool.reserveA : pool.reserveB;
        uint256 reserveOut = inIsA ? pool.reserveB : pool.reserveA;

        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);

        // 0.3% fee: multiply amountIn by 997, denominator by 1000
        uint256 amountInWithFee = amountIn * 997;
        amountOut = (amountInWithFee * reserveOut) / (reserveIn * 1000 + amountInWithFee);

        require(amountOut >= minAmountOut, "SLIPPAGE");
        require(amountOut < reserveOut, "INSUFFICIENT_LIQUIDITY");

        if (inIsA) {
            pool.reserveA += amountIn;
            pool.reserveB -= amountOut;
        } else {
            pool.reserveB += amountIn;
            pool.reserveA -= amountOut;
        }

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
