// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/QuantDEX.sol";
import "../src/interfaces/IERC20.sol";

// ---------------------------------------------------------------------------
// Minimal ERC20 mock — mint, transfer, transferFrom, approve, balanceOf
// ---------------------------------------------------------------------------
contract MockERC20 {
    string public name;
    uint8  public decimals = 18;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(string memory _name) {
        name = _name;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "BAL");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "BAL");
        require(allowance[from][msg.sender] >= amount, "ALLOWANCE");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
contract QuantDEXTest is Test {
    QuantDEX dex;
    MockERC20 tokenA;
    MockERC20 tokenB;

    address alice = address(0xA11CE);
    address bob   = address(0xB0B);

    uint256 constant LIQUIDITY_A = 100e18;
    uint256 constant LIQUIDITY_B = 200e18;

    function setUp() public {
        dex    = new QuantDEX();
        tokenA = new MockERC20("TokenA");
        tokenB = new MockERC20("TokenB");

        // Fund alice and bob
        tokenA.mint(alice, 1000e18);
        tokenB.mint(alice, 1000e18);
        tokenA.mint(bob,   1000e18);
        tokenB.mint(bob,   1000e18);
    }

    // -----------------------------------------------------------------------
    // addLiquidity
    // -----------------------------------------------------------------------

    function testAddLiquidityBootstrap() public {
        vm.startPrank(alice);
        tokenA.approve(address(dex), LIQUIDITY_A);
        tokenB.approve(address(dex), LIQUIDITY_B);

        uint256 sharesMinted = dex.addLiquidity(address(tokenA), address(tokenB), LIQUIDITY_A, LIQUIDITY_B);
        vm.stopPrank();

        // Geometric mean of 100e18 * 200e18 = sqrt(20000e36) = ~141.42e18
        assertGt(sharesMinted, 0, "no shares minted");

        (uint256 rA, uint256 rB, uint256 total) = dex.pools(keccak256(abi.encodePacked(address(tokenA), address(tokenB))));
        assertEq(rA, LIQUIDITY_A);
        assertEq(rB, LIQUIDITY_B);
        assertEq(total, sharesMinted);
    }

    function testAddLiquiditySecondDeposit() public {
        // Bootstrap
        vm.startPrank(alice);
        tokenA.approve(address(dex), LIQUIDITY_A);
        tokenB.approve(address(dex), LIQUIDITY_B);
        dex.addLiquidity(address(tokenA), address(tokenB), LIQUIDITY_A, LIQUIDITY_B);
        vm.stopPrank();

        // Bob adds liquidity at the same ratio
        vm.startPrank(bob);
        tokenA.approve(address(dex), 10e18);
        tokenB.approve(address(dex), 20e18);
        uint256 sharesMinted = dex.addLiquidity(address(tokenA), address(tokenB), 10e18, 20e18);
        vm.stopPrank();

        assertGt(sharesMinted, 0, "second deposit yielded no shares");
    }

    // -----------------------------------------------------------------------
    // removeLiquidity
    // -----------------------------------------------------------------------

    function testRemoveLiquidity() public {
        vm.startPrank(alice);
        tokenA.approve(address(dex), LIQUIDITY_A);
        tokenB.approve(address(dex), LIQUIDITY_B);
        uint256 sharesMinted = dex.addLiquidity(address(tokenA), address(tokenB), LIQUIDITY_A, LIQUIDITY_B);

        uint256 balABefore = tokenA.balanceOf(alice);
        uint256 balBBefore = tokenB.balanceOf(alice);

        (uint256 outA, uint256 outB) = dex.removeLiquidity(address(tokenA), address(tokenB), sharesMinted);
        vm.stopPrank();

        assertEq(outA, LIQUIDITY_A, "wrong tokenA returned");
        assertEq(outB, LIQUIDITY_B, "wrong tokenB returned");
        assertEq(tokenA.balanceOf(alice), balABefore + outA);
        assertEq(tokenB.balanceOf(alice), balBBefore + outB);
    }

    // -----------------------------------------------------------------------
    // swap
    // -----------------------------------------------------------------------

    function testSwapAForB() public {
        // Seed pool
        vm.startPrank(alice);
        tokenA.approve(address(dex), LIQUIDITY_A);
        tokenB.approve(address(dex), LIQUIDITY_B);
        dex.addLiquidity(address(tokenA), address(tokenB), LIQUIDITY_A, LIQUIDITY_B);
        vm.stopPrank();

        uint256 swapIn = 10e18;

        vm.startPrank(bob);
        tokenA.approve(address(dex), swapIn);
        uint256 balBBefore = tokenB.balanceOf(bob);
        uint256 amountOut = dex.swap(address(tokenA), address(tokenB), swapIn, 0);
        vm.stopPrank();

        assertGt(amountOut, 0, "swap produced no output");
        assertEq(tokenB.balanceOf(bob), balBBefore + amountOut);
    }

    function testSwapReverseDirection() public {
        // Seed pool keyed (tokenA, tokenB)
        vm.startPrank(alice);
        tokenA.approve(address(dex), LIQUIDITY_A);
        tokenB.approve(address(dex), LIQUIDITY_B);
        dex.addLiquidity(address(tokenA), address(tokenB), LIQUIDITY_A, LIQUIDITY_B);
        vm.stopPrank();

        uint256 swapIn = 5e18;

        vm.startPrank(bob);
        tokenB.approve(address(dex), swapIn);
        uint256 balABefore = tokenA.balanceOf(bob);
        uint256 amountOut = dex.swap(address(tokenB), address(tokenA), swapIn, 0);
        vm.stopPrank();

        assertGt(amountOut, 0, "reverse swap produced no output");
        assertEq(tokenA.balanceOf(bob), balABefore + amountOut);
    }

    function testSlippageReverts() public {
        vm.startPrank(alice);
        tokenA.approve(address(dex), LIQUIDITY_A);
        tokenB.approve(address(dex), LIQUIDITY_B);
        dex.addLiquidity(address(tokenA), address(tokenB), LIQUIDITY_A, LIQUIDITY_B);
        vm.stopPrank();

        vm.startPrank(bob);
        tokenA.approve(address(dex), 10e18);
        // Demand more output than the pool can possibly give
        vm.expectRevert(bytes("SLIPPAGE"));
        dex.swap(address(tokenA), address(tokenB), 10e18, type(uint256).max);
        vm.stopPrank();
    }

    // -----------------------------------------------------------------------
    // Constant-product invariant
    // -----------------------------------------------------------------------

    function testConstantProductInvariantHoldsAfterSwap() public {
        vm.startPrank(alice);
        tokenA.approve(address(dex), LIQUIDITY_A);
        tokenB.approve(address(dex), LIQUIDITY_B);
        dex.addLiquidity(address(tokenA), address(tokenB), LIQUIDITY_A, LIQUIDITY_B);
        vm.stopPrank();

        bytes32 key = keccak256(abi.encodePacked(address(tokenA), address(tokenB)));
        (uint256 rA0, uint256 rB0,) = dex.pools(key);
        uint256 kBefore = rA0 * rB0;

        vm.startPrank(bob);
        tokenA.approve(address(dex), 10e18);
        dex.swap(address(tokenA), address(tokenB), 10e18, 0);
        vm.stopPrank();

        (uint256 rA1, uint256 rB1,) = dex.pools(key);
        uint256 kAfter = rA1 * rB1;

        // k must be >= kBefore (fee revenue increases k slightly)
        assertGe(kAfter, kBefore, "constant product invariant violated");
    }
}
