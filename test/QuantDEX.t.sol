// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/QuantDEX.sol";

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
// Malicious token that attempts reentrancy on transfer()
// It holds tokenA internally and re-approves + re-calls swap during transfer.
// ---------------------------------------------------------------------------
contract MaliciousToken {
    string public name = "Evil";
    uint8  public decimals = 18;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    QuantDEX public dex;
    MockERC20 public victimToken;
    bool     public attacked;
    bool     public reentryReverted;

    constructor() {}

    function setDex(address _dex, address _victim) external {
        dex = QuantDEX(_dex);
        victimToken = MockERC20(_victim);
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    /// @dev Called by DEX when sending evil tokens to the swapper.
    ///      We attempt a reentrant swap here. The ReentrancyGuard should reject it.
    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        // Attempt reentrant swap: we (this contract) will call swap(victimToken -> evil)
        // We already have victimToken balance and have pre-approved the DEX.
        if (!attacked && address(dex) != address(0)) {
            attacked = true;
            try dex.swap(address(victimToken), address(this), 1e18, 0) {
                reentryReverted = false;
            } catch {
                reentryReverted = true;
            }
        }
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

        // Pool key uses sorted order
        (address t0, address t1) = address(tokenA) < address(tokenB)
            ? (address(tokenA), address(tokenB))
            : (address(tokenB), address(tokenA));
        (uint256 rA, uint256 rB, uint256 total) = dex.pools(keccak256(abi.encodePacked(t0, t1)));
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

        bytes32 key = keccak256(abi.encodePacked(
            address(tokenA) < address(tokenB) ? address(tokenA) : address(tokenB),
            address(tokenA) < address(tokenB) ? address(tokenB) : address(tokenA)
        ));
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

    // -----------------------------------------------------------------------
    // Security tests
    // -----------------------------------------------------------------------

    /// @dev Reentrancy: MaliciousToken tries to reenter swap() during transfer().
    ///      The ReentrancyGuard must cause the inner call to revert.
    function testReentrancyGuardBlocksAttack() public {
        MaliciousToken evil = new MaliciousToken();
        evil.setDex(address(dex), address(tokenA));

        // Seed liquidity: tokenA / evil pair
        tokenA.mint(alice, 1000e18);
        evil.mint(alice, 1000e18);

        vm.startPrank(alice);
        tokenA.approve(address(dex), 100e18);
        evil.approve(address(dex), 200e18);
        dex.addLiquidity(address(tokenA), address(evil), 100e18, 200e18);
        vm.stopPrank();

        // Give the evil contract tokenA and pre-approve DEX so its reentrant swap
        // won't fail on balance/allowance — only the ReentrancyGuard should stop it.
        tokenA.mint(address(evil), 10e18);
        vm.prank(address(evil));
        tokenA.approve(address(dex), 10e18);

        // Bob triggers the outer swap (tokenA -> evil).
        // During the DEX's evil.transfer() call, MaliciousToken will attempt
        // a reentrant swap(tokenA -> evil) from the evil contract itself.
        tokenA.mint(bob, 10e18);
        vm.startPrank(bob);
        tokenA.approve(address(dex), 10e18);
        uint256 outEvil = dex.swap(address(tokenA), address(evil), 10e18, 0);
        vm.stopPrank();

        // Outer swap must have succeeded
        assertGt(outEvil, 0, "outer swap should succeed");

        // Inner reentrant swap must have been blocked by ReentrancyGuard
        assertTrue(evil.reentryReverted(), "ReentrancyGuard did not block reentrant call");

        // Pool reserves must still be consistent (not drained)
        bytes32 key = keccak256(abi.encodePacked(
            address(tokenA) < address(evil) ? address(tokenA) : address(evil),
            address(tokenA) < address(evil) ? address(evil) : address(tokenA)
        ));
        (uint256 rA, uint256 rB,) = dex.pools(key);
        assertGt(rA, 0, "pool drained by reentrancy");
        assertGt(rB, 0, "pool drained by reentrancy");
    }

    /// @dev Donation attack: directly transfer tokens to contract, verify swap
    ///      output is unchanged (uses stored reserves, not balanceOf).
    function testDonationAttackDoesNotAffectSwapOutput() public {
        vm.startPrank(alice);
        tokenA.approve(address(dex), LIQUIDITY_A);
        tokenB.approve(address(dex), LIQUIDITY_B);
        dex.addLiquidity(address(tokenA), address(tokenB), LIQUIDITY_A, LIQUIDITY_B);
        vm.stopPrank();

        // Calculate expected swap output before donation
        uint256 swapIn = 10e18;
        uint256 reserveIn  = LIQUIDITY_A;
        uint256 reserveOut = LIQUIDITY_B;
        uint256 expectedOut = (swapIn * 997 * reserveOut) / (reserveIn * 1000 + swapIn * 997);

        // Donate tokens directly to the contract (donation attack)
        vm.startPrank(bob);
        tokenA.transfer(address(dex), 50e18); // donate tokenA directly
        vm.stopPrank();

        // Swap should still produce the same output because the contract
        // uses stored pool.reserveA/reserveB, not balanceOf.
        vm.startPrank(bob);
        tokenA.approve(address(dex), swapIn);
        uint256 actualOut = dex.swap(address(tokenA), address(tokenB), swapIn, 0);
        vm.stopPrank();

        assertEq(actualOut, expectedOut, "donation attack altered swap output");
    }

    /// @dev Slippage protection: swap where amountOut < amountOutMin must revert.
    function testSlippageProtectionExplicit() public {
        vm.startPrank(alice);
        tokenA.approve(address(dex), LIQUIDITY_A);
        tokenB.approve(address(dex), LIQUIDITY_B);
        dex.addLiquidity(address(tokenA), address(tokenB), LIQUIDITY_A, LIQUIDITY_B);
        vm.stopPrank();

        uint256 swapIn = 10e18;
        // Compute the actual output
        uint256 reserveIn  = LIQUIDITY_A;
        uint256 reserveOut = LIQUIDITY_B;
        uint256 actualOut = (swapIn * 997 * reserveOut) / (reserveIn * 1000 + swapIn * 997);

        // Demand 1 wei more than the pool will give
        uint256 tooHigh = actualOut + 1;

        vm.startPrank(bob);
        tokenA.approve(address(dex), swapIn);
        vm.expectRevert(bytes("SLIPPAGE"));
        dex.swap(address(tokenA), address(tokenB), swapIn, tooHigh);
        vm.stopPrank();
    }

    /// @dev Pool symmetry: addLiquidity(A, B) and addLiquidity(B, A) must use the
    ///      same pool (sorted keys are identical).
    function testPoolSymmetryCanonicalOrdering() public {
        // Add liquidity in (tokenA, tokenB) order
        vm.startPrank(alice);
        tokenA.approve(address(dex), LIQUIDITY_A);
        tokenB.approve(address(dex), LIQUIDITY_B);
        dex.addLiquidity(address(tokenA), address(tokenB), LIQUIDITY_A, LIQUIDITY_B);
        vm.stopPrank();

        // Add liquidity in reversed (tokenB, tokenA) order — must land in same pool
        vm.startPrank(bob);
        tokenB.approve(address(dex), 20e18);
        tokenA.approve(address(dex), 10e18);
        uint256 sharesMinted = dex.addLiquidity(address(tokenB), address(tokenA), 20e18, 10e18);
        vm.stopPrank();

        assertGt(sharesMinted, 0, "reversed add yielded no shares");

        // Both should map to the same pool key
        bytes32 key = keccak256(abi.encodePacked(
            address(tokenA) < address(tokenB) ? address(tokenA) : address(tokenB),
            address(tokenA) < address(tokenB) ? address(tokenB) : address(tokenA)
        ));
        (,, uint256 total) = dex.pools(key);
        // Total shares must reflect contributions from both alice and bob
        assertGt(total, 0, "pool has no shares after both deposits");

        // Verify there is no separate pool for the reversed key
        bytes32 reversedKey = keccak256(abi.encodePacked(
            address(tokenA) < address(tokenB) ? address(tokenB) : address(tokenA),
            address(tokenA) < address(tokenB) ? address(tokenA) : address(tokenB)
        ));
        // reversed key is the same as canonical key when tokens are identical;
        // but if tokenA != tokenB and we truly reversed, they must differ —
        // verify the contract only populated one.
        if (reversedKey != key) {
            (uint256 rrA,,) = dex.pools(reversedKey);
            assertEq(rrA, 0, "duplicate pool created for reversed token order");
        }
    }
}
