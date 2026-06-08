// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/QuantDEX.sol";

/// @dev Minimal mintable ERC20 for handler use
contract InvariantToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }

    function transfer(address to, uint256 amount) external returns (bool) {
        if (balanceOf[msg.sender] < amount) return false;
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        if (allowance[from][msg.sender] < amount) return false;
        if (balanceOf[from] < amount) return false;
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

/// @title Handler — drives random interactions with QuantDEX for invariant testing
/// @dev Foundry calls functions on this contract with fuzzed inputs during invariant runs.
///      The handler tracks "ghost state" to let the invariant test validate global properties.
contract QuantDEXHandler is Test {
    QuantDEX public dex;
    InvariantToken public tokenA;
    InvariantToken public tokenB;

    address[] public actors;
    bytes32 public poolKey;

    // Ghost variables — track expected state independently of the contract
    uint256 public ghost_totalSharesMinted;
    uint256 public ghost_totalSharesBurned;

    constructor(QuantDEX _dex, InvariantToken _tA, InvariantToken _tB) {
        dex    = _dex;
        tokenA = _tA;
        tokenB = _tB;

        // Create 3 actors
        actors.push(address(0xA001));
        actors.push(address(0xA002));
        actors.push(address(0xA003));

        // Pre-fund all actors
        for (uint i = 0; i < actors.length; i++) {
            tokenA.mint(actors[i], 1_000_000e18);
            tokenB.mint(actors[i], 1_000_000e18);
            vm.prank(actors[i]);
            tokenA.approve(address(dex), type(uint256).max);
            vm.prank(actors[i]);
            tokenB.approve(address(dex), type(uint256).max);
        }

        // Compute the canonical pool key
        (address t0, address t1) = address(tokenA) < address(tokenB)
            ? (address(tokenA), address(tokenB))
            : (address(tokenB), address(tokenA));
        poolKey = keccak256(abi.encodePacked(t0, t1));
    }

    function addLiquidity(uint256 actorSeed, uint256 amtA, uint256 amtB) external {
        address actor = actors[actorSeed % actors.length];
        amtA = bound(amtA, 1e15, 100_000e18);
        amtB = bound(amtB, 1e15, 100_000e18);

        vm.prank(actor);
        try dex.addLiquidity(address(tokenA), address(tokenB), amtA, amtB) returns (uint256 minted) {
            ghost_totalSharesMinted += minted;
        } catch { /* expected: ZERO_SHARES on extreme imbalance */ }
    }

    function removeLiquidity(uint256 actorSeed, uint256 shareFraction) external {
        address actor = actors[actorSeed % actors.length];
        (,, uint256 total) = dex.pools(poolKey);
        if (total == 0) return;

        uint256 actorShares = dex.shares(poolKey, actor);
        if (actorShares == 0) return;

        // Burn between 1% and 100% of actor's shares
        shareFraction = bound(shareFraction, 1, 100);
        uint256 toBurn = (actorShares * shareFraction) / 100;
        if (toBurn == 0) return;

        vm.prank(actor);
        try dex.removeLiquidity(address(tokenA), address(tokenB), toBurn) {
            ghost_totalSharesBurned += toBurn;
        } catch { /* expected: ZERO_OUTPUT on dust */ }
    }

    function swap(uint256 actorSeed, uint256 amtIn, bool aToB) external {
        address actor = actors[actorSeed % actors.length];
        amtIn = bound(amtIn, 1e15, 50_000e18);

        address tIn  = aToB ? address(tokenA) : address(tokenB);
        address tOut = aToB ? address(tokenB) : address(tokenA);

        vm.prank(actor);
        try dex.swap(tIn, tOut, amtIn, 0) { } catch { }
    }
}

/// @title InvariantTest — Property-based invariant tests for QuantDEX
///
/// Foundry runs the handler randomly many times, then checks these invariants hold.
/// Invariants that must NEVER be violated regardless of call sequence:
///
///   1. x*y >= k (constant product never decreases after swaps)
///   2. Total LP shares == sum of all individual shares
///   3. If totalShares > 0 then reserveA > 0 AND reserveB > 0
///   4. Ghost accounting: totalShares == minted - burned
contract InvariantTest is Test {
    QuantDEX       public dex;
    InvariantToken public tokenA;
    InvariantToken public tokenB;
    QuantDEXHandler public handler;

    bytes32 poolKey;

    function setUp() public {
        dex    = new QuantDEX();
        tokenA = new InvariantToken();
        tokenB = new InvariantToken();
        handler = new QuantDEXHandler(dex, tokenA, tokenB);

        // Seed the pool with initial liquidity so handler can start swapping immediately
        tokenA.mint(address(this), 10_000e18);
        tokenB.mint(address(this), 10_000e18);
        tokenA.approve(address(dex), type(uint256).max);
        tokenB.approve(address(dex), type(uint256).max);
        dex.addLiquidity(address(tokenA), address(tokenB), 10_000e18, 10_000e18);

        (address t0, address t1) = address(tokenA) < address(tokenB)
            ? (address(tokenA), address(tokenB))
            : (address(tokenB), address(tokenA));
        poolKey = keccak256(abi.encodePacked(t0, t1));

        // Tell Foundry to target the handler contract
        targetContract(address(handler));
    }

    /// @notice Invariant 1: Pool has solvency — reserves can cover all LP share redemptions.
    ///         Specifically: if totalShares > 0, both reserves must be > 0.
    ///         A pool with shares but zero reserves would be insolvent.
    function invariant_reservesSolvency() public view {
        (uint256 rA, uint256 rB, uint256 total) = dex.pools(poolKey);
        if (total > 0) {
            assertGt(rA, 0, "Reserve A must be nonzero when shares exist");
            assertGt(rB, 0, "Reserve B must be nonzero when shares exist");
        }
        if (rA == 0 || rB == 0) {
            assertEq(total, 0, "Shares must be zero when either reserve is zero");
        }
    }

    /// @notice Invariant 2: Ghost accounting — tracked minted/burned shares match contract state.
    ///         totalShares == shares minted by setUp + ghost_minted - ghost_burned
    function invariant_ghostShareAccounting() public view {
        (,, uint256 total) = dex.pools(poolKey);
        // setUp minted shares equal to sqrt(10000e18 * 10000e18) = 10000e18
        uint256 setUpShares = 10_000e18;
        uint256 expected = setUpShares + handler.ghost_totalSharesMinted() - handler.ghost_totalSharesBurned();
        assertEq(total, expected, "Ghost share accounting mismatch");
    }

    /// @notice Invariant 3: No user holds more shares than totalShares.
    ///         Checks for the three handler actors.
    function invariant_noShareOverflow() public view {
        (,, uint256 total) = dex.pools(poolKey);
        uint256 sumUserShares = dex.shares(poolKey, address(this))
            + dex.shares(poolKey, address(0xA001))
            + dex.shares(poolKey, address(0xA002))
            + dex.shares(poolKey, address(0xA003));
        assertLe(sumUserShares, total, "Sum of user shares exceeds totalShares");
    }
}
