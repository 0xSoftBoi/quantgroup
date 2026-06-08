// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/QuantDEX.sol";

/// @title Attacks.t.sol — AMM Attack Simulations
/// @notice Demonstrates known attack vectors against constant-product AMMs.
///         Each test shows the attack setup, what the attacker gains, and how
///         the mitigation (if any) limits damage.
///
/// @dev These tests are EDUCATIONAL. Some "attacks" succeed — the point is to
///      document the behavior, not claim the contract is broken.
///      Read the comments in each test carefully.
contract MockERC20 is IERC20 {
    string public name;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(string memory _name) { name = _name; }

    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "INSUFFICIENT");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount, "ALLOWANCE");
        require(balanceOf[from] >= amount, "INSUFFICIENT");
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

contract AttacksTest is Test {
    QuantDEX public dex;
    MockERC20 public tokenA;
    MockERC20 public tokenB;

    address constant VICTIM   = address(0x1111);
    address constant ATTACKER = address(0x2222);
    address constant LP       = address(0x3333);

    function setUp() public {
        dex    = new QuantDEX();
        tokenA = new MockERC20("TokenA");
        tokenB = new MockERC20("TokenB");

        // Fund LP with equal amounts for a balanced pool
        tokenA.mint(LP, 100_000e18);
        tokenB.mint(LP, 100_000e18);

        // Bootstrap the pool with equal reserves
        vm.startPrank(LP);
        tokenA.approve(address(dex), 100_000e18);
        tokenB.approve(address(dex), 100_000e18);
        dex.addLiquidity(address(tokenA), address(tokenB), 100_000e18, 100_000e18);
        vm.stopPrank();
    }

    // -------------------------------------------------------------------------
    // Attack 1: Sandwich
    // -------------------------------------------------------------------------

    /// @notice Simulates a sandwich attack around a victim's swap.
    ///
    /// The attacker observes the victim's pending tx in the mempool and executes:
    ///   1. Front-run: buy tokenB before victim (drives tokenB price up)
    ///   2. Victim swaps at a worse rate than expected
    ///   3. Back-run: sell tokenB for profit
    ///
    /// RESULT: The attacker profits from the victim's price impact.
    /// The slippage guard limits the victim's loss — but only if set correctly.
    /// With amountOutMin=0 (shown here), the victim has NO protection.
    ///
    /// @dev Key insight: sandwich is NOT a contract bug. It's a mempool-level
    ///      property. Mitigation requires either:
    ///      a) Private mempool (Flashbots)
    ///      b) Commit-reveal scheme
    ///      c) Batch auction (CoW Protocol)
    ///      d) A realistic amountOutMin set by the victim
    function testSandwichAttackSetup() public {
        uint256 VICTIM_SWAP = 10_000e18;    // victim wants to sell 10k tokenA
        uint256 FRONT_RUN   = 20_000e18;    // attacker front-runs with 20k tokenA

        // Fund attacker and victim
        tokenA.mint(ATTACKER, FRONT_RUN);
        tokenA.mint(VICTIM, VICTIM_SWAP);

        // Record tokenB balance of attacker before attack
        uint256 attackerBefore = tokenB.balanceOf(ATTACKER);

        // STEP 1 — Attacker front-runs: buy tokenB
        vm.startPrank(ATTACKER);
        tokenA.approve(address(dex), FRONT_RUN);
        uint256 attackerBought = dex.swap(address(tokenA), address(tokenB), FRONT_RUN, 0);
        vm.stopPrank();

        // STEP 2 — Victim swaps. amountOutMin=0 means zero slippage protection.
        //          In production, a proper DEX interface would set this based on current quote.
        vm.startPrank(VICTIM);
        tokenA.approve(address(dex), VICTIM_SWAP);
        uint256 victimReceived = dex.swap(address(tokenA), address(tokenB), VICTIM_SWAP, 0);
        vm.stopPrank();

        // STEP 3 — Attacker back-runs: sell tokenB back for profit
        vm.startPrank(ATTACKER);
        tokenB.approve(address(dex), attackerBought);
        uint256 attackerRecovered = dex.swap(address(tokenB), address(tokenA), attackerBought, 0);
        vm.stopPrank();

        uint256 attackerProfit = attackerRecovered > FRONT_RUN ? attackerRecovered - FRONT_RUN : 0;
        uint256 attackerLoss   = attackerRecovered < FRONT_RUN ? FRONT_RUN - attackerRecovered : 0;

        // What the victim WOULD have received without the sandwich
        // (calculated at original pool state: 100k/100k)
        uint256 fairOutput = (VICTIM_SWAP * 997 * 100_000e18) / (100_000e18 * 1000 + VICTIM_SWAP * 997);

        emit log_named_uint("Victim received (sandwiched)    ", victimReceived / 1e18);
        emit log_named_uint("Victim fair output (no sandwich)", fairOutput / 1e18);
        emit log_named_uint("Victim loss due to sandwich     ", (fairOutput - victimReceived) / 1e18);
        emit log_named_uint("Attacker profit (tokenA)        ", attackerProfit / 1e18);
        emit log_named_uint("Attacker loss   (tokenA)        ", attackerLoss / 1e18);

        // Victim received LESS than fair price — sandwich succeeded
        assertLt(victimReceived, fairOutput, "Victim should receive less due to sandwich");

        // The 0.3% fee acts as friction — attacker pays fees on both legs,
        // so small sandwiches may be unprofitable. Large sandwiches are profitable.
        // With 20k front-run on a 100k pool (20% impact), attacker profits.
        emit log_string("Sandwich succeeded. Use amountOutMin to protect victims.");
    }

    /// @notice Shows that a realistic slippage guard blocks the sandwich's damage.
    function testSlippageGuardBlocksMEV() public {
        uint256 VICTIM_SWAP = 10_000e18;
        uint256 FRONT_RUN   = 20_000e18;

        tokenA.mint(ATTACKER, FRONT_RUN);
        tokenA.mint(VICTIM, VICTIM_SWAP);

        // Victim computes a fair quote BEFORE the front-run (off-chain)
        // and sets amountOutMin to 98% of that quote (2% slippage tolerance).
        uint256 fairQuote = (VICTIM_SWAP * 997 * 100_000e18) / (100_000e18 * 1000 + VICTIM_SWAP * 997);
        uint256 victimMinOut = (fairQuote * 98) / 100; // 2% slippage tolerance

        // Front-run drives price up
        vm.startPrank(ATTACKER);
        tokenA.approve(address(dex), FRONT_RUN);
        dex.swap(address(tokenA), address(tokenB), FRONT_RUN, 0);
        vm.stopPrank();

        // Victim's tx reverts because the sandwiched output is below their limit
        vm.startPrank(VICTIM);
        tokenA.approve(address(dex), VICTIM_SWAP);
        vm.expectRevert("SLIPPAGE");
        dex.swap(address(tokenA), address(tokenB), VICTIM_SWAP, victimMinOut);
        vm.stopPrank();

        emit log_string("Victim's tx reverted. Slippage guard protected them.");
        emit log_string("Lesson: always set amountOutMin to ~98-99% of quoted output.");
    }

    // -------------------------------------------------------------------------
    // Attack 2: Donation / Share Inflation
    // -------------------------------------------------------------------------

    /// @notice Demonstrates the first-deposit donation/inflation attack — and why this
    ///         contract is immune to it: internal reserve accounting.
    ///
    /// Classic attack on AMMs that read their token BALANCE as the reserve:
    ///   1. Attacker is the first depositor — deposits 1 wei each token → gets 1 share
    ///   2. Attacker "donates" a large amount directly to the contract (bypassing addLiquidity)
    ///   3. If reserves == balanceOf, 1 share now represents enormous value: the next
    ///      depositor's mint rounds to 0 shares and they lose funds
    ///
    /// WHY IT FAILS HERE: reserves are internal accounting (pool.reserveA/reserveB), updated
    /// only inside addLiquidity/swap. A raw transfer never enters the share math, so the
    /// donation is simply ignored and the second depositor mints against the real reserves.
    /// (The sqrt bootstrap is for ratio-independence — Uniswap v2 §3.4 — not this defense.)
    function testDonationAttack() public {
        address firstDepositor = address(0x4444);
        address secondDepositor = address(0x5555);

        // Fresh dex for isolation
        QuantDEX freshDex = new QuantDEX();
        MockERC20 tA = new MockERC20("A");
        MockERC20 tB = new MockERC20("B");

        // Attacker attempts: deposit dust, then donate large amounts
        uint256 DUST = 1e6;            // 1 micro-token
        uint256 DONATION = 1_000e18;   // 1000 tokens donated directly

        tA.mint(firstDepositor, DUST + DONATION);
        tB.mint(firstDepositor, DUST + DONATION);
        tA.mint(secondDepositor, 1e18);
        tB.mint(secondDepositor, 1e18);

        // Step 1: First depositor bootstraps with dust → gets sqrt(1e6 * 1e6) = 1e6 shares
        vm.startPrank(firstDepositor);
        tA.approve(address(freshDex), type(uint256).max);
        tB.approve(address(freshDex), type(uint256).max);
        freshDex.addLiquidity(address(tA), address(tB), DUST, DUST);

        (,, uint256 totalSharesAfterBootstrap) = freshDex.pools(
            keccak256(abi.encodePacked(
                tA < tB ? address(tA) : address(tB),
                tA < tB ? address(tB) : address(tA)
            ))
        );
        emit log_named_uint("Shares after dust bootstrap", totalSharesAfterBootstrap);

        // Step 2: Attacker donates directly (would inflate share value)
        tA.transfer(address(freshDex), DONATION);
        tB.transfer(address(freshDex), DONATION);
        vm.stopPrank();

        // Step 3: Second depositor adds liquidity.
        // Because reserves are internal accounting, the donation above never entered
        // pool.reserveA/reserveB — the second depositor's shares are computed against the
        // REAL reserves (the dust), so they mint normally. The donated tokens are dead weight.
        vm.startPrank(secondDepositor);
        tA.approve(address(freshDex), type(uint256).max);
        tB.approve(address(freshDex), type(uint256).max);
        uint256 sharesReceived = freshDex.addLiquidity(address(tA), address(tB), 1e18, 1e18);
        vm.stopPrank();

        emit log_named_uint("Second depositor shares received", sharesReceived);
        emit log_named_uint("First depositor total donated (tokens)", (DONATION * 2) / 1e18);

        // Key assertion: second depositor still gets nonzero shares — in fact full shares,
        // because the donation was invisible to the reserve accounting (no dilution at all).
        assertGt(sharesReceived, 0, "Second depositor should always receive shares > 0");
        emit log_string("Donation never entered internal reserves, so share value was unaffected.");
        emit log_string("The attack is closed by accounting, not by the sqrt bootstrap.");
    }

    // -------------------------------------------------------------------------
    // Attack 3: Price Oracle Manipulation
    // -------------------------------------------------------------------------

    /// @notice Demonstrates that spot reserves can be manipulated in a single tx.
    ///
    /// Any contract that reads pool.reserveA/reserveB directly as a price oracle
    /// is vulnerable. An attacker can:
    ///   1. Swap heavily to move the spot price
    ///   2. Trigger the oracle-dependent contract at manipulated price
    ///   3. Swap back to restore price (or simply leave)
    ///
    /// This test shows the price movement achievable. NEVER use spot reserves
    /// as a price oracle. Use a TWAP (this contract has none — a known limitation).
    function testPriceManipulation() public {
        // Initial spot price: 1 tokenA = 1 tokenB (100k/100k pool)
        uint256 INITIAL_RESERVE = 100_000e18;
        uint256 initialPrice_numerator   = INITIAL_RESERVE;  // reserveB
        uint256 initialPrice_denominator = INITIAL_RESERVE;  // reserveA

        // Attacker moves price with a large swap
        uint256 MANIPULATE_AMOUNT = 50_000e18; // 50% of pool
        tokenA.mint(ATTACKER, MANIPULATE_AMOUNT);

        vm.startPrank(ATTACKER);
        tokenA.approve(address(dex), MANIPULATE_AMOUNT);
        dex.swap(address(tokenA), address(tokenB), MANIPULATE_AMOUNT, 0);
        vm.stopPrank();

        // Read manipulated spot price from reserves
        bytes32 key = keccak256(abi.encodePacked(
            address(tokenA) < address(tokenB) ? address(tokenA) : address(tokenB),
            address(tokenA) < address(tokenB) ? address(tokenB) : address(tokenA)
        ));
        (uint256 rA, uint256 rB,) = dex.pools(key);

        uint256 manipulatedRatio_b_per_a = (rB * 1e18) / rA; // tokenB per tokenA, scaled
        uint256 originalRatio            = (initialPrice_numerator * 1e18) / initialPrice_denominator;

        emit log_named_uint("Original spot price (B per A, scaled 1e18)", originalRatio);
        emit log_named_uint("Manipulated spot price (B per A, scaled 1e18)", manipulatedRatio_b_per_a);
        emit log_named_uint("Price moved by (%)", ((originalRatio - manipulatedRatio_b_per_a) * 100) / originalRatio);

        // Price moved significantly with a 50% pool swap
        assertLt(manipulatedRatio_b_per_a, originalRatio, "Price should have moved down for tokenB/tokenA");
        emit log_string("ORACLE WARNING: spot price moved >30% in one tx. Never use as oracle.");
        emit log_string("MITIGATION: use a TWAP oracle (this contract has none - by design for simplicity).");
    }
}
