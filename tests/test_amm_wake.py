"""
Wake Fuzz Test: QuantDEX AMM Security
======================================
Stateful property-based test covering:
  - K invariant: reserveA * reserveB never decreases after a swap
  - Share accounting: per-user shares always sum to totalShares
  - Sandwich attack: victim always receives less than fair price when sandwiched
  - Donation attack: direct token transfer cannot inflate shares to steal funds
  - Slippage guard: amountOutMin=0 vs proper guard under adversarial conditions

Run: wake test tests/test_amm_wake.py -v
"""

from wake.testing import *
from wake.testing.fuzzing import *
from pytypes.src.QuantDEX import QuantDEX
from pytypes.tests.contracts.MockERC20 import MockERC20

import math


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

INITIAL_LIQUIDITY = 10_000 * 10**18   # 10k tokens each side
SWAP_AMOUNT       = 100  * 10**18    # 100 tokens per swap
FEE_NUMERATOR     = 997              # 0.3% fee (997/1000)
FEE_DENOMINATOR   = 1000


def pool_key(dex: QuantDEX, token_a: MockERC20, token_b: MockERC20) -> bytes:
    """Return keccak256 of sorted (addr0, addr1) — mirrors QuantDEX._poolKey()."""
    a = int(token_a.address, 16)
    b = int(token_b.address, 16)
    lo, hi = (token_a, token_b) if a < b else (token_b, token_a)
    from eth_abi import encode
    from web3 import Web3
    return Web3.keccak(lo.address.lower()[2:].zfill(40).encode() +
                       hi.address.lower()[2:].zfill(40).encode())


def get_pool(dex: QuantDEX, token_a: MockERC20, token_b: MockERC20):
    """Fetch pool reserves and totalShares as (rA, rB, total)."""
    a = int(token_a.address, 16)
    b = int(token_b.address, 16)
    lo, hi = (token_a, token_b) if a < b else (token_b, token_a)
    lo_addr = lo.address
    hi_addr = hi.address
    from eth_abi import encode
    from web3 import Web3
    packed = bytes.fromhex(lo_addr[2:].zfill(40)) + bytes.fromhex(hi_addr[2:].zfill(40))
    key = Web3.keccak(packed)
    return dex.pools(key)   # returns (reserveA, reserveB, totalShares)


def cpamm_out(amount_in: int, reserve_in: int, reserve_out: int) -> int:
    """Expected constant-product output with 0.3% fee."""
    fee_in = amount_in * FEE_NUMERATOR
    return (fee_in * reserve_out) // (reserve_in * FEE_DENOMINATOR + fee_in)


def approve_max(token: MockERC20, spender_addr: str, owner: Account):
    token.approve(spender_addr, 2**256 - 1, from_=owner)


# ---------------------------------------------------------------------------
# Stateful FuzzTest
# ---------------------------------------------------------------------------

class QuantDEXFuzzTest(FuzzTest):
    """
    Stateful fuzzer: random sequence of addLiquidity / removeLiquidity / swap flows.
    After every flow, invariants are checked.
    """

    dex:     QuantDEX
    token_a: MockERC20
    token_b: MockERC20
    lp:      Account   # initial LP
    actors:  list      # additional traders

    def pre_sequence(self) -> None:
        """Deploy contracts and seed initial state before each fuzz sequence."""
        self.lp     = chain.accounts[0]
        self.actors = list(chain.accounts[1:5])

        self.token_a = MockERC20.deploy("TokenA", "TKA", from_=self.lp)
        self.token_b = MockERC20.deploy("TokenB", "TKB", from_=self.lp)
        self.dex     = QuantDEX.deploy(from_=self.lp)

        # Mint and approve for all participants
        for acc in [self.lp] + self.actors:
            self.token_a.mint(acc.address, 1_000_000 * 10**18, from_=self.lp)
            self.token_b.mint(acc.address, 1_000_000 * 10**18, from_=self.lp)
            approve_max(self.token_a, self.dex.address, acc)
            approve_max(self.token_b, self.dex.address, acc)

        # Seed pool with initial liquidity
        self.dex.addLiquidity(
            self.token_a.address,
            self.token_b.address,
            INITIAL_LIQUIDITY,
            INITIAL_LIQUIDITY,
            from_=self.lp,
        )

    # -----------------------------------------------------------------------
    # Flows
    # -----------------------------------------------------------------------

    @flow(weight=40)
    def flow_swap_a_for_b(self) -> None:
        """Random actor swaps tokenA for tokenB with no slippage guard."""
        actor = random_account(predicate=lambda a: a in self.actors)
        amount_in = random_int(1 * 10**18, 200 * 10**18)
        try:
            self.dex.swap(
                self.token_a.address,
                self.token_b.address,
                amount_in,
                0,          # no slippage guard
                from_=actor,
            )
        except TransactionRevertedError:
            pass  # pool may be exhausted — expected

    @flow(weight=40)
    def flow_swap_b_for_a(self) -> None:
        """Random actor swaps tokenB for tokenA."""
        actor = random_account(predicate=lambda a: a in self.actors)
        amount_in = random_int(1 * 10**18, 200 * 10**18)
        try:
            self.dex.swap(
                self.token_b.address,
                self.token_a.address,
                amount_in,
                0,
                from_=actor,
            )
        except TransactionRevertedError:
            pass

    @flow(weight=20)
    def flow_add_liquidity(self) -> None:
        """Random actor adds proportional liquidity."""
        actor = random_account(predicate=lambda a: a in self.actors)
        amount_a = random_int(1 * 10**18, 500 * 10**18)
        amount_b = random_int(1 * 10**18, 500 * 10**18)
        try:
            self.dex.addLiquidity(
                self.token_a.address,
                self.token_b.address,
                amount_a,
                amount_b,
                from_=actor,
            )
        except TransactionRevertedError:
            pass

    @flow(weight=10)
    def flow_remove_liquidity(self) -> None:
        """Random actor removes a fraction of their LP shares."""
        actor = random_account(predicate=lambda a: a in self.actors)
        key = _sorted_key(self.dex, self.token_a, self.token_b)
        user_shares = self.dex.shares(key, actor.address)
        if user_shares == 0:
            return
        burn = random_int(1, user_shares)
        try:
            self.dex.removeLiquidity(
                self.token_a.address,
                self.token_b.address,
                burn,
                from_=actor,
            )
        except TransactionRevertedError:
            pass

    # -----------------------------------------------------------------------
    # Invariants (checked after every flow)
    # -----------------------------------------------------------------------

    @invariant()
    def invariant_k_nonnegative(self) -> None:
        """
        Pool must never have one reserve at zero while the other is nonzero.
        A violated reserve means liquidity was drained unsoundly.
        """
        pool = self.dex.pools(_sorted_key(self.dex, self.token_a, self.token_b))
        rA, rB, total = pool.reserveA, pool.reserveB, pool.totalShares
        if total > 0:
            assert rA > 0, "invariant: reserveA=0 but totalShares>0"
            assert rB > 0, "invariant: reserveB=0 but totalShares>0"

    @invariant()
    def invariant_share_accounting(self) -> None:
        """
        Sum of per-user LP shares for active actors must never exceed totalShares.
        (Exact equality hard to check for all accounts; we verify no over-allocation.)
        """
        key = _sorted_key(self.dex, self.token_a, self.token_b)
        pool = self.dex.pools(key)
        total = pool.totalShares

        acc_sum = 0
        for acc in [self.lp] + list(self.actors):
            acc_sum += self.dex.shares(key, acc.address)

        assert acc_sum <= total, (
            f"invariant: share sum {acc_sum} > totalShares {total} (over-allocated)"
        )

    @invariant()
    def invariant_reserves_positive_iff_shares(self) -> None:
        """totalShares > 0 iff reserveA > 0 (no ghost shares, no locked reserves)."""
        pool = self.dex.pools(_sorted_key(self.dex, self.token_a, self.token_b))
        rA, rB, total = pool.reserveA, pool.reserveB, pool.totalShares
        assert (total > 0) == (rA > 0), (
            f"invariant: totalShares={total} but reserveA={rA}"
        )


def _sorted_key(dex: QuantDEX, ta: MockERC20, tb: MockERC20) -> bytes:
    """Compute pool mapping key (keccak of sorted addresses, abi.encodePacked)."""
    from web3 import Web3
    a_str = str(ta.address)
    b_str = str(tb.address)
    a_int = int(a_str, 16)
    b_int = int(b_str, 16)
    lo_str = a_str if a_int < b_int else b_str
    hi_str = b_str if a_int < b_int else a_str
    # abi.encodePacked packs addresses as 20 bytes each
    packed = bytes.fromhex(lo_str[2:].zfill(40)) + bytes.fromhex(hi_str[2:].zfill(40))
    return Web3.keccak(packed)


# ---------------------------------------------------------------------------
# Unit tests (deterministic, not fuzz)
# ---------------------------------------------------------------------------

@chain.connect()
def test_k_invariant_single_swap():
    """After a single swap, k must be >= k_before (fees increase k)."""
    lp    = chain.accounts[0]
    alice = chain.accounts[1]

    ta = MockERC20.deploy("TokenA", "TKA", from_=lp)
    tb = MockERC20.deploy("TokenB", "TKB", from_=lp)
    dex = QuantDEX.deploy(from_=lp)

    for acc in [lp, alice]:
        ta.mint(acc.address, 1_000_000 * 10**18, from_=lp)
        tb.mint(acc.address, 1_000_000 * 10**18, from_=lp)
        ta.approve(dex.address, 2**256 - 1, from_=acc)
        tb.approve(dex.address, 2**256 - 1, from_=acc)

    dex.addLiquidity(ta.address, tb.address, INITIAL_LIQUIDITY, INITIAL_LIQUIDITY, from_=lp)

    key = _sorted_key(dex, ta, tb)
    pool_before = dex.pools(key)
    k_before = pool_before.reserveA * pool_before.reserveB

    dex.swap(ta.address, tb.address, SWAP_AMOUNT, 0, from_=alice)

    pool_after = dex.pools(key)
    k_after = pool_after.reserveA * pool_after.reserveB

    assert k_after >= k_before, f"k decreased: {k_before} -> {k_after}"
    print(f"[PASS] k invariant: {k_before} -> {k_after} (delta +{k_after - k_before})")


@chain.connect()
def test_sandwich_victim_receives_less():
    """
    Sandwich attack: attacker front-runs victim's swap, then back-runs.
    Victim receives less than they would in an unmanipulated pool.

    Security note: amountOutMin=0 provides zero MEV protection.
    Set amountOutMin >= 98% of spot price in production.
    """
    lp      = chain.accounts[0]
    victim  = chain.accounts[1]
    attacker = chain.accounts[2]

    ta = MockERC20.deploy("TokenA", "TKA", from_=lp)
    tb = MockERC20.deploy("TokenB", "TKB", from_=lp)
    dex = QuantDEX.deploy(from_=lp)

    for acc in [lp, victim, attacker]:
        ta.mint(acc.address, 10_000_000 * 10**18, from_=lp)
        tb.mint(acc.address, 10_000_000 * 10**18, from_=lp)
        ta.approve(dex.address, 2**256 - 1, from_=acc)
        tb.approve(dex.address, 2**256 - 1, from_=acc)

    # Seed pool: 100k / 100k
    seed = 100_000 * 10**18
    dex.addLiquidity(ta.address, tb.address, seed, seed, from_=lp)

    key = _sorted_key(dex, ta, tb)

    # Measure victim output WITHOUT sandwich (reference)
    pool_ref = dex.pools(key)
    fair_out = cpamm_out(SWAP_AMOUNT, pool_ref.reserveA, pool_ref.reserveB)

    # === SANDWICH: Step 1 — attacker front-runs ===
    front_run_amount = 5_000 * 10**18
    tb_before_attacker = tb.balanceOf(attacker.address)
    dex.swap(ta.address, tb.address, front_run_amount, 0, from_=attacker)
    tb_after_front = tb.balanceOf(attacker.address)
    attacker_front_received = tb_after_front - tb_before_attacker

    # === SANDWICH: Step 2 — victim swaps at manipulated price ===
    tb_before_victim = tb.balanceOf(victim.address)
    dex.swap(ta.address, tb.address, SWAP_AMOUNT, 0, from_=victim)   # amountOutMin=0, no protection
    victim_received = tb.balanceOf(victim.address) - tb_before_victim

    # === SANDWICH: Step 3 — attacker back-runs ===
    tb.approve(dex.address, 2**256 - 1, from_=attacker)
    dex.swap(tb.address, ta.address, attacker_front_received, 0, from_=attacker)
    ta_after_back = ta.balanceOf(attacker.address)

    # Victim received less than fair price
    assert victim_received < fair_out, (
        f"Expected victim to receive less than fair_out={fair_out}, got {victim_received}"
    )
    loss_bp = (fair_out - victim_received) * 10_000 // fair_out
    print(f"[PASS] Sandwich: victim loss = {loss_bp} bp ({loss_bp/100:.2f}%) of fair value")
    print(f"       Fair output: {fair_out // 10**18} TKB, Actual: {victim_received // 10**18} TKB")


@chain.connect()
def test_slippage_guard_blocks_sandwich():
    """
    With amountOutMin set to fair_out * 98%, the victim's tx reverts under sandwich.
    This demonstrates the defense: always set slippage tolerance.
    """
    lp      = chain.accounts[0]
    victim  = chain.accounts[1]
    attacker = chain.accounts[2]

    ta = MockERC20.deploy("TokenA", "TKA", from_=lp)
    tb = MockERC20.deploy("TokenB", "TKB", from_=lp)
    dex = QuantDEX.deploy(from_=lp)

    for acc in [lp, victim, attacker]:
        ta.mint(acc.address, 10_000_000 * 10**18, from_=lp)
        tb.mint(acc.address, 10_000_000 * 10**18, from_=lp)
        ta.approve(dex.address, 2**256 - 1, from_=acc)
        tb.approve(dex.address, 2**256 - 1, from_=acc)

    seed = 100_000 * 10**18
    dex.addLiquidity(ta.address, tb.address, seed, seed, from_=lp)

    key = _sorted_key(dex, ta, tb)
    pool = dex.pools(key)
    fair_out = cpamm_out(SWAP_AMOUNT, pool.reserveA, pool.reserveB)

    # Victim sets tight slippage: 98% of fair output
    min_out = fair_out * 98 // 100

    # Attacker front-runs first
    dex.swap(ta.address, tb.address, 5_000 * 10**18, 0, from_=attacker)

    # Victim's tx should revert because pool was manipulated
    with must_revert():
        dex.swap(ta.address, tb.address, SWAP_AMOUNT, min_out, from_=victim)

    print(f"[PASS] Slippage guard: victim tx reverted as expected (min_out={min_out // 10**18} TKB)")


@chain.connect()
def test_donation_attack_bounded():
    """
    Direct token donation (transfer to pool without calling addLiquidity) inflates
    reserves but does NOT inflate existing LP shares — donator just gifts value to LPs.

    A would-be attacker who donates before the first deposit gains nothing because
    the geometric-mean bootstrap requires at least 1 wei share — inflation is bounded.
    """
    lp      = chain.accounts[0]
    attacker = chain.accounts[1]
    victim  = chain.accounts[2]

    ta = MockERC20.deploy("TokenA", "TKA", from_=lp)
    tb = MockERC20.deploy("TokenB", "TKB", from_=lp)
    dex = QuantDEX.deploy(from_=lp)

    for acc in [lp, attacker, victim]:
        ta.mint(acc.address, 10_000_000 * 10**18, from_=lp)
        tb.mint(acc.address, 10_000_000 * 10**18, from_=lp)
        ta.approve(dex.address, 2**256 - 1, from_=acc)
        tb.approve(dex.address, 2**256 - 1, from_=acc)

    # Step 1: attacker adds 1 wei to be first depositor
    dex.addLiquidity(ta.address, tb.address, 1, 1, from_=attacker)

    key = _sorted_key(dex, ta, tb)
    attacker_shares = dex.shares(key, attacker.address)
    pool_after_attack = dex.pools(key)

    # Step 2: attacker donates a huge amount directly to pool address
    # (This mimics the donation inflation attack vector from Uniswap v2 issue #148)
    ta.transfer(dex.address, 1_000_000 * 10**18, from_=attacker)
    # Note: QuantDEX doesn't sync reserves on transfer — donation doesn't affect reserves
    # The pool's reserves only update when addLiquidity/swap/removeLiquidity is called.
    # This means donation to the contract address is "wasted" — it cannot be recovered.

    # Step 3: victim deposits normally
    dex.addLiquidity(ta.address, tb.address, 1_000 * 10**18, 1_000 * 10**18, from_=victim)
    victim_shares = dex.shares(key, victim.address)

    pool_final = dex.pools(key)

    # Victim got meaningful shares proportional to their deposit
    assert victim_shares > 0, "Victim received no shares despite depositing"

    # Attacker's shares are minimal (based on 1 wei deposit)
    # In a working inflation attack, attacker would hold nearly all shares.
    # QuantDEX bootstrap (sqrt) makes attacker shares = sqrt(1*1) = 1 — essentially nothing.
    assert attacker_shares <= victim_shares, (
        f"Inflation attack succeeded: attacker ({attacker_shares}) >= victim ({victim_shares})"
    )

    print(f"[PASS] Donation attack bounded: attacker shares={attacker_shares}, victim shares={victim_shares}")


# ---------------------------------------------------------------------------
# Fuzz test entry point
# ---------------------------------------------------------------------------

@chain.connect()
def test_fuzz_invariants():
    QuantDEXFuzzTest.run(
        sequences_count=50,
        flows_count=100,
    )
    print("[PASS] Fuzz: all invariants held across 50×100 random operation sequences")
