# Open findings

Things the harness has measured but not settled. Each entry says what was
observed, what it is not, and what would close it.

---

## 1. The reference chain never finalized, so its epoch view froze — CLOSED 2026-11-17

**Status:** root cause found and fixed. Opened 2026-11-11 as "two core
assignments, reading different entropy entries", which was wrong; what it
recorded was a symptom. The correction is below.

**What this was recorded as.** That polkajam computes the core assignment two
ways and they disagree — `storage.core_assignments_for(slot)` shuffling with
entropy entry 2 while the cached `EpochInfo::core_assignments(slot)` uses
entry 1 — measured against a live node as:

```
cached ee155ace9c402920  best-block[1] ee155ace9c402920
                         best-block[2] bb30a42c1e62f0af
```

**What it actually was.** `current_and_next_epochs` reads a cache that
polkajam writes in exactly one place: the finalization path
(`chain/mod.rs:1175`, "Publish the new finalized head"). Finality in dummy
mode is driven by `finality::dummy_run`, an async worker the **node** spawns
(`node/mod.rs:377`). `AuthoringHarness::new` builds a `JamChain` and spawns
nothing, so a harness session finalized once — at genesis — and never again.

The cached view was not lagging. It was **frozen at genesis for the whole
run**, while the head walked away from it. Authoring a `tiny` chain across
two boundaries, with no node involved at all:

```
period 12, genesis slot 0
slot  1 (epoch 0) cached_idx 0 state_idx 0 | cached ee155ace9c402920 entry1 ee155ace9c402920 entry2 bb30a42c1e62f0af
slot 12 (epoch 1) cached_idx 0 state_idx 1 | cached ee155ace9c402920 entry1 c782837d5e696d6c entry2 ee155ace9c402920
slot 24 (epoch 2) cached_idx 0 state_idx 2 | cached ee155ace9c402920 entry1 0c4e24ca0c0d8e0f entry2 c782837d5e696d6c
```

The first line reproduces the original measurement byte for byte. `cached`
never changes; the entries rotate past it. It equals entry 1 at slot 1, entry
**2** at slot 12 and neither at slot 24 — so "the cached view reads entry 1"
was a coincidence of *when* the measurement was taken, not a rule.

**Why the stale-cache hypothesis was wrongly refuted.** The finding said the
cache was not stale because "the cached epoch index matched the best-block
state epoch exactly (815264 against 815264)". Those indices agree for as long
as the run is still inside the genesis epoch, which is where that measurement
was taken — a frozen cache and a healthy one are indistinguishable there. The
test could not have told the two apart.

**Why the lane went quiet.** The epoch view answers only for the cached epoch
and the one after it. With the cache stuck at genesis, every slot more than
one epoch out resolved to nothing, so `submission_slot_for` found no slot and
N3 reported all four rows unexercised. `wait_for_the_epoch_view_to_catch_up`
made it worse: it waited up to half the observation window for a cache that
could never move, and the head drifted further away while it waited.

**The fix.** `advance_finality` in the oracle, called after authoring and
after a successful import. Not `dummy_run`'s rule of one slot behind the head:
the harness is asked to import blocks a node announced late, a block older
than the finalized head cannot be imported at all, and at a one-slot lag a
block two slots late is refused — which turned a late announcement into a
harness-side failure on `n1_header_seal_import_ok`, a row about whether the
block is well formed. It finalizes the *earliest block still in the head's
epoch*, the least that moves the epoch index, leaving the rest of the epoch
open to import; and it skips the head, so a fresh boundary does not leave
zero headroom.

**Measured after the fix**, on a live run:

```
[assignment] entropy: cached ee155ace9c402920  best-block[1] 4f739a0703289dcc
             best-block[2] ee155ace9c402920  -> cached matches entry 2 (the on-chain rule)
[assignment] cached epoch view 822125, best-block state epoch 822125
[assignment] slot 9865512 core 0: storage Ok(Some([2, 3, 4])) epoch Ok(Some([2, 3, 4]))
[assignment] slot 9865512 core 1: storage Ok(Some([0, 1, 5])) epoch Ok(Some([0, 1, 5]))
```

**The two views agree, on both cores.** There is no divergence to choose
between, so the three questions this finding left open — which view is
authoritative, whether a guarantee over the cached cohort can be included,
whether the harness should grade against the on-chain rule — do not arise.
Nor was there anything to raise upstream: the defect was ours.

N3 went from four unexercised rows to eleven running, nine of them passing.

**Pinned by** `the_cached_epoch_view_follows_the_chain` in `m2-reference`,
which authors across two boundaries and asserts the cached view has moved off
genesis and sits within one epoch of the head.

**One caution.** In the run above the cached entropy also equals entry 2, but
the chain was only a few epochs old and entry 2 may still hold genesis
entropy at that age. The cohorts agreeing is the direct evidence; the entropy
line is consistent with it rather than independent proof.

## 2. A distributed report is never included — CLOSED 2026-11-12

**Status:** closed. Every cause was the harness's; the node was right each
time, and said so in its own words once asked at debug level.

Hypothesis 1, that a report needs its bundle available first, is **wrong**.
`receive_guarantee` calls `distribution.prefetch_shard(&guarantee)` with the
comment "optimistically start downloading our availability shard before the
report is seen on chain", and then notes the guarantee into the table.
Availability is fetched after inclusion, never required before it.

What was actually wrong was four things, each hidden behind the one in front
of it. Running the node with
`RUST_LOG=jam_node::chain::guarantors=debug` is what made them visible: the
discard paths in `receive_guarantee` return `Ok(())`, so a rejected report
looks like a clean stream on the wire and says nothing at INFO.

1. **`Invalid guarantee: Wrong core assignment`.** The guarantee was composed
   by `try_compose_guarantee`, which signs over the storage view of the
   assignment, while the node checks the signers against its own. The same
   split as finding 1, and the same fix as the CE 134 answer: sign per
   validator over the epoch view's cohort.
2. **`Invalid guarantee: No signature from peer …`.** A node validates a
   received guarantee against the peer that sent it, so the sender has to be
   one of the signers. The distribution went out on whichever connection
   claimed the plan. It now goes out on the connection to a validator that
   signed.
3. **`Wrong core assignment` again.** The guarantee declared the slot it was
   composed in while being signed by the cohort of the slot it was aimed at.
   A node derives the expected signers from the declared slot, so both halves
   being individually right is not enough -- they have to name one slot.
4. **The submission refused with `Unwanted`.** The submitted package and the
   distributed report were built from the same empty work item, so they were
   the same package. While the guarantee was still being rejected this was
   invisible; once it was accepted the node noted the report and refused the
   CE 133 submission of that package as already reported. `Unwanted` covers a
   duplicate as well as a bad anchor, which is why it read like an anchor
   problem. The distributed report now carries a distinguishing payload.

With those four fixed, a run reached all 30 rows and exit 0 -- the first time
the inclusion row has ever passed.

**It is not yet reproducible.** The very next run scored 14, the node having
opened CE 134 to one co-guarantor instead of two. That is finding 1's
signature, not this one's: the submission had landed on the *first slot* of
the new epoch, one slot after the head, and the node's cached epoch view
rotates on finalization, which trails. At the boundary itself it is still
shuffling by the old epoch's entropy however much the two views agree on
paper. Aiming a few slots into the epoch rather than at its edge was tried as a
widening of that margin. **Measured over five consecutive runs, it is a
regression:** every one scored zero passes, in two distinct ways.

- Two runs produced no plan at all -- "no slot at or after N leaves 2 slots
  of its rotation". Aiming `epoch + 3` puts the target beyond what the cached
  epoch view can answer for: it holds only the current epoch and the next,
  and when finality lags the cached index trails the head, so the slot lands
  two epochs out and resolves to nothing.
- Three runs had the submission refused with `Unwanted`. The aim was about
  fourteen slots past the head and the package is built at plan time, so its
  anchor had aged out of recent history.

That second result does put a bound on the anchor window this file has twice
said was unestablished: about eleven slots ahead is accepted, about fourteen
is not. The settle is back to zero, and the bound was the useful part: the package is
now built two slots before its submission rather than when the run is
planned, which puts the anchor inside both limits.

**Measured over three consecutive runs: two scored 30 of 30 with exit 0, and
the third exercised nothing.** That third is finding 1 again -- the cached
epoch view had fallen more than one epoch behind the head, so the submission
slot resolved to neither the cached epoch nor the next and no plan was made.
It reported the rule unexercised rather than failing the node, which is the
right outcome for a question the harness could not pose, but it is still
finding 1 setting the ceiling on how often this lane can run at all.

So finding 2's chain is closed and finding 1 is what remains between this
lane and a deterministic pass.

---

## 3. The inclusion row fails when the submission waits a long time — CLOSED 2026-11-12

**Status:** closed. The node named the cause and the fix follows from it.

The outcome used to be predictable from the chain's phase within the epoch at
plan time. Ten consecutive runs separated totally:

| epoch phase at plan | slots waited | outcome |
|---------------------|--------------|---------|
| 5, 3, 3, 2, 1 | 7 to 11 | inclusion row FAILS, all five |
| 10, 9, 8, 7 | 2 to 5 | clean 30 of 30, all four |

The lane aims at the next epoch, so planning early in an epoch means waiting
most of one. Long waits failed.

**The node's words, from one instrumented run at phase 3:**

```
Discarded guarantee: Invalid guarantee: anchor is not recent
```

The stale thing is the report's *refine-context anchor*, not the guarantee's
slot. The report was composed when the run was planned and distributed seven
to eleven slots later, by which time its anchor had aged out of the node's
recent history.

**The fix is two constraints held at once**, which is why three earlier
attempts failed:

- Compose a short lead before the distribution, so the anchor is fresh.
  Composing at plan time leaves it stale; composing against the very head
  makes the guarantee name a slot the reference has reached and the node has
  not.
- Pass the *distribution* slot for the cohort and the declared slot, not the
  compose slot. The lane aims at phase 0, so two slots before the target is
  the previous epoch with a different cohort entirely -- a lead alone
  silently swaps one rejection for another.

Earlier attempts moved the declared slot and never the anchor, or moved both
together. They are stashed as `n3-send-time-build` and
`n3-report-send-time-compose`.

**Measured after the fix:** four consecutive runs clean at phases 8, 7, 5 and
5. Phase 5 is inside the old failing band, where every run had failed.

Phase 1, the deepest part of that band, has since come back clean twice,
which closes the sampling gap this entry was left with.

---

## 4. The node accepts a CE 133 first message over the size cap

**Status:** open, reproduced, and it may be the spec rather than the node.
Opened 2026-11-15; seen again 2026-11-18 on the `b1ea8aca4` pin
(`sessions/n3n4-1`), and this time over **CE 146 as well as CE 133** —
`n3_ce146_oversized_reset` failed against its own 204,800-byte cap in the
same run. The two protocols cap different messages and the node accepted
both, which is what the extension below predicted.

The CE 133 fault rows put a deliberately oversized first message on the wire:
**205,076 bytes against the cap of 204,802** (`2 + 200 * 1024`), read off the
trace rather than inferred. The node accepted it and did not reset the
stream.

DESIGN §11 N3 reads that as a defect -- its fault column says `first message
> 2+200*1024 bytes -> reset :362-364`. The spec is softer than DESIGN:

> The initial message `Core Index ++ Work-Package` **should be limited** to
> `2 + (200 * 1024)` bytes. This ensures that Guarantors can not be forced to
> download huge work packages, before they can check that the Work-Package is
> actually authorized.

That is a SHOULD addressed to the builder, with a rationale about protecting
guarantors. Whether a guarantor **must** reject a larger one is an
interpretation DESIGN made and the spec does not state. polkajam reads its
first message with `read_decoded`, which caps at the type's
`max_encoded_len`, and a `WorkPackage`'s is far above 200 KiB -- so it is
enforcing a different limit, not no limit.

**Before this is reported as a node defect it needs settling**, and it is a
question for the conformance group rather than for the harness:

1. Is the cap normative on the receiver, or only on the sender? If only the
   sender, the row is wrong and should be dropped or made soft.
2. If normative, what is a guarantor meant to do -- reset, or read and
   discard? The rationale is about not being *forced to download*, which
   argues for a reset before the body arrives.
3. ~~Seen once. It should be reproduced before anything is filed.~~
   Reproduced 2026-11-18, over both protocols, which leaves 1 and 2 as the
   open questions.

This is the first N3 row that failed for a reason that is not plainly the
harness's. Every earlier one was ours.

**CE 146 inherits the same question.** `simple.md:383` says the
`Work-Package` message **should be limited** to `200 * 1024` bytes, in the
same SHOULD form and with the same rationale, so `n3_ce146_oversized_reset`
rests on the same unsettled reading as `n3_ce133_oversized_reset`. Both are
Hard, which keeps them consistent with each other rather than with any
answer; whatever settles one settles both, and if the cap turns out to bind
only the sender then both rows go, not one. Noted here rather than
rediscovered when the CE 146 row first fails against a live node.

---

## 5. The node resets a well-formed CE 134 share with `NoError`

**Status:** open, and now reproduced. Opened 2026-11-16, seen again
2026-11-18 on the `b1ea8aca4` pin (`sessions/n3n4-1`) with the same message
to the byte, down to the core and the code. Point 3 below is answered: it
is not a one-off.

The CE 134 receive row shares a bundle *with* the node, on a core the node
holds at that slot, offering the active validator count as the shard count.
The node reset the stream rather than answering:

```
the NUT reset a well-formed share on core 1 with code 0x100
```

`0x100` is `NoError` in polkajam's own table -- "No error", from RFC 9114 --
not one of the JAMNP refusal codes (`Unwanted`, `TooBusy`, `TooMany`). So
the node is not saying the share was bad; it is closing the stream without a
reason.

The same run's unacceptable-shard-count share *was* correctly refused, so the
path works and the node does distinguish the two cases.

Worth establishing before this is called a defect:

1. Whether `NoError` on a reset is polkajam's way of declining a share it
   does not want -- for example because it is already refining that core, or
   has seen the package -- rather than an error at all.
2. Whether the harness should be sharing at that slot at all. The share goes
   out one slot after a run's own submissions, so the node may still be busy
   with one of those.
3. ~~Seen once. Reproduce before filing.~~ Reproduced 2026-11-18, two pins
   and two days apart, which leaves 1 and 2 as the open questions.

## 6. crates.io 0.1.29 is not the pinned 0.1.29, and the difference is on the wire

**Status:** open, and it settles a planned step rather than describing node
behaviour. Found 2026-11-16, while moving the workspace off its git
dependencies.

The polkajam split's last step was to stop depending on polkajam by git and
take `jam-types` and `jam-std-common` from crates.io instead. Both are
published at **0.1.29**, which is the workspace version at the pinned
revision `e3d216c2`, so the swap looked like a formality.

They are different code. Unpacking the published crates and diffing them
against the checkout at the pin:

```
jam-std-common/src/state.rs
  #[derive(Clone, Encode, Decode, Debug, Eq, PartialEq, Default)]
  pub struct ServiceActivityRecord {
-     pub provided_count: u32,     // the pin
+     pub provided_count: u16,     // crates.io 0.1.29
-     pub provided_size: u64,
+     pub provided_size: u32,
-     pub extrinsic_size: u64,
+     pub extrinsic_size: u32,
```

`ServiceActivityRecord` derives `Encode` and `Decode`, so those three widths
are a **wire format**, and that struct is in the state the N1 lane diffs. A
harness built against the published crate and an oracle built against the pin
would disagree about the bytes of a state value while agreeing about
everything else -- which is the failure this whole split exists to make
impossible, reintroduced at the last step.

The two are not simply older and newer, either. The published crate has a
`ProtocolParameters::large()` the pin does not; the pin has a
`max_refine_gas * core_count` overflow check and a `bundle_size_constants_match_gp`
test the published crate does not. They are points on different lines, both
calling themselves 0.1.29.

**What this means.** The version number is not a safe way to match a
published crate to a revision, because polkajam publishes 0.1.x from a moving
trunk and a crates.io version is immutable once published while the trunk is
not. So:

- `jam-types` and `jam-std-common` stay git dependencies on the pin. The
  rest of phase 4 -- dropping `jam-node` and `polkajam-fuzz` and the
  `jam-node` profile override -- stands, and is what the phase was for: the
  workspace no longer compiles the node.
- A re-pin must check this again rather than assume the published version
  caught up. The check is cheap: unpack
  `~/.cargo/registry/cache/*/jam-types-<v>.crate` and diff its `src` against
  the checkout under `~/.cargo/git/checkouts/polkajam-*/<short rev>/crates/`.
- Worth asking upstream whether a published version can be tagged, so a
  revision and a release can be matched without diffing them.

## 7. The harness and the oracle resolved different codec versions

**Status:** fixed 2026-11-17, and worth a guard it does not yet have.

`jam-codec` is the codec both sides of the oracle socket encode and decode
with. The workspace and `oracle/` are separate cargo trees with separate
lockfiles, and both asked for `"0.1.1"` -- a caret requirement. They resolved
differently: the workspace to **0.1.1**, the oracle to **0.1.2**.

Encoding is identical. A probe over 2,199 values -- every power-of-two
boundary from 2^0 to 2^63, each ±1, plus a pseudorandom spread -- produced
byte-identical output from both. On that evidence alone the skew looks
cosmetic, and this finding nearly said so.

Decoding is not identical. polkajam's own `8d9495219` ("Non-canonical compact
lenghts are rejected", #1392) names the change:

```
input           0.1.1                  0.1.2
80 00           Ok(0)                  Err(Codec error)
c0 00 00 00     Ok(0), 1 byte left     Err(Codec error)
80 01           Ok(1)                  Err(Codec error)
00  canonical   Ok(0)                  Ok(0)
```

0.1.1 accepts a compact integer written in more bytes than it needs; 0.1.2
rejects it. The harness decodes what the node under test sends, so on 0.1.1
the harness was **laxer than the node it grades**: a node emitting a
non-canonical length would have been accepted here while polkajam itself
rejects it. That is a missed detection rather than a wrong verdict, which is
the gentler of the two directions, but it is the wrong one for a conformance
harness.

Both trees are pinned to 0.1.2 now and the lockfiles agree.

**The guard that is still missing.** Nothing checks that they agree. Two
independently-resolved lockfiles can drift again on the next `cargo update`,
and the symptom would be a decoder disagreement across the socket with no
error anywhere -- the same shape as findings §6 and as the two defects the
oracle split introduced. DESIGN §8 states the rule this breaks: anything both
sides must compute identically belongs in one place. The codec is exactly
that, and it cannot live in `m2-oracle-proto` because each tree resolves its
own copy.

The cheap version: each side's `build.rs` reads the resolved `jam-codec`
version out of its own `Cargo.lock` -- the oracle's already reads its manifest
for the polkajam revision -- and the handshake compares them, the way it
already compares the protocol version. About fifteen lines, and it turns a
silent divergence into a refusal to start.

## 8. The node accepts a CE 133 extrinsic message of the wrong size

**Status:** open, reproduced, and it may be a change in the node rather
than a standing defect. Seen 2026-11-17; seen again 2026-11-18 on the
`b1ea8aca4` pin (`sessions/n3n4-1`), so it is not a one-run artefact.

CE 133's second message carries the extrinsic data, and `simple.md:373` gives
its size as the sum of the lengths the work-package declares. polkajam itself
reads it with `read_exact(saturated_extrinsic_size())`, so that equality is
the rule, and DESIGN §11 N3 lists "extrinsic size mismatch" as a fault the
node must reset the stream for.

The fault row sends a message whose size does not match the declared sum. The
node accepted it and did not reset.

**What makes this worth a second look rather than a filing.** The same row
passed at the previous pin (`e3d216c2`) in earlier sessions, and failed on
the first run after re-pinning to `5ef954fb1`. Twenty-seven commits separate
them, several touching block import and work-package handling. It is equally
possible that the row only now ran to completion: the N3 lane was reporting
every row unexercised before §1 was fixed, so "passed before" may mean
"passed in an older session under different conditions" rather than "passed
on this code path yesterday".

**Before filing anything upstream**, establish:

1. Whether it reproduces. One run is not a pattern, and the N3 lane has only
   just started exercising again.
2. Whether it reproduces at the *old* pin with the current harness, which
   separates a node change from a harness change.
3. Which of polkajam's read paths handles this message now, and whether the
   `saturated_extrinsic_size` read survived the re-pin range.

Related: §4, the oversized first message, which is the same shape — a size
rule the node does not enforce — and which also failed in this run.

## 9. The hazmat availability export cannot build a justification

**Status:** open upstream; the harness is pinned to the proposed branch,
and with it the whole of N4 is now reachable. Found 2026-11-17, starting N4.

polkajam #1378 exported erasure coding and the justification builders so the
harness could produce availability artifacts outside the node, and that is
what let the N4 lane start. It is not sufficient for half of it.

`bundle_justification` and `segment_justification` both take a `ShardProof`,
and nothing outside `jam-node` can build one. Every top-level module in that
crate is private except `hazmat`, so only its explicit re-exports are
reachable, and the Merkle layer is not among them. Tracing what the node
itself does to turn a bundle into a servable shard
(`availability/mod.rs:190-215`):

| step | exported |
|---|---|
| `erasure_shards(bundle, n)` | yes |
| `segments_shards(segments, n)` | yes |
| `merkle_root(s, len)` | **no** — `util::merkle` |
| `pack_erasure_tree_entry(hash, root)` | **no** — `util::merkle` |
| `merkle_proofs(entries, len)` | **no** — `util::merkle` |
| `bundle_justification(&ShardProof)` | yes, and uncallable without the above |

`check_bundle_proof` and `check_segment_proof` take wire types and are fully
usable. So the harness can **verify** a node's justification and cannot
**construct** its own.

**What that cost.** Five of DESIGN's seven N4 rows are the node producing
and the harness checking -- CE 137/138/139/140 serve, CE 141 send, CE 141
receive to inclusion -- and those were reachable with the verify half alone.
The two where the *harness* must serve shards to the node, CE 137 fetch and
CE 139/140 fetch, were not.

**And what it cost that was not obvious.** Without the construct half there
is also no way to *simulate* a node that serves shards, so none of the five
reachable rows could be shown to fail. Checks nobody has seen fail are
checks nobody knows are checks, and this harness has already paid for that
twice. With the pin moved, `m2-sim` holds a real coded bundle and
`n4_sim_it` drives eleven faults through it.

**Open upstream** as polkajam#1401, from branch `jv-export-n4`:
`util::merkle` becomes `pub(crate)` and `hazmat::merkle` re-exports
`merkle_proofs`, `merkle_root`, `pack_erasure_tree_entry` and the proof
types. The same shape as #1378 -- a re-export and a visibility bump, no
behaviour change.

The pin moved to that branch on 2026-11-17 (`43689c3de`, then `0aaa2cb20`
with §14's export and `b1ea8aca4` with §16's), ahead of the PR
being opened, for two reasons. `merkle_root` is needed to *check* a CE 137
justification at all, since that protocol takes its segment root from the
shards rather than from the justification (§11b). And `merkle_proofs` with
`pack_erasure_tree_entry` are needed to *build* one, without which no
simulated node can serve shards and none of N4's serve rows could be shown
to fail. The pin goes back to a merge commit once #1401 lands.

## 10. DESIGN had the erasure recovery threshold wrong

**Status:** fixed in DESIGN 2026-11-17.

DESIGN §2's tiny-parameter table said "EC recovery 2 shards" and the §11 N4
row said the node "reconstructs imports from 2 shards". It is **three**:

```rust
pub const fn erasure_recovery_count(val_count: usize) -> usize {
    let mut recovery_count = val_count / VALS_PER_CORE + 1;   // 6/3 + 1 = 3
    while !SEGMENT_LEN.is_multiple_of(POINT_LEN * recovery_count) { recovery_count -= 1; }
    recovery_count
}
```

polkajam pins it with `erasure_recovery_count_matches_gp`: 6 to 3, 78 to 27,
1023 to 342. A CE 139/140 fetch row written from DESIGN would have asked a
conforming node to reconstruct from one shard too few and failed it.

Found by asserting the wrong value in a reachability test and reading the
failure, rather than by reading the table -- which is the only reason it was
caught before the row was written. `CodedBundle` now carries the threshold
from the engine so no lane has to hold a copy of this number.

## 11. The harness's availability codecs were shape models, not the wire — CLOSED 2026-11-17

**Status:** closed. Found 2026-11-17, wiring the N4 emulator against the real
serving path; all three defects were the harness's own.

`crates/jamnp-s/src/codec/ce137_148.rs` opens by saying so:

> Shapes only: the harness does not produce real erasure data at this layer,
> so all shards/segments/bundles are opaque `Vec<u8>`.

That was a fair trade while nothing spoke those protocols. The moment N4
started it stopped being one, and three separate things were wrong — each of
which would have failed an honest node rather than erroring.

**a. CE 137/138/139/140 replies are framed messages, not one structure.**
`ShardResponse` and friends derive `Encode`/`Decode`, so a bundle shard
decoded as a compact-length-prefixed `Vec<u8>` and the segment shards as a
prefixed `Vec<Vec<u8>>`. The node writes neither. It writes a *sequence of
whole messages* — bundle shard, then CE 137's segment shards concatenated
with no boundary, then the justification — each with the stream's own
`[len: u32 LE]` framing (`availability/net/mod.rs:358-368`, read back by
`read_exact` / `read_decoded_bounded_seq`). Nothing in the reply says how
long a shard is, because the reader already knows: the frame does.

The justification is the sharpest case. Its elements are written back to
back with **no count in front of them**, while the engine's own
`BundleJustification` is a `BoundedVec` whose `Decode` expects a compact
count. Handing the wire bytes to that decoder reads the first element's
discriminator as a length.

**b. The two bundle protocols take their segment root from different
places.** CE 138 appends it as a final `0 ++ Hash` element and the reader
pops it off before checking the proof; CE 137 omits it and the reader takes
the Merkle root of the segment shards instead (`net/mod.rs:946-963` against
`:1030-1046`). Reading one the other's way turns a sound proof into a failed
one. This is now `CheckServedShard`'s `protocol` field, decided in the
oracle: it is a rule both sides must apply identically, so it is applied in
one place.

**c. CE 141's bitfield had a length prefix.** `Assurance.bitfield` was a
`Vec<u8>` with a derived codec, which puts a compact length in front of it.
The wire is `AvailabilityStatement ++ Signature` and the bitfield is
`[u8; ceil(C / 8)]` — fixed width, no prefix. Under tiny that is one extra
byte, which shifts the 64-byte signature out of place: every assurance the
harness sent would have been refused, and every one it received would have
been read as a bad signature from a node that signed correctly.

Two tests had the wrong vector written into them, which is why this survived
a full suite. They now assert the raw layout, and
`assurance::the_wire_and_the_engine_agree_about_the_width` holds the two
independent readings of the width together — `jamnp-s` derives it from the
core count, `m2-reference` asks the engine's type, and neither can drift
alone because the wire carries nothing to contradict either.

**The general shape.** All three are the same mistake in different places: a
self-describing codec standing in for a wire whose lengths are carried out of
band. A shape model is only safe while nothing sends it, and the comment
saying so is not a guard.

## 12. N4's plan cannot be written before the run, and that is the protocol's doing

**Status:** not a defect — a design note, recorded because the first attempt
got it wrong. 2026-11-17, wiring N4 into a real run.

Every other plan this harness makes is laid out before the observation
window: the ticket schedule, the CE 133 submission, the report to distribute,
the bundles to share. N4's cannot be, and the reason is worth writing down
because the obvious alternative is wrong in a way that reads as a node
defect.

CE 137/138/139/140 are *fetches against an erasure root*. A node serves
shards for the bundles it holds, and it holds the ones it guaranteed. The
harness knows several erasure roots before a run starts — every bundle it
built itself — and the node is entitled to answer `NoData` for every one of
them, because it never saw those bundles. A lane that asked for one of those
would record a refusal and fail `n4_ce137_answered` against a node doing
exactly the right thing.

The only root a node owes shards for is one **it** published. That root
exists only once the node has guaranteed a package and distributed the
report, which is mid-run. So:

- the harness submits a package over CE 133 (N3's machinery, which N4 now
  also depends on — `LaneSet::needs_package` covers both),
- a watcher waits for the node's own CE 135 distribution and reads
  `package_spec.erasure_root`, `erasure_shards` and `exports_count` straight
  off the report's bytes,
- the plan goes out on a watch of its own, because `plans_set` has long
  since flipped by then and a driver waiting on that would read an empty
  plan and do nothing.

A run where the node guarantees nothing therefore exercises no N4 fetch. The
lane says so, which is the truth, rather than failing the node for the
harness having nothing to ask about.

**The assurance rounds are split for a related reason.** The three
deliberate faults (`WrongAnchor`, `BadSignature`, `EmptyCore`) must come from
validators that did *not* already send an honest assurance for the same
anchor — otherwise the node drops the second as a duplicate, and
`n4_ce141_invalid_assurance_excluded` passes for a reason that has nothing to
do with the assurance being invalid. So the honest round and the spoiled
round sit three slots apart, against different blocks. With a supermajority
threshold of 5 of 6, that also keeps the honest round complete enough for
`n4_availability_threshold_reached` to mean something.

## 13. A timing row that could never fail — CLOSED 2026-11-17

**Status:** closed. Found by writing the simulated node that should have
broken it, which is the only reason it was found at all.

`n4_ce141_sent_before_the_slot` read:

```rust
seen.lead_ms > 0
```

against a `lead_ms` computed as the time remaining in the slot the assurance
arrived in. That quantity is positive by construction — it is bounded by
`(0, slot_period]` — so the row passed on every node, conforming or not,
and would have gone on passing forever.

`simple.md:679-680` asks for roughly two seconds' lead. The row now asks for
that, as a **floor** rather than a window: assuring *early* is not a defect,
since a node with nothing left to wait for may send as soon as it has
verified its shard, so only too little lead is reported. It stays Soft,
because "roughly" is not a number a node can be hard-failed on.

Two things worth keeping from this.

**The row looked fine in review and in its unit test.** The test fed
`lead_ms: -500` and watched the row fail — a value the real measurement
cannot produce. A unit test that fabricates its input can only prove the
comparison does what it says, never that the input can reach the values it
compares against. The simulated node is what closes that gap, because it
produces the measurement the way a run does.

**The first attempt at the fault did not work either.** `AssuranceLate`
slept one whole slot period before sending, which lands at exactly the same
phase of the next slot and reads as punctual. It now holds until the slot has
nearly run out. A fault that fails to break the thing it is aimed at looks
identical to a check that works.

## 14. The inclusion rows asked for the wrong block — CLOSED 2026-11-18

**Status:** closed. Found by writing the simulated node that should have
broken `n4_ce141_inclusion`, which had never been exercised against anything.

Both of its rows were wrong, in ways that compounded.

**An assurance can be carried in exactly one block.** `check_signatures`
refuses an assurances extrinsic unless every assurance in it anchors the
block's *parent*:

```rust
if assurance.statement.anchor != parent_hash {
    return Err(BadAttestationParent);
}
```

So the only block that can ever carry an assurance is the child of the block
it names. The row asked whether *any* NUT block after the offer carried it —
and the node authors about two slots in six, so most of its blocks are not
that child. A node keeping the rule exactly would have been failed for it.

**And the anchor was the wrong block to begin with.** The harness anchored
every offer at the last block the *NUT* had authored. The harness fills the
slots the node does not, so that block is usually several blocks behind the
head, and nothing is ever authored directly on top of it. Every offer named
a block that would never be a parent again. The two defects hid each other:
with the anchor stale, the "any later block" reading was the only one under
which the row could ever pass.

The anchor is now the chain's head, read at send time, and the rows are
judged against the one block that could carry the assurance — the child of
that anchor, authored at or after the slot the assurance was sent for.

Two more things came out of writing it.

**A node that includes an invalid assurance authors an invalid block.** A
bad signature fails `check_signatures`; a bit for a core with no assignment
fails with `CoreNotEngaged`. So the fault cannot be posed by pooling: the
authoring engine refuses to produce the block. `AssuranceIncludesInvalid`
rewrites the authored body instead, and fails N1's import row in company,
which the test asserts rather than remarks on. The wrong-anchor fault cannot
reach a block even then — the engine files assurances by anchor and the
author reads only the entry for its parent — so it is the other two that
make the exclusion row fail.

**Offering once was not enough.** With the rows tied to one block, a single
offer is graded only if the node happens to author that block. A run now
assures the head every slot, as a validator does, half the slots honestly
and half spoiled, so each row has several of the node's own slots to be
judged on.

### Why this took an upstream export

`AssuranceTracker` is a private field of `Authoring` and `note_dummy_assurance`
is unreachable outside `jam-node`. The authoring harness could sign its own
assurance and never take one it was handed, so nothing could simulate the
half that matters: a node's assurances extrinsic carries what its *peers*
sent it. `AuthoringHarness::submit_assurance` is the entry point, pushed to
the same branch as the Merkle exports (§9) and open as
**paritytech/polkajam#1401**.

## 15. The same shape-model defect in CE 146 and CE 148 — CLOSED 2026-11-18

**Status:** closed for these two. The CE 137/138/139/140 response types are
still shape models; see below.

§11 found the availability codecs modelling *shapes* rather than the wire,
and fixed the ones the N4 lane reads. `BundleSubmission` (CE 146) and
`SegmentResponse` (CE 148) had the same defect and were not touched, because
nothing used them yet. Found by going to use them.

CE 146 is five messages and CE 148's reply is two. Both types derived
`Encode`/`Decode` over one structure, which writes a length prefix in front
of the work-package and of every extrinsic, segment and proof. A guarantor
reading that takes the prefix as package content. Worse for CE 146 than for
CE 137: the whole reason the bundle is split across messages is so a
guarantor can authorize the package *before* downloading the rest
(`simple.md:381-384`), and a single value throws that away even when the
bytes happen to parse.

Both are now per-message, matching `WorkPackageSubmission`, which had been
written correctly for CE 133 and whose `decode_extrinsics` both protocols
now share — the extrinsic message has one rule and it lives in one place.

**The test vectors were wrong, again.** `ce148_response_vector` and
`ce146_vector` asserted the derived bytes, so the suite confirmed the defect
rather than catching it. This is the second time (§11 found the same thing
in `assurance_vector_2byte_bitfield`). A vector written from the
implementation tests nothing; it has to be written from the grammar.

**What is left.** `ShardResponse`, `AuditShardResponse`,
`SegmentShardsResponse` and `ProvenSegmentShardsResponse` are still single
derived structures. Nothing grades through them — `m2-emu::avail_io` reads
those replies by position off the stream, which is what §11 changed — and
the only caller is `jamnp-s::proto`, a trace decoder nothing in the
workspace drives yet. They are left as the trap they are rather than
quietly: a frame is one message, and `proto`'s one-frame-one-message model
cannot represent a multi-message reply at all. CE 129, CE 133, CE 146 and CE
148 are each special-cased there for exactly that reason, and the four above
want the same treatment when something starts reading traces.

## 16. CE 148 could not be checked at all — CLOSED 2026-11-18

**Status:** closed by an upstream export, the third of its kind.

A CE 148 reply is whole segments and one import proof each, and the only
thing that says a proof is good is `cd_proof_root_ph`: it hashes the segment
into a leaf and walks the path back to the segments root. That function is
`pub` inside `jam-node`'s private `util::merkle` and was not re-exported.

The asymmetry is what made it worth a finding rather than a shrug. The
*builders* were already reachable — `cd_merkle_proof` and `cd_merkle_root`
are public in `jam-std-common`, which this harness links — so anything
outside the node crate could construct a proof and had no way to check one.
A harness in that position can only grade shape: how many segments came
back, whether the message is a whole number of them, whether a proof arrived
for each. All true of a node serving somebody else's segments.

**Open upstream** as part of **paritytech/polkajam#1401**: one more
re-export in `hazmat::merkle`, beside the two added for the justification
builders (§9). The same shape as those, and as `submit_assurance` (§14): a
re-export and a visibility bump, no behaviour change.

The pattern is now three for three. Every time this harness has gone to
grade a new protocol, the engine could do the thing and could not be asked
to do it from outside. Worth saying plainly for whoever writes the next
lane: check what `hazmat` exports *before* designing the rows, because the
rows that survive are the ones the engine will answer.

### Where the rows live

CE 148 is graded in N4, where DESIGN §11 groups it under N3. The grouping
there is by purpose — CE 148 completes a bundle — but what decides which
lane can ask is the plan: the request names a segments root, the only root
the node is obliged to serve is one it exported itself, and that exists only
once it has guaranteed a package and published a report. The same report and
the same mid-run plan N4 already waits for (§12). DESIGN is updated to say
so rather than left to disagree with the code.

## 17. The segment protocols cannot be exercised against a live node

**Status:** open. Found while writing the CE 148 rows, by asking what the
run would actually ask for. Opened 2026-11-18.

Every segment protocol — CE 139, CE 140 and now CE 148 — is driven from the
availability plan, and the plan's `segment_indices` come from the
`exports_count` on the report the node published:

```rust
let segment_indices: Vec<u16> = (0..spec.exports_count.min(MAX_SEGMENTS_ASKED)).collect();
```

The package this run submits is built from `work_item_with_payload`, which
declares `export_count: 0`. So `exports_count` is zero, `segment_indices` is
empty, and a live run asks nothing over any of the three. Their rows report
*not exercised*, which is the truth, and a reader skimming a green report
has no reason to look closer.

This is not a defect in the rows. They are held to the bar by
`m2-sim/tests/n4_sim_it.rs`, which drives a node holding real coded segments
and real proofs through eight faults across the three protocols. What is
missing is the *live* half: nothing has ever asked polkajam for a segment.

**What it takes to close.** A work item that exports segments, which means
the dev bootstrap service actually exporting them during refine —
`export_count` is a declaration, and a refine that does not produce that many
fails. So this is not a one-line change to the item; it is a question about
what the service can be asked to do, and it needs a live run to settle rather
than a guess. Until then:

- a green CE 139/140 or CE 148 row against a live node means "the harness
  never asked", and the lane's own docs say so;
- the simulated node is the only thing those rows have been measured
  against, which is better than nothing and is not the same as a node.

**A fourth row has the same cause**, found 2026-11-18 while proving the CE
134 receive rows. `n3_ce134_shares_the_submitted_package` grades the
mappings on a share the node *sends* and is gated on those mappings being
non-empty — deliberately, because a package with no imported segments
correctly has none and a row written as "names it, or there were none"
could not fail. Mappings map the **import** list to the roots it comes
from, so the gate opens only for a package that imports segments, and no
package this harness builds does. The row has therefore never run against
anything, live or simulated, and is not counted among N3's proven rows.

That makes four rows waiting on the same thing: CE 139, CE 140, CE 148 and
this one. A work item that exports segments would let an later package
import them and open all four at once.

Related: §12, which is why the plan is mid-run at all.

---

## 18. Two N3 rows could not pass a conforming node — CLOSED 2026-11-18

**Status:** found and fixed the same day, by the first live run of N3 and N4
on the `b1ea8aca4` pin (`sessions/n3n4-1`). The mirror image of §13: that
was a row that could never fail, this is a pair that could never pass.

`n3_ce133_unauthorized_not_shared` and `n3_ce133_not_a_guarantor_ignored`
both ask whether the node *refrained* from sharing a package. The lane
answers by looking at the shares it saw:

```rust
let shared_after: Vec<u16> = ctx
    .shares
    .iter()
    .filter(|share| share.at_wall_ms >= submitted.sent_at_wall_ms)
    .map(|share| share.peer)
    .collect();
```

That is every CE 134 share in the rest of the run, not every share *of this
package*. A run submits seven packages a slot apart and two of them are
honest, so any submission with an honest one after it is graded against
shares the node was right to make. Both rows failed, with the same evidence:

```
n3_ce133_unauthorized_not_shared: the NUT shared a package built against an
  authorizer no core accepts; it reached [0, 1, 1, 0]
n3_ce133_not_a_guarantor_ignored: the NUT shared a package addressed to core
  1, which it does not hold at slot 9880528; it reached [0, 1, 1, 0]
```

`[0, 1, 1, 0]` is four shares to two peers — two co-guarantors twice over.
The honest CE 146 submission sits two slots after the second of these in the
plan, and the oversized CE 146 submission the node also accepted sits one
slot after that. Neither row is reading anything the package it names
caused.

**What this is not.** It is not evidence that polkajam shares unauthorized
packages or packages for cores it does not hold. The run says nothing either
way about those rules, which is the point: a row whose evidence is "somebody
shared something later" cannot distinguish a node that broke the rule from
one that kept it.

The positive direction has the same defect and it is the more comfortable
one: `n3_ce133_shares_with_both_co_guarantors` collects `answering` the same
way, so a node that ignored a submission can still pass that row on the
shares of a later one.

**Why nothing caught it.** `m2-sim/tests/n3_sim_it.rs` poses one honest
submission and one oversized one per protocol, and the two faults these rows
grade — `Unauthorized` and `NotAGuarantor` — are not posed at all. The
simulated node has never been asked to ignore a package while another
submission is in flight, which is the only arrangement in which the bug
shows.

**What would close it.** A correlation that names the package. Two keys are
available and neither is currently used:

- the share's bundle carries the work-package verbatim, so the harness can
  ask whether the bundle it received contains the package it sent;
- `SharingContext.core_index`, which separates the not-a-guarantor
  submission from the honest ones but not the unauthorized one.

**The fix.** `shares_answering` in `scenarios/n3.rs`, used by both
directions: a share answers the submission it followed, bounded by the next
submission the *node* saw — across both protocols, because bounding by the
next CE 133 submission alone would let the CE 146 one between them keep
attributing its shares backwards.

The key is the window, not the package, and the reason is that nothing a
share carries names one. `SharingContext.mappings` is keyed by the
work-package hash but is empty for a package that imports no segments, which
is every package this harness builds; the bundle in message 2 carries the
package but would have to go back to the engine to be read as one. The
window is sound here because the lane also grades how long the node took —
`shares_within_the_window` holds it to about three seconds while submissions
are a whole slot apart — so a share late enough to land in the wrong window
has already failed a row of its own.

**Proven.** `m2-sim/tests/n3_sim_it.rs` now poses the arrangement: a package
for a core the node does not hold, with an honest submission behind it. The
honest node passes the silence row and the new `SimFault::SharesForeignCore`
fails it. Reverting the bound to the old filter makes the honest node fail,
which is the bug reproduced on demand.

**What is still weaker than it reads.** `Unauthorized` is not posed
separately. The simulated node does not decode packages, so it cannot tell
an authorized one from an unauthorized one without being told, and the row
it feeds is graded by the same `shares_answering` the not-a-guarantor row
is. The correlation is proven; the node's judgement of authorization is not
simulated.

Related: §2 and §14, both of which were a row asking a question adjacent to
the one its rule is about.

---

## 19. The CE 135 report was never distributed, and nothing said so — CLOSED 2026-11-18

**Status:** found and fixed the same day, by the second live run on the
`b1ea8aca4` pin (`sessions/n3n4-2`). A race, so earlier runs may have
distributed and later ones not.

`n3_ce135_inclusion` reported *not exercised* on a live run that had planned
a report and said so:

```
[assignment] distributing report on core 0 in slot 9880524
```

The emulator gates every plan behind one `watch` channel, `plans_set`, and
the plans are written at different times: the ticket plans first, then the
report, the shares and the submission. Each connection task waited for the
gate, checked once, and returned:

```rust
while !*plans_set.borrow_and_update() { ... }
let Some(plan) = shared.claim_report_plan(peer) else { return };
```

So every task woke on the *ticket* plans, found no report plan yet, and gave
up. What saved the shares is that any connection may claim them and
connections keep arriving through a run, so a late one took them. The report
cannot be claimed by just any connection — only one validator in the cohort
may distribute it — and a run with no new connection to that validator after
the plan was written never distributed it at all.

The run said nothing, because a plan nobody claimed and a report nobody
answered leave the same rows empty. A diagnostic now reports it, and it is
what named the bug:

```
[distributor] the report for slot 9880680 was never distributed: no
  connection to validator 2, the only member of core 0's cohort that may
  send it
```

**The fix.** `claim_when_planned` in `m2-emu/src/emu.rs`: wait for the gate,
try the claim, and go back to waiting if there is nothing to claim yet.
Claiming is the only thing that ends the wait. Used by the report and the
shares alike, so the surviving half of the race is gone too.

Related: §13 and §18. All three are the same lesson from different angles —
a row that reports nothing is not a row that passed, and the run has to say
which it was.

---

## 20. The assurance window missed every slot the node authored — CLOSED 2026-11-18

**Status:** found and fixed 2026-11-18, on the second live run
(`sessions/n3n4-2`). Not a defect in the inclusion rows §14 fixed; a defect
in giving them anything to grade.

Every one of 32 assurance offers reported *not exercised*. The diagnostic
added in the same run says why:

```
[availability] none of 32 assurance offer(s) across slots 9880681..=9880692
  could be carried: an assurance is valid in exactly one block, the child of
  the block it anchors, and the NUT authored slots [9880662, 9880670,
  9880675, 9880693, 9880699, 9880704, 9880717, 9880718]
```

The node authored eight blocks in the window and the offers spanned twelve
slots that contained none of them — the nearest, 9880693, is one slot past
the last offer. `ASSURANCE_SLOTS` was a fixed epoch's worth, chosen when the
reasoning was "a full epoch puts several of the node's own slots among
them". With six validators the node authors about one slot in six, and
twelve slots is not several of anything.

**The fix.** The offers now run for whatever is left of the observation
window, less two slots of tail so the last offer still has a child block to
be carried in, with a floor of twelve. A run cannot choose which slots are
the node's, so the only thing that reliably puts one among the offers is
offering in all of them.

**What this cost.** Two live runs in which the N4 inclusion rows — the ones
PR #15 was written to fix — reported themselves unexercised, which on a
green report reads exactly like a node that carried nothing. §14 fixed what
the rows ask; this fixed whether they are ever asked.

**What widening it exposed.** Two defects that were already there and too
small to see: §24, a reconnection re-fetching shards the node had rightly
let go, which a twelve-slot window hid behind one or two repeats; and §23,
a row that had never been reached at all. Neither was caused by this
change. A longer run is a stronger test, and the first thing a stronger
test found was the harness.

---

## 21. Every assurance a live run sends is for a core that carries nothing — CLOSED 2026-11-18

**Status:** both halves landed. Found on the third live run
(`sessions/n3n4-3`), the first half the same day
(`sessions/n3n4-4` measured it), the second after PR #16
(`sessions/n4-cores-1`). A residual remains and belongs to §22 rather than
here: the harness now reads the engaged cores correctly, and what is left
is what a node does with an assurance that was valid when it was sent.

An assurance says "I hold my shard of the report on core *c*". It is valid
only where core *c* is **engaged** — carrying a report that is on chain
awaiting availability. The harness picks the core once, when the
availability plan is written:

```rust
cores: vec![decoded.core_index],
```

read off the report the NUT *distributed over CE 135*. Distributing a report
does not put it on chain. Some validator has to include it in a block, and
in a live run nobody does: the NUT's own blocks carried none
(`n3_ce135_report_included` failed with `the NUT's blocks carried []`), and
the reference chain — which authors five slots in six — never pools what the
NUT distributes at all. Nothing in the runner calls `submit_guarantee`.

So no core is ever engaged, and **every assurance the run sends is invalid**,
the honest half included. The node's log says so three times:

```
ERROR authoring  Error authoring block: block execution error:
  assurances error: core not engaged
```

**What it cost.** The node had six authoring opportunities in the run. The
three outside the assurance window succeeded; the three inside it — slots
9880826, 9880840 and 9880859 — all failed. The harness took away every slot
it owned while assurances were in flight, which is precisely the window the
inclusion rows need a block in. §20 widened that window from 12 slots to 35
and so widened the damage: run 2 lost some slots unnoticed, run 3 lost all
of them.

It also produced a false negative in another lane. `n3_ce135_inclusion`
failed — the first time it has ever been graded, §19 having just made it
reachable — with "the report ... distributed in slot 9880824 was never
included". True, and not the node's doing: it had no valid slot between the
distribution and the guarantee going stale.

**What this is not.** It is not evidence about how polkajam handles
availability. Nothing in three live runs has put a valid assurance in front
of it.

**What would close it.** The engaged cores are chain state and have to be
read like chain state — at send time, from the anchor, exactly as the
*anchor* itself had to be (§14). Two pieces:

- the reference chain should pool the reports the NUT distributes, so a core
  becomes engaged at all. `RefChain::submit_guarantee` now exists — it was
  added for the CE 135 inclusion rows — and `reports_seen` already holds
  what to pool;
- `AvailPlan.cores` should become a read rather than a value, answered per
  slot. `Harness::engaged_cores()` is public in polkajam and is not in the
  oracle protocol yet, so this is one new message and no upstream export.

**What the first half changed.** The emulator now pools what the NUT
distributes (`pool_distributed_report`), so a core engages. The fourth run
is the first in which polkajam **sent an assurance of its own** — 45 of
them, where every earlier run reported `n4_ce141_not_exercised` — and the
first in which `n4_ce141_valid_assurance_included` was graded at all, three
times. Two of N4's rows went from never-asked to asked in one change.

**What the second half changed.** `AvailPlan.cores` is gone.
`drive_availability` reads the engaged cores per slot through a closure,
exactly as it reads the anchor, because both are chain state and change for
the same reasons. The oracle answers from `Harness::engaged_cores()` —
`yolo_availability`, the same thing the assurances extrinsic is checked
against — so the harness asks the question the node will ask. No upstream
export was needed.

Measured over three runs, the node's own authoring slots:

| | opportunities | lost to `core not engaged` |
|---|---|---|
| before either half (`n3n4-4`) | 8 | 5 |
| first half only (`n3n4-5`) | 5 | 2 |
| both halves (`n4-cores-1`) | 7 | 2 |

and `n4_ce141_valid_assurance_included` went 3 → 5 → **9** graded, with
`n4_availability_threshold_reached` passing for the first time: a report
the harness assured actually became available.

**What is left, and why it is not this.** Two slots still went to `core not
engaged`, consecutively and right after availability completed. The harness
reads the engaged cores about two seconds before the slot and the node
checks them when it authors; a core freed in between leaves an assurance
that was valid when sent and stale when used. Whether the reference's view
also lags the node's by a block fetch is not yet separated out — a run now
prints the engaged set whenever it moves, which is what will tell them
apart.

Either way the harness is no longer claiming a core it has reason to think
is free, so what remains is a question about the node dropping a stale
assurance rather than refusing to author. That is §22.

Related: §14, the same mistake about the same protocol — a value fixed at
plan time that is a function of chain state. §20, which made it visible by
making it bigger.

---

## 22. The node loses a block to an assurance that was valid when it was sent

**Status:** open, and now the strongest candidate for a real polkajam
defect this harness has produced. First seen 2026-11-18
(`sessions/n3n4-3`) when the harness's own assurances were all invalid;
reproduced in `sessions/n4-cores-1` after §21 closed, when they were not.
Still needs the settling §4 and §5 do before it is reported.

The other half of §21, read from the node's side. Sent an assurance naming a
core that carries no report, polkajam **accepted it into its pool** and then
could not author:

```
ERROR authoring  Error authoring block: block execution error:
  assurances error: core not engaged
```

Three of three authoring slots lost, in one run, to assurances from peers.
The node is right that the core is not engaged — that is §21, the harness's
error — but it discovered this while composing its own block, not while
deciding whether to pool what a peer sent it.

This is what `n4_ce141_invalid_assurance_excluded` exists to catch, and the
node's failure mode is worse than the row models. The row asks whether an
invalid assurance stayed out of the block; this node answers by not
producing a block at all, which the row scores as *not exercised*. A lane
that only ever looks at blocks cannot see a missing one.

**Before this is reported as a node defect it needs settling:**

1. Does JAMNP-S require a receiver to validate an assurance against the
   engaged cores *before* pooling it? `simple.md` is thinner here than the
   on-chain rule is.
2. Is a validator expected to defend its own authoring against what peers
   send it, or is an unauthored slot the accepted cost of a bad peer? The
   practical reading is that one peer should not be able to cost a validator
   its blocks by sending one malformed assurance.
3. ~~Observed in one run, and in a run whose assurances were all invalid
   for the harness's own reason. Reproduce against a run that sends valid
   ones — which means §21 first.~~ §21 is closed, and the behaviour
   survives it.

**What §21 closing did to this.** With the engaged cores read per slot, the
node still lost two of seven authoring slots (`sessions/n4-cores-1`), and
the two were consecutive and immediately after availability completed. So
the sharpened question is narrower and better than the one first recorded:

> The harness reads the engaged cores about two seconds before the slot and
> the node checks them when it authors. A core freed in between leaves an
> assurance that was **valid when it was sent** and stale when it is used.
> polkajam refuses to author at all rather than dropping it.

That is not a harness aiming badly any more. It is a validator losing a
block to a peer that did nothing wrong, and in a real network reports
become available constantly, so the window this needs is not rare.

**How wide the window is.** A run now prints the engaged set whenever it
moves, and the answer is that it moves constantly
(`sessions/n4-cores-2`, one validator's view):

```
slot 9884653 -> []
slot 9884654 -> [1]
slot 9884655 -> [0]
...
slot 9884665 -> []
```

A core is engaged for about a slot at a time. Against that turnover a
two-second lead is most of the life of the value, so "valid when sent,
stale when used" is not an edge case — it is the ordinary case, and it is
why the harness reading the set correctly still leaves the node losing
blocks.

That also disposes of the lag question: the harness is tracking the set
slot by slot and sending what it sees. What is stale by authoring time is
the assurance already sitting in the node's pool, which no sender can do
anything about. In a real network reports become available constantly and
every validator's pool is full of assurances for cores that have since
been freed.

Guarantees are the instructive contrast, verified while writing §21: block
composition re-checks every guarantee it holds and **skips** the ones that
no longer apply. Assurances are fatal instead. Whether that asymmetry is
deliberate is the first question to put to the conformance group.

**Why receive-time checking cannot be the answer**, traced through the node
2026-11-19. `AssuranceTracker::on_assurance_received`
(`availability/assurance_tracker.rs:140`) accepts an assurance when the
leaf is known, the signer is known, it is not a duplicate and the signature
verifies. It does not read the bitfield — and at that moment it has no
reason to, because the assurance *is* valid. The staleness appears
afterwards, between pooling and authoring. `assurances_at` (`:58`) then
returns the pool unfiltered and the author puts all of it in the block. So
the filter has to sit at composition, which is exactly where the guarantee
equivalent already sits.

Written up for the node's authors as `ask_polkajam.md`, with the code path,
the three runs, and what is deliberately not being claimed.

---

## 23. The row grading a node's assurance bits compared them against a slot — CLOSED 2026-11-18

**Status:** found and fixed the same day, on the fourth live run
(`sessions/n3n4-4`) — the first run in which polkajam ever sent an assurance
of its own, which is the only reason the row ran at all.

`n4_ce141_bits_have_reports` asks whether every core an assurance claims
carried a report. It failed 45 times out of 45, with evidence that gives
itself away:

```
the assurance for anchor 2e13e595 claims core(s) [0] that carried no report;
  cores with reports were [50520]
```

There are two cores in `tiny`. `50520` is a slot number truncated to `u16`.
The set was built from

```rust
.guarantees_prehashed().into_iter().map(|(_, core, _)| core as u16)
```

and `Extrinsic::guarantees_prehashed` returns
`(WorkReportHash, Slot, &GuaranteeSignatures)`. The second element is the
slot the guarantors attested at; the core index lives on the report. So the
row compared core indices against truncated slots, which can never match,
and **failed every assurance a conforming node sent**.

The same helper is used correctly a few lines away in N3's `included`, where
only the hash is taken, which is presumably how the shape passed review.

**The fix.** Read `guarantee.report.core_index` off the guarantees
themselves — and off the **whole chain**, not only the node's own blocks,
which was a second defect in the same three lines. A core is engaged by
whichever block carries the guarantee; the node authors one slot in six, and
now that the reference pools what the node distributes (§21) the engaging
block is usually the reference's. Reading only the node's blocks would have
left the row failing for a new reason as soon as the old one was fixed.

**Why nothing caught it.** The row needs the node to send an assurance, and
until §21's first half landed no live run had ever engaged a core, so
polkajam never assured and the row never ran. The simulated node's
assurances go through `n4_inclusion_sim_it.rs`, which builds its context
directly and does not exercise this derivation. A row can be wrong for
months if nothing ever reaches it.

Related: §18, the same kind of row — one that could not pass a conforming
node — found the same way, by a live run finally reaching it.

---

## 24. A reconnection re-fetched shards the node had rightly let go — CLOSED 2026-11-18

**Status:** found and fixed 2026-11-18 on the fifth live run
(`sessions/n3n4-5`). A regression §20 introduced and §20's own widening
exposed, which is the tidiest kind to find.

`n4_ce137_answered` and `n4_ce138_answered` failed 19 times each against a
node that had answered the first request correctly:

```
the NUT reset the CE 137 stream for root 5969ac3b index 1
```

Five passes, nineteen failures — one pass per emulated validator, then
failures. The availability exchange is spawned per **connection**, not per
run, and a run re-dials. Every reconnection re-ran the whole thing: fetch
the shard, fetch the segments, then assure. By the later rounds the report
had left the core and the node no longer held the bundle, so it refused —
correctly — and the lane scored each refusal as a hard failure.

It was latent before. With §20's twelve-slot window a peer reconnected once
or twice and the repeats were few enough to pass unnoticed; widening the
window to the rest of the run turned two repeats into five and the rows
went red.

**The fix.** The fetches are claimed once per validator per run, in
`EmuShared::fetched_shards`. Assuring is deliberately *not* claimed: a
validator assures every slot, and a reconnection should pick that back up —
which is the whole reason the exchange is spawned per connection in the
first place.

The claim is taken *before* the attempt, so two connections for one
validator cannot both fetch, and given back if the attempt never reached
the node. A refusal counts as reached — that is an answer, and the serve
rows grade it — but a stream that never opened is a connection dying, and
without the give-back that validator would lose its fetch for the whole
run. The first cut of this fix claimed unconditionally and the next live
run graded three validators' fetches instead of five, which is how the
distinction showed up.

Reconnection had a second, smaller effect on the assurance loop, fixed with
it: the loop restarts at the plan's first slot, which is by then in the
past, so `sleep_until_lead` returned at once and the offer was recorded
against a slot its anchor had nothing to do with. The inclusion rows read
`sent_in_slot`, so a stale one sends them looking at the wrong blocks. Slots
already past are now skipped.

**What it says about the others.** §20 widened the window for a good
reason, and widening it turned a latent defect into a visible one and then
found a second (§23) by finally reaching a row. Both were already there.
A longer run is a stronger test, and this is the third time in one day that
making the harness ask more questions has found the harness wrong before it
found the node wrong.

Related: §21, the same shape — an availability plan written once and
re-used while the chain moves past what it describes.

---

## 25. Only the validators the node dialled ever asked it for anything — CLOSED 2026-11-18

**Status:** found and fixed 2026-11-18 on the seventh live run
(`sessions/n3n4-7`), by comparing subject counts between runs rather than
looking for red.

The availability exchange — the CE 137/138 shard fetch, the CE 139/140/148
segment fetches, and the assurances that follow — was started on the accept
path only, the connections the **NUT** opened to the harness. N0's
preferred-initiator rule means the node dials some peers and waits for the
rest, so roughly half the emulated validators never ran it at all. A run
fetched shards for three validators out of five.

Nothing failed. Three passing rows and five passing rows read alike, and the
missing two produced no row to be missing. It surfaced only because §24
changed the count and the two runs either side were compared.

This is the same defect, in the same function, as the one the dial path
already carries a comment about:

> This was missing, so a run whose designated sender was a peer the emulator
> dialled had no distributor at all and sent nothing — the node never saw a
> CE 135 and the inclusion row failed with no trace of why, in half the runs.

That note was written for `start_report_distribution` and
`start_availability` never got the same treatment.

**The fix.** Start it on both paths, with one correction that the second
path makes necessary: a peer can now have two live connections driving the
exchange at once, and the assurance loop's "the head has not moved" guard
was a local, so two loops would each think they were first and put two
assurances from one validator under one anchor — the exact thing the guard
exists to prevent. The last anchor assured is now shared per validator and
checked and claimed under one lock. The shard fetch was already claimed per
validator by §24.

**What it broke, and what that exposed.** Driving the exchange from both
sides made `m2-sim`'s N4 inclusion test fail for exactly one validator in
five — the one the test has dial the node. The mock transport carries no
peer identity, so the stand-in could attribute an assurance only on
connections *it* had opened; once a validator's assurance could arrive on
one the node merely accepted, it was dropped unattributed.

A real node reads the sender's index off the connection's certificate. The
stand-in now recovers it from the signature instead: CE 141 carries no
validator index, but exactly one validator's key verifies a given
assurance. That answers the same question from what is on the wire, and
leaves the stand-in no longer dependent on which side opened the
connection.

**What it says about coverage.** Three of the defects found today were
invisible as failures: §19 and §20 showed as rows reporting *nothing*, and
this one as fewer subjects than the run deserved. A report that is green
because a question went unasked looks exactly like a report that is green
because the answer was right.
