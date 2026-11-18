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

**Status:** open, observed once, and it may be the spec rather than the node.
Opened 2026-11-15.

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
3. Seen once. It should be reproduced before anything is filed.

This is the first N3 row that failed for a reason that is not plainly the
harness's. Every earlier one was ours.

---

## 5. The node resets a well-formed CE 134 share with `NoError`

**Status:** open, observed once. Opened 2026-11-16.

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
3. Seen once. Reproduce before filing.

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

**Status:** open, observed once, and it may be a change in the node rather
than a standing defect. Seen 2026-11-17.

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

The pin moved to that branch on 2026-11-17 (`43689c3de`, and `0aaa2cb20`
once §14's export joined it), ahead of the PR
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
