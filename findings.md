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

## 4. The node applies the work-package size cap on CE 133 and not on CE 146

**Status:** open, narrowed, and most of what this finding used to say was
wrong. Opened 2026-11-15 as "the node accepts a CE 133 first message over
the size cap". Rewritten 2026-11-20, when §8's investigation showed the
node had been enforcing that cap all along and the harness could not see
the refusal.

**What was wrong.** This finding said:

> polkajam reads its first message with `read_decoded`, which caps at the
> type's `max_encoded_len`, and a `WorkPackage`'s is far above 200 KiB — so
> it is enforcing a different limit, not no limit.

`WorkPackageWithCore` has a hand-written bound, not a derived one
(`chain/guarantors/protocol.rs:29-33`):

```rust
impl MaxEncodedLen for WorkPackageWithCore {
    fn max_encoded_len() -> usize {
        CoreIndex::max_encoded_len() + SANE_MAX_PACKAGE_SIZE
    }
}
```

`SANE_MAX_PACKAGE_SIZE` is `200 * 1024`, so the bound is **204,802** — the
spec's `2 + (200 * 1024)`, to the byte. The node refuses an over-cap CE 133
first message, and says so in the words of the rule
(`sessions/ce133-1`, the node's own `peer-misbehaved` log):

```
Message size 205071 outside expected range 0..=204802
```

It refuses by closing the connection, which is what the lane could not read
and reported as acceptance — §8, in full. **The impl is byte-identical at
`b1ea8aca4`**, the pin this finding was measured against, so this was a
misreading when it was written and not a change in the node since.

**What is left, and it is sharper than what it replaces.** The same run
put 205,069 bytes on CE 146's work-package message against its 204,800-byte
cap. The node accepted it: no refusal, no misbehaviour logged, nothing. The
honest CE 146 submission in the same run was taken and shared with both
co-guarantors, so the protocol works and this is the cap alone.

The two protocols reach the package through different types:

| | first message | read as | bound |
|---|---|---|---|
| CE 133 | `Core Index ++ Work-Package` | `WorkPackageWithCore` | `2 + SANE_MAX_PACKAGE_SIZE` = 204,802 |
| CE 146 | `Work-Package` alone, message 2 | `ImmutableWorkPackage` | the derived bound, far above 200 KiB |

So it is one rule read two ways, because two types carry it — and the type
that carries the spec's number is the one that was written for this
protocol. `simple.md:383` states CE 146's cap in the same SHOULD form and
with the same rationale as `:362-364`.

**The question that survives.** Whether the cap binds the receiver at all
is still unsettled, and it is still a question for the conformance group
rather than the harness: `:362-364` and `:383` are both **should**, both
addressed to the message, and both justified by a protection offered to
guarantors, which reads more like a licence to refuse than a duty to.

What has changed is that polkajam can no longer be cited as a node that
takes the permissive reading. It takes the strict one on CE 133. The
likelier reading of CE 146 is now an oversight rather than a position.

**What this costs the question put to the spec authors.** `ask_dave.md` is
written around the claim corrected above and must not be sent as it stands.

`n3_ce133_oversized_refused` passes against polkajam as of 2026-11-20.
`n3_ce146_oversized_refused` fails, and is the only part of this finding
with a live failure behind it.

---

## 5. The node resets a well-formed CE 134 share with `NoError` — CLOSED 2026-11-20

**Status:** CLOSED. A harness defect, and the node was right. The share the
harness offered was anchored to a block the node had dropped from its recent
blocks, so refusing it was correct. Both of this finding's open questions
are answered, and neither answer was the one it expected.

**Question 1: is `NoError` polkajam's way of declining a share it does not
want?** No, and the node says so itself. Immediately above the CE 134
receive path (`chain/guarantors/stream_receiver.rs:511-512`):

```rust
// TODO @dave: For many errors here we will just close the stream with
// NetErrorCode::NoError. It may be helpful to add some more error codes.
```

The mechanism matches the comment. When `receive_other_work_package`
returns `Err`, the `BiStream` is dropped, and `Drop for Stream`
(`net/stream.rs:276-285`) kills it with `code.unwrap_or(ErrorCode::NoError)`.
So `NoError` is the default on an error path with no code attached, not a
decision — the node is refusing and cannot say why.

Unlike §30, the *shape* of the refusal is right: `simple.md:115-120` gives
the acceptor's stream reset as the way to reject, and that is what this is.
Only the code is empty. It is already known upstream, so there is nothing
here to report that is not already written down in the node.

**Question 2: should the harness be sharing at that slot at all?** Not with
that bundle. The node's own log, once its guarantor target was turned up
(`sessions/ce134-1`):

```
failed to receive WorkPackageSharing(0): guarantee table error:
  invalid anchor 0xdfa8dd97427288ed...
```

`check_anchor` (`chain/guarantors/table.rs:1077-1085`) requires the bundle's
anchor to be in the node's recent-block ring, and `recent_block_count` is
**8**. The share was composed during `plan_package` and sent at
`honest_slot + 9`, so its anchor was one or two blocks past the window every
time. The node could not have accepted it.

**The harness had already fixed this once, in the sender beside it.**
`spawn_report_sender`'s own comment records the identical failure for
CE 135:

> Composed when the run is planned, the report's refine-context anchor has
> aged out by the time it goes out seven to eleven slots later:
> `Invalid guarantee: anchor is not recent`.

CE 134's sender was the one that never got the lead. It has one now,
`SHARE_COMPOSE_LEAD_SLOTS`, the same two slots and for the same reason on
both sides: long enough that the anchor is still recent when the share
arrives, short enough that the bundle does not name a head the reference has
reached and the node has not. A fix applied to one of two senders is a fix
for one of two senders.

**The worse half: the sibling row was passing for the wrong reason.** The
lane shares twice, once honestly and once offering a shard count that is not
the active validator count. *Both* were being refused for the stale anchor,
so `n3_ce134_wrong_shard_count_refused` reported a pass across two pins
without the shard count ever being the reason for anything.

A reset carries no reason, so this lane cannot read *why* a share was
refused. The only thing that can attribute it is the honest share beside it
— identical but for the count — being answered. That control was failing,
and the row took the credit anyway. It now reports
`n3_ce134_wrong_shard_count_not_exercised` when the honest share was not
answered: **a row that cannot fail for the reason it names is not grading
that reason.**

**The false pass was written down in three places, and all three agreed.**
The row took a refusal as a verdict. The sim test asserted
`ShareRefused must leave n3_ce134_wrong_shard_count_refused passing`, so a
stand-in that refused *every* share was credited with refusing the faulty
one for its shard count. And the unit test offered the faulty share with no
honest share beside it at all and asserted every row passed — a context in
which the question cannot be asked, answered in the affirmative.

That is what makes this kind of defect expensive: the tests were written
from the same reading as the code, so they agreed with it rather than
checking it. All three are inverted now, and each fails if the gate is
removed. The unit test grades the three cases that exist — control
answered and fault refused, control answered and fault answered, control
refused — where before it graded one, the one that could not distinguish
anything.

**Confirmed against the node** (`sessions/ce134-3`): `n3_ce134_answered` and
`n3_ce134_hash_equals_the_reference` pass, where the first had failed since
2026-11-16; and `n3_ce134_wrong_shard_count_refused` passes for the reason
it names, in the node's own words:

```
failed to receive WorkPackageSharing(0): unacceptable shard count 5
```

**One fragility this exposed and did not fix.** A run between the two above
(`sessions/ce134-2`) sent no share at all and the report said only
"not exercised". `start_share_to_nut` claims the whole share plan for the
first connection to reach it and holds that one connection across the nine
slots until the share is due, and a node that closes connections every few
slots (§30) can take it away in the meantime. The two silent returns in the
sender now say which it was and quote the connection's end, so the next
occurrence names itself rather than being read as the node staying quiet.
Whether the sender should re-dial instead is open; it has not recurred.

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

**Repeated on the re-pin to `d92cadd30` (2026-11-19):** unchanged. The pin
still has `provided_count: u32` and `provided_size: u64` where the
published 0.1.29 has `u16` and `u32`, so the conclusion stands and the
dependencies stay on git.

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

## 7. The harness and the oracle resolved different codec versions — CLOSED 2026-11-19

**Status:** CLOSED 2026-11-19. The skew was fixed 2026-11-17; the guard
that was missing is now in the handshake.

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

**The guard, added 2026-11-19.** Nothing checked that they agree. Two
independently-resolved lockfiles can drift again on the next `cargo update`,
and the symptom would be a decoder disagreement across the socket with no
error anywhere -- the same shape as findings §6 and as the two defects the
oracle split introduced. DESIGN §8 states the rule this breaks: anything both
sides must compute identically belongs in one place. The codec is exactly
that, and it cannot live in `m2-oracle-proto` because each tree resolves its
own copy.

This entry proposed reading the resolved version out of each `Cargo.lock` in
a `build.rs` and comparing the two strings. What was built instead compares
the **behaviour**, because the version is a label and the behaviour is the
thing: `m2_oracle_proto::codec_probe()` encodes ten compact integers at the
width boundaries and decodes five canaries, and the handshake carries the
answers. `m2-oracle-proto` is compiled once in each tree against that tree's
own codec, so one source runs in both places and asks the question that
matters. It also costs no lockfile parsing and no guess about which lockfile
governs a crate that two trees compile.

Three of the canaries are the inputs that actually split the two versions,
measured against the published crates rather than assumed:

| input | 0.1.1 | 0.1.2 |
|---|---|---|
| `00` (canonical) | accepts | accepts |
| `80 00` | **accepts** | refuses |
| `c0 00 00 00` | **accepts** | refuses |
| `80 01` | **accepts** | refuses |
| `fc` (truncated) | refuses | refuses |

The last is there so the probe has a case both versions refuse: a probe whose
every canary discriminates cannot tell a codec that disagrees from one that
refuses everything. Encoding is compared too, byte for byte, even though §7
found it identical across these two -- a guard that only looks where the last
bug was is a guard for the last bug.

The probe cannot be defeated by the divergence it looks for. Encoding is what
puts the handshake on the wire, so a side that encoded lengths differently
would produce a frame the other could not decode at all, which the handshake
already reports as a malformed reply.

A mismatch names the input and both answers:

```
the oracle's codec and this build's do not agree -- decoding 8000: this
build refuses it, the other accepts it. They are separate cargo trees
asking for `jam-codec` by a caret requirement, so they can resolve
differently: compare `cargo tree -p jam-codec` here with the same in
`oracle/`, pin both to one version, and rebuild both.
```

`PROTOCOL_VERSION` goes to 9, because `PeerInfo` changed shape. That makes
an oracle binary built before this one unusable, which is the intent -- but
it cannot report itself as a version mismatch, because reading the version
is what fails: the old handshake is missing the probe, so it does not decode
at all. The handshake path says so instead, naming the likely cause and the
one command that fixes it, and a test drives a hand-encoded protocol-8
reply to prove it. Anyone pulling this runs `./scripts/prepare-nut.sh` once.

**Seen to fire.** `crates/m2-reference/tests/oracle_handshake_it.rs` stands a
fake oracle on a unix socket and drives the refusal through `Oracle::connect`,
with the lax probe set to 0.1.1's *measured* answers rather than an invented
pattern -- and a control where the codecs agree and the connection is
accepted, so the guard is not merely refusing everything. The protocol-version
guard, which had never been driven over a socket either, is tested there too.

## 8. The node accepts a CE 133 extrinsic message of the wrong size — CLOSED 2026-11-20

**Status:** CLOSED 2026-11-20. It was a harness defect, and the node was
right. The finding's title is the thing that was wrong: the node does not accept the
message, it refuses it — by closing the whole connection, which the lane
could not see and therefore reported as acceptance.

**What the node does.** CE 133's extrinsic message is read with
`read_exact(package.saturated_extrinsic_size())`
(`chain/guarantors/stream_receiver.rs:258`), and `read_exact` is not a byte
read:

```rust
pub async fn read_exact(&mut self, size: u32) -> Result<Vec<u8>, StreamErr> {
    self.read_range(size..=size).await
}
```

`read_range` reads the message's own 4-byte size and refuses anything
outside the range (`net/stream.rs:443-447`):

```rust
return Err(StreamErr::Misbehaviour(
    format!("Message size {size} outside expected range {size_range:?}").into(),
))
```

So the equality is enforced exactly as `simple.md:373` states it. But
`StreamErr::Misbehaviour` is routed by `handle_stream_err`
(`net/connection.rs:126`) to `handle_misbehaviour`, which is §30's two
lines: dock reputation, then `quic.close(...)`. The refusal lands on the
connection.

**What the harness did with that.** `spawn_package_sender` read the node's
verdict off one thing:

```rust
if let Err(ReadError::Reset(code)) = recv.read(&mut buf).await { ... refused = true ... }
```

A connection close fails that read a different way, so `refused` stayed
false and the row reported "the NUT accepted an extrinsic message whose
size did not equal the sum of the lengths its package declared". It had
rejected it as hard as it knows how. **A row that can see only one of the
two ways to say no will call the other one yes.**

**Measured on both sides**, `sessions/ce133-1`, with the node's own
misbehaviour log turned up:

| | |
|---|---|
| node (`peer-misbehaved`) | `Message size 1 outside expected range 0..=0` |
| harness (`[submission]`) | `closed by the peer: Message size 1 outside expected range 0..=0 (code 257)` |

The range is `0..=0` because the package in a fault submission declares no
extrinsics, and the fault is one byte on top of that
(`bodies.push(0xff)`). One byte over nothing is still a mismatch, and the
node found it.

**What this answers of the three questions §8 posed.** Question 1, does it
reproduce: yes, every run — but of the harness, not the node. Question 3,
which read path handles the message and did `saturated_extrinsic_size`
survive the re-pin: `read_and_verify_extrinsics`, and yes, it is alive at
`d92cadd30`. Question 2 — does it reproduce at the old pin — is moot: there
was never a node defect to date.

**Why it looked like a re-pin regression.** §8 guessed that the row "passed
before and failed after", with twenty-seven commits in between to blame.
The real explanation was the one §8 also offered and did not pursue: the
row only began running to completion after §1 was fixed. Before that it was
unexercised, and an unexercised row is not a passing one. Two candidate
explanations, and the finding chased the expensive one.

**The fix.** `SubmittedPackage` now carries the connection's end as well as
the stream's reset, and `refused_either_way()` counts both — a reset, or a
close the *peer* performed. A timeout or a hang-up on this side is still
not a verdict. The rows are renamed from `_reset` to `_refused`, because
they ask whether the node applied the rule and not where it put the answer.
Where it put the answer is `rejection_keeps_the_connection` in N0 (§30),
which now also sees the builder's connection. One row per question.

`n3_sim_it` grades the fix against a stand-in that closes on an over-cap
package in polkajam's own words, with a node that neither resets nor closes
as the control — the row must still fail that one, or widening the
predicate would have made it unfailable.

Related: §4, which had the same defect under it and one real node gap left
over once this was removed.

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

**Upstream** as polkajam#1401, from branch `jv-export-n4`, merged
2026-11-18:
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
to fail. **#1401 merged 2026-11-18**, squashed as `d92cadd30`, and the pin moved
there on 2026-11-19. Because it was squashed, `b1ea8aca4` is not an
ancestor of upstream main, so the move was to a different commit rather
than a fast-forward: `hazmat::merkle` re-exports all four symbols there,
and `submit_assurance`, `submit_guarantee` and `engaged_cores` are public
on the harness. Two other commits came with it — #1382, which threads a
chaos controller through the CE 133/134/146 receive path, gated off in an
ordinary run, and #1404, an STF divergence fix. Neither moved a verdict:
the live run on the new pin (`sessions/repin-1`) reports the same hard
failures as the run before it.

## 10. DESIGN had the erasure recovery threshold wrong — CLOSED 2026-11-17

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

`simple.md:682-683` asks for roughly two seconds' lead. The row now asks for
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
the same branch as the Merkle exports (§9) and **merged as
paritytech/polkajam#1401** (2026-11-18, `d92cadd30`).

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

**Merged upstream** in **paritytech/polkajam#1401** (2026-11-18,
`d92cadd30`): one more re-export in `hazmat::merkle`, beside the two added
for the justification builders (§9). The same shape as those, and as
`submit_assurance` (§14): a re-export and a visibility bump, no behaviour
change.

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

## 17. The segment protocols cannot be exercised against a live node — CLOSED 2026-11-19

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

**What it took to close.** The service can be asked, and was not blocked at
all — only unexplored. The dev bootstrap service reads its payload as an
encoded `Instructions` and carries an `Export { data }` instruction that
calls `export_slice` per blob. `jam-bootstrap-service-common` is published
and host-buildable, and its own description is "useful for interoperating
and constructing work items".

So the honest submission now exports four segments, and a live run asks for
them. `a_work_item_asked_to_export_does` holds the service to it, with a
non-exporting control so a passing count cannot just be the engine echoing
back what it was handed.

**Measured** (`sessions/n4-exports-3`): CE 139 and CE 140 answer and
verify against polkajam, five of five on every row. CE 148 is declined,
which `simple.md:663` allows and the row records as Soft — the first time
any of the three has been put to a real node.

Opening the door immediately found §26 behind it: the row checking CE 140's
justifications had been comparing against the wrong tree the whole time,
and nothing could have noticed while no package exported anything.

**The import half, closed the same way.** The fourth row waiting on this
was `n3_ce134_shares_the_submitted_package`, which grades the mappings on a
share the node *sends*. It needed a package that imports segments, and the
exports made one possible: the run now submits a last package whose work
item imports segment 0 of the first one, naming it by work-package hash so
the node has to resolve the hash to a segments-root and say so.

Opening that door found the row was asking for the wrong thing — §27.

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

---

## 26. The segment-shard justification was checked against the wrong tree — CLOSED 2026-11-19

**Status:** found and fixed the same day, on the first live run in which a
package exported anything (`sessions/n4-exports-1`). A harness defect that
the simulated node was structurally unable to see.

`n4_ce140_justifications_verify` failed five times out of five against a
node that was serving correctly:

```
CE 140 for root f38a03cd index 0: 0: did not verify, 1: did not verify,
  2: did not verify, 3: did not verify
```

Every one, not some, which is the shape of a bad input rather than a bad
proof.

A segment justification proves that a slice sits at its index in a Merkle
tree built over **every segment the package exported**. Checking one needs
the size of that tree. The runner passed the size of the *request*:

```rust
segment_index,
shards.requested.len() as u32,
```

**Why the simulated node could not catch it.** `n4_sim_it` held two
segments and asked for both, so `requested.len()` and the true count were
the same number. They are the same number in every arrangement the test
could make, because the test chose both. The two only come apart when a
package exports more than a run asks for — and until §17's fix landed, no
package exported anything at all, so the live surface could not come apart
either.

That is a blind spot with a shape worth naming: a test that supplies both
sides of an equation cannot discover that the equation is wrong.

**The fix, and the second number it took to get there.** `AvailPlan`
carries `segment_count`, `SegmentShardsServed` records it, and the check
uses it. What that number *is* took two live runs to settle, because three
of them meet at this call site:

| | |
|---|---|
| what a run asks for | `MAX_SEGMENTS_ASKED`, capped — what the code used |
| what the package exported | `exports_count` — the first fix, still wrong |
| what was actually coded | the exports **plus their import-proof pages** |

`import_proof_pages` appends one page per `PROVEN_PER_SEGMENT` (64)
segments to the vector *before* the set is erasure-coded
(`chain/logistics.rs:151`, `availability/mod.rs`: `segments.append(&mut
proof_segments)`), so a four-export package is coded as five segments. The
engine states the same formula at its maximum in
`jam_types::max_export_segments`, which is the cross-check that this is the
rule rather than an arithmetic that happens to fit.

The first fix passed the sim and failed live, which is what sent the search
to the engine instead of to another guess.

**Proven.** `n4_sim_it` now holds four segments and asks for two. The
honest node passes with the fix and fails all five rows without it, which
is the live failure reproduced on demand in 0.16 s.

**Why the simulated node cannot model the second half either.** It codes
exactly the segments it is handed and appends no proof pages, so for the
sim `segments.len()` really is the tree size. That is why the first fix
passed there and failed live. The count is a property of how a segment set
was produced, not a formula that holds everywhere, which is why it belongs
on the plan rather than being derived at the point of the check.

**Measured after the second fix** (`sessions/n4-exports-3`):
`n4_ce140_justifications_verify` five of five HARD PASS, with CE 139's
rows passing alongside. All three segment protocols have now been put to a
real node: CE 139 and CE 140 answer and verify, and CE 148 is declined,
which `simple.md:663` allows and the row records as Soft.

Related: §23, also a row that could not pass, also found the first time
anything reached it. §17, which had to be closed before this could be seen
at all.

---

## 27. The CE 134 mapping row asked for a mapping no node can send — CLOSED 2026-11-19

**Status:** found and fixed the same day, while building the importing
package §17 was waiting on. A harness defect, in a row that had never run
against anything.

`n3_ce134_shares_the_submitted_package` graded the segments-root mappings
on a share the node sends, and asked that they name **the package being
shared**:

```rust
let names_it = share
    .mappings
    .iter()
    .any(|(package, _)| package.0 == submitted.package_hash);
```

They never can. The mappings are `len++[Work-Package Hash ++
Segments-Root]` (`simple.md:449`), and `simple.md:412-415` says what they
are for: a guarantor may share a package only once "all import segments
have been retrieved. Note that this will involve mapping any WP hashes in
the import list to segments-roots." The mapping is the **import list's**
resolution, carried to the co-guarantors so they can fetch the same
segments and check the bundle against them.

The package being shared cannot appear in it. Its own segments-root does
not exist yet — producing it is the refining the share is asking for.

polkajam agrees, and says so in one line: `collect_imports` builds the
lookup from `RootIdentifier::Indirect(wph)` entries of the import list
(`chain/logistics.rs:51`), and `guarantor.rs:244` puts exactly that
`sr_lookup` into the sharing context.

**Why nothing caught it.** The row was gated on the mappings being
non-empty, and mappings are empty for a package that imports nothing,
which was every package this harness built. The gate never opened, so the
row never ran — against a live node or a simulated one. It was counted,
correctly, as unproven (§17), and the unprovenness was read as "waiting
for an arrangement" rather than "waiting to be found wrong".

The gate also made the most plausible defect unreportable. A node that
fetched its own import segments and never passed the resolution on sends
*no* mappings — and a row that only looks at shares with mappings cannot
fail that node.

**The fix.** `n3_ce134_maps_the_imported_package`, in a check of its own
(`n3_ce134_mappings`) because it is gated on something no other row needs:
a submission that imports. The submission carries what it imported from,
so the row compares against a known pair rather than against a shape:

| | |
|---|---|
| the key | the hash of the package imported from |
| the value | that package's `exports_root`, as the engine computed it |

Both halves, because a node that sends the right key under the wrong root
has resolved the import *wrongly*, and `simple.md:444-446` lets the
receiving guarantor trust the mapping blindly — so a wrong one sends it to
fetch the wrong segments.

**Proven.** `m2-sim/tests/n3_ce134_mappings_sim_it.rs` passes the pair a
conforming node sends and fails three ways of not sending it: no mappings
at all, a mapping for some other package, and the right package under the
wrong root. The positive is in the same arrangement as the negatives,
because a row that is absent is not a row that passed — which is the whole
of how this one survived.

**And the run can now ask it.** The last submission of a run imports
segment 0 of the first, by work-package hash. It is gated on the chain: a
guarantor resolves that hash out of the packages its chain has seen
(`state_db.rs:1309`), so until the guarantee for the exporting package is
in a block the import names nothing — and a node asked too early does not
refuse the submission, it takes it, fails to fetch, and never shares. That
would read on the report as a node refusing to share a package it was
given. So the builder checks first and skips rather than poses a question
the node cannot answer, and the row says it was not exercised.

Related: §18 and §23, also rows that could not pass a conforming node;
§26, also found the first time anything reached it. Three of the four were
invisible for the same reason — nothing had ever asked.

---

## 28. The spec moved under P3's design, and nothing said so — CLOSED 2026-11-20

**Status:** CLOSED. The repository is re-pinned to `simple.md` at **aa0e2b8
(2026-10-26)**, every citation renumbered against the old text, the CE 144
and CE 145 codecs rewritten, and DESIGN's N5 rows re-specified. Opened
2026-11-19 while checking §4's citations.

**What this finding got wrong about itself.** It said:

> Nothing is wrong in the code: N5 and N6 do not exist yet.

The *lanes* do not exist. The **codecs do**, and they modelled the
superseded wire in full: `AuditAnnouncementMsg` with its `Tranche` byte,
`Evidence` with `Tranche0`/`Subsequent` variants, `SubsequentEvidence` with
its no-show list, and a `Judgment` whose guarantee was an `Option` appended
after the signature. Fourteen tests asserted those shapes, three of them
hand-built byte vectors. §11 and §15 are the same defect — a codec that is
a shape model rather than the wire — and this is a third instance, found
before a lane was built on it rather than after.

**The four hunks, and what each cost:**

| section | change | cost |
|---|---|---|
| Shard assignment `:506-521` | $R$ for 6 validators, 2 → 3 | none. §10 had already taken 3 from the engine, before the spec said so. The citation's range is unchanged |
| CE 138 `:558-583` | `Auditor -> Assurer` becomes `Node -> Assurer`; non-validators may request, assurers may throttle | none behaviourally. The section grew three lines, so its own range and everything after it moved |
| CE 144 `:746-785` | announcement restructured | the codec, its tests, and DESIGN's N5 rows |
| CE 145 `:787-828` | judgments batched, guarantee moved inside the discriminator | the same |

**The three shape changes, as the lane must now assert them.**

*The tranche is not on the wire.* An announcement carries an `Intent` byte
— 0 for the initial tranche, `1 ++ Core Index` for a later one — and a
recipient derives the tranche from the signature's VRF output
(`:769-771`). The old codec sent a `Tranche` field no conforming node
reads.

*No-show evidence is gone.* A later-tranche announcement names one
work-report on one core and proves the requirement with `S(r)` alone. The
list of previous-tranche announcements standing for the no-show count does
not exist.

*The guarantee moved inside the validity discriminator.* `Validity = 0 ++
Guarantee (Invalid) OR 1 (Valid)`, so on a negative judgment the guarantee
sits **before** the work-report hash rather than after the signature. This
is the change most likely to be got wrong by someone patching the old
struct, because an `Option<Guarantee>` appended at the end still compiles,
still round-trips against itself, and is wrong on the wire by the width of
a guarantee. The codec's test asserts the hash's *position* after the
guarantee, not merely that both are present.

**Both protocols batch.** CE 144 sends `[Announcement]` and CE 145 sends
`[Judgment]`, and CE 145 may mix auditors, work-reports and epochs in one
message (`:814-815`). A lane expecting one value per message would fail a
conforming node on its first batch.

*Corrected 2026-11-20:* this paragraph originally called each of those a
"length-prefixed vector". They are not. `:148-152` says a sequence not
preceded by `len++` takes its length from context, and "in the case of a
message consisting of a single sequence, the length of the sequence is
implied by the message size in bytes". So `[Announcement]` and `[Judgment]`
are the items concatenated with no count in front, and a reader decodes
until the message runs out. §33 records what that error cost.

**The re-pin, and why it was not optional.** DESIGN §2 states the
invariant: *"Every `simple.md:NNN` in this repository refers to that
revision."* Re-specifying N5 against HEAD while the rest cited a96dc6b
would have broken it, and a repository carrying two spec revisions without
saying which is which is the defect class §6 and §7 record. So the pin
moved and everything moved with it.

**How, and what it cost.** Mechanically, against the old text rather than
by eye. Each `simple.md:NNN` citation was read at a96dc6b, matched
byte-for-byte against aa0e2b8, and rewritten only where exactly one
candidate matched: **93 renumbered across 14 files**, 157 already identical,
and the rest reported rather than guessed. Of those reported, all but four
were CE 144/145 citations being rewritten anyway.

Two lessons worth keeping:

- **Most citations moved by +3, and the ones that mattered did not.** The
  CE 144/145 citations moved by −2, −6, −8 or changed outright. Renumbering
  by a constant offset would have left the N5 citations plausible and
  wrong.
- **Do not run the renumberer over a file already written against the new
  revision.** Several citations in the rewritten codec were renumbered a
  second time, because their *old-revision* text happened to match
  somewhere else at HEAD — `:819` became `:811`, `:825` became `:819`. They
  were caught by reading every citation in that file back against HEAD,
  which is the check this work ends with and the one worth repeating on any
  future re-pin.

**What it does not close.** §4's question survives: the size-cap wording is
untouched since 2026-03-22, so it is still unanswered at HEAD.

## 29. A validator connection dies mid-run, and nothing re-dialled it — CLOSED 2026-11-19

**Status:** CLOSED 2026-11-19. The consequence is fixed and measured here;
the cause turned out to be a node defect and is §30.

Found 2026-11-19 while checking whether the advisory bumps had
broken anything. It is neither the bumps nor the re-pin: it reproduces on
both pins and both dependency sets.

The node loses its connection to one emulated validator part-way through a
run and does not get it back:

```
ERROR guarantee_broadcaster  failed to send guarantee to eled3vb5...:
      Error opening stream: Not connected to the peer
WARN  authoring  Ticket broadcast failure, communication error with peer
      eled3vb5...: Error opening stream: Not connected to the peer
```

That SAN is **validator 4** (`SecretKeyset::trivial(4)`). In
`sessions/bumps-1` the node went from five peers to four 102 seconds in and
stayed there, and the rows it cost were scattered across lanes that have
nothing to do with each other:

| row | lane | what the report said |
|---|---|---|
| `n2_self_proxy_ce132_all_peers` | N2 | "did not reach peer(s) [4]" |
| `n3_ce133_shares_with_both_co_guarantors` | N3 | "never opened CE 134 to validator 4 ... it reached {0}" |

Read off the report these are two unrelated node defects, one about ticket
broadcast and one about work-package sharing. They are one connection.

**Why it stayed dead.** `preferred_initiator` makes the *emulator* the one
that dials for validators 3 and 4, so the node is right to sit and wait
(`simple.md:70-80`). On this side `dial_nut` returns when its connection
ends, and both call sites discarded that with `let _ =`. The task finished,
nothing re-dialled, and nothing was logged — the harness did not know it
had lost a peer, and neither did the report.

**Counting it properly.** The first version of this entry said the drop
happened in most runs. That was wrong, and the way it was wrong is worth
keeping: three of the four occurrences were at 250 s, 259 s and 360 s into
a 300-second window — the run tearing its own dial tasks down at the end.
Only `bumps-1` lost a peer mid-run. Timestamps distinguished them; counting
log lines did not.

**The fix, in two halves.** A keep-alive, because quinn defaults to a
30-second idle timeout and **no** keep-alive and this harness set neither,
so any quiet link was a candidate. And `hold_connection`, which re-dials
when a connection ends and says so, for the peers this side is responsible
for initiating.

**Measured** (`sessions/keepalive-1`, the seed that failed before): no
`Not connected` in the node's log at all, five peers for the whole window,
and the hard rows back to the five known ones — `n2_self_proxy_ce132_all_peers`
and `n3_ce133_shares_with_both_co_guarantors` both gone.

**The cause, since 2026-11-19: §30.** The node closes the whole connection
when it will not accept a message, and the harness spoils one assurance per
validator partway through every run. Validator 4's is signed with the wrong
key, so from the spoil slot on, each of its assurances cost it the
connection — which is the "every 37 seconds" above.

Two things in this entry were wrong, and both are worth keeping. The
hypothesis — that the node was *also* dialling validator 4 and the two
connections displaced each other — was already contradicted by the run that
proposed it: `nut_waits_where_not_preferred` reads the whole log, not the
opening, and it passed. And "it is still only validator 4 — never 3" was an
artefact of this entry's own fix: validator 1 was being dropped twice as
often, on a connection the node re-dialled itself, and the fix logged only
the side the harness dials. A log that covers half the subject will find
half the pattern and make it look like the whole one.

Related: §18, §23 and §27 — rows that failed for reasons that were not the
node's. This one differs: the row was right and the *subject* was missing.
The node really did not reach validator 4, because there was nothing there
to reach.

## 30. A message the node refuses closes the whole connection

**Status:** open, and it is a node defect. Found 2026-11-19, chasing §29's
open half: a connection to one emulated validator that ended every few
slots and nothing could explain.

The node answers a message it will not accept by closing the QUIC
connection, with an application close that says what it did not like:

```
closed by peer: Bad assurance: Invalid message (code 257)
closed by peer: Invalid guarantee: Invalid work report hash (code 257)
```

A CE stream has one way to be refused. The acceptor resets it, and that
reset *is* the rejection: "resetting/stopping of a stream by the stream
acceptor should be considered rejection of the request or failure to
process the request" (`simple.md:115-120`, at a96dc6b, the revision
`DESIGN.md` §8 names — and byte-identical at those same lines at upstream
HEAD aa0e2b8, so §28's spec drift does not reach this). Closing the connection
instead takes every other protocol with that validator down with it —
block requests, ticket distribution, package sharing, availability — none
of which had anything to do with the message that offended.

**The evidence, from `sessions/teardown-2`.** The harness spoils one
assurance per validator from a chosen slot, and which fault each poses is
fixed by index (`spoil_for`, `peer % 3`): validators 0 and 3 send a wrong
anchor, 2 claims a core carrying nothing, **1 and 4 sign with the wrong
key**. From the spoil slot at t=217.9 s:

| validator | fault posed | assurances after the spoil | connections closed |
|---|---|---|---|
| 0 | wrong anchor | 6 | 0 |
| 1 | **bad signature** | 16 | **16** |
| 2 | empty core | 18 | 0 |
| 3 | wrong anchor | 18 | 0 |
| 4 | **bad signature** | 8 | **8** |

One close per bad-signature assurance, none anywhere else. The controls are
in the same run and on the same transport: validator 3 is dialled by the
same side as 4 and sends its assurance in the same instant, and its
connection survived the whole window. **An assurance the node cannot accept
is fine; an assurance it cannot verify costs the connection.**

The second reason closed one connection each on validators 0 and 1. That is
the same behaviour reached through CE 134 rather than CE 141, which is what
`bumps-1` — the session §29 was written from — had been showing all along.

One more control, found by running the lanes wrong. `sessions/teardown-1`
was launched without `--lanes`, so N3 and N4 never ran, no assurance was
ever sent — and across the whole 300-second window the node closed nothing
and held five peers throughout. No invalid message, no close.

**It reproduces.** `keepalive-1`, `bumps-2`, `repin-1` and `n3-imports-1`
all show it, before this was understood: in each, validator 4's *last*
assurance is the first one whose anchor diverges from validator 3's, which
is the spoil slot, and the connection never came back. Validator 1 poses
the same fault and was dropped just as often — invisibly, because the node
is the preferred initiator there and re-dialled itself within the
millisecond.

**What it costs a report.** §29's table: `n2_self_proxy_ce132_all_peers`
"did not reach peer(s) [4]" and `n3_ce133_shares_with_both_co_guarantors`
"never opened CE 134 to validator 4". Two lanes, two unrelated-looking node
defects, one connection — and neither row is about assurances at all.

**The hypothesis this replaces.** §29 proposed that the node was also
dialling validator 4 despite not being the preferred initiator, the two
connections displacing each other. That was wrong, and the run already had
the answer: `nut_waits_where_not_preferred` reads every `NUT_INITIATED`
observation in the log, not just the opening ones, and it passed. The node
never dialled 3 or 4 at all. What made the hypothesis attractive was that
validator 4's drops were the only ones visible — and that was an artefact
of §29's own fix, which logged re-dials on the side the harness dials and
said nothing on the side it accepts.

**The row.** `rejection_keeps_the_connection` (Soft), which reports each
close with the node's own code and reason. Soft on purpose: `simple.md`
gives the stream reset as the way to reject but nowhere forbids closing the
connection, and hard-failing a node on a rule nobody wrote is the mistake
§18 and §27 record.

Two write-ups, because the question splits in two. Whether the escalation
is allowed at all is the spec author's to answer (`ask_dave_rejection.md`),
and the behaviour itself is polkajam's to hear about
(`ask_polkajam_rejection.md`). If the answer is that a rejection must stay
on its stream, this row becomes Hard.

Writing them turned up two things the finding did not have. The measured
table is the source read back rather than a sample:
`AssuranceTrackerError::is_misbehaviour` is true for one variant, returned
from the signature check alone, so a wrong anchor returns `UnknownLeaf` and
an empty-core claim is never looked at — three of the five faults *cannot*
reach the close and two must. And the escalation is deliberate, not an
oversight: `Connection::handle_misbehaviour` adjusts reputation and closes
the connection in the same two lines, and `Stream::peer_misbehaved`'s own
comment assumes the connection is already gone. That makes this a policy
question rather than a bug, which is how both write-ups put it.

The spec reading also came out stronger than "nowhere forbids it". Every
refusal `simple.md` describes is a stream reset — `:115-120`, and again at
`:252` and `:336`, the latter for a ticket the node cannot verify because
finality is behind — not the same as a signature that fails, but the
closest the document comes to declining something it cannot check. The one
connection close it prescribes is at the certificate level (`:20`), and the
one behavioural consequence it puts at connection level (`:82-84`) is about
builders proving their credentials, not validators, who are instead asked
to stay connected to one another (`:61-63`). None of that forbids the
escalation, so the row stays Soft; all of it is why the question is worth
asking.

`crates/m2-sim/tests/n0_connection_close_sim_it.rs` grades both directions
against a stand-in that closes on a refusal, with the honest node as the
control. Both runs put the same bytes on the wire; only the answer differs.

**Live** (`sessions/teardown-4`, 581 rows): thirteen closes, thirteen rows,
each naming the validator, the node's own wording and code, and the instant
— which is the same clock the trace records, so a row points at the bytes
that preceded it. Eleven were `Bad assurance: Invalid message`, eight of
them validator 4's and three validator 1's; the other two were
`Invalid guarantee: Invalid work report hash`, one each on validators 0
and 1.

**What made it findable.** `handle_connection` discarded the error that
ended its accept loop, so every connection death looked alike. The
transport now reports the end as [`ConnectionEnd`] — the peer's close with
its code and reason kept apart from an idle timeout and from this side
hanging up — and the emulator records every one, on the connections it
dials and the ones it accepts. The accepted half had never been logged at
all, which is why validator 1 went unnoticed through five sessions.

---

## 31. Only the first package a run submits is ever accumulated

**Status:** open, and it is a harness limitation rather than a node defect.
Found 2026-11-20 while building N6, which is the first lane to need
anything from *accumulate* rather than from the wire.

A work item's `Solicit`, `Transfer`, `Bless` or any other on-chain effect
takes place in accumulate. A report is accumulated only once it is
available; available means assured; and the harness assures exactly one
report per run, because the availability plan is built from the first report
the node distributes (`m2-runner`'s `plan_package`). So **the first package
is the only one whose accumulate ever runs.** Every later package is
guaranteed, included, and then sits there.

**Measured** (`sessions/n6-2`). The solicit was given its own submission one
slot behind the honest one. The node guaranteed it, included it, and the
bootstrap service accumulated exactly once -- for the honest package, at
slot 9907730. The announcement that followed was correctly ignored, because
no service had asked for anything. Moving the solicit onto the honest
package made the same run pass (`sessions/n6-3`).

**What it costs today.** N6's `Solicit` rides the honest package rather than
a submission of its own, which is not where it belongs: the honest package
is what N3 and N4 grade, and it now has a second job. The comment on
`work_item_that_exports_and_solicits` says why it has to, so the next reader
does not "tidy" it apart and spend a run finding out.

**What it would cost a lane that needs two.** Any future row that needs two
independent on-chain effects -- a solicit and a forget, a transfer and a
lookup -- cannot have them, because the second package's accumulate will
never run. That is the shape to watch for, and it is a property of the
harness's availability plan rather than of the protocol.

**What would fix it.** The availability plan would have to cover every
report the node distributes rather than the first, which means assuring more
than one core's worth per run. `findings.md` §12 records why the plan cannot
be written before the run; this is the other half of the same constraint and
is worth solving together with it.

**Why this is not a node finding.** Nothing polkajam did here was wrong. A
report that is not available must not be accumulated, and the node declining
to act on a preimage no service had requested is the rule working.

---

## 32. The node implements the superseded CE 144/145 wire format

**Status:** open, but **not** the node finding it first looked like.
Found 2026-11-20 while starting N5, and corrected the same day: the fix is
already written upstream, on a branch that has not reached `main`. What is
left is an integration-timing finding, which is a different thing to report
and a different thing to ask. See "Who has already fixed it" below, which
was written after the rest of this section and overrides its framing.

`jam-np` rewrote CE 144 and CE 145 at **aa0e2b8 (2026-10-26)**, which §28
records and which this repository is now pinned to. polkajam at
`d92cadd30` (HEAD 2026-11-18) still sends the shape that revision replaced.

**Measured, from the node's own traffic** (`sessions/n6-5`, five CE 144
streams and five CE 145 streams opened by the NUT):

```
CE 144, 132 bytes:
  74e5b68d…6dad  header hash (32)
  00             tranche
  01             compact length, one entry
  0100           core index 1
  8a897398…b214  work-report hash (32)
  44342640…5e0e  Ed25519 signature (64)
```

That is `Header Hash ++ Tranche ++ len++[Core ++ WRHash] ++ Ed25519`, the
pre-aa0e2b8 shape, to the byte. The current spec asks for
`Header Hash ++ Validator Index ++ Intent ++ Bandersnatch Signature`
(`simple.md:778`), where the tranche is *not* sent — recipients derive it
from the signature's VRF output (`:769-771`) — and the signature is 96
bytes rather than 64.

Confirmed in source rather than inferred from the bytes:
`auditing/mod.rs:202-213` is

```rust
pub struct AnnouncementMessage {
    pub initiator: HeaderHash,
    pub tranche_index: TrancheIndex,
    pub announcement: AnnouncementData,   // cores + ed25519::Signature
}
```

**CE 145 is the same story**, and subtler — subtler than this section
first claimed. Its 103 bytes are
`Epoch(4) ++ ValIdx(2) ++ 01 ++ WRHash(32) ++ Ed25519(64)`, and since
`[Judgment]` carries no length prefix (`:148-152`) and `Validity = 1` is
one byte in both revisions, **a single positive judgment is byte-identical
between them**. The node's CE 145 message above is already exactly what
`aa0e2b8` asks for. The divergence is entirely in batching and in the
negative form, where `aa0e2b8` inlines `Validity = 0 ++ Guarantee` and
`a96dc6b` sent the guarantee as a separate second message. A harness that
only ever saw single positive judgments could not tell the two apart at
all.

**The dates.** `auditing/mod.rs` was last changed by #1319 on 2026-10-09,
seventeen days before the spec revision. Nothing has touched it since, and
HEAD is three weeks past the change.

**What it costs N5.** A lane built against the current spec — which is what
§28 re-specified and what conformance means — fails polkajam on every
CE 144/145 row, for one reason, every run. That is true but not useful
feedback, and a lane whose every row fails for a known cause stops being
read. The plan was that N5 would grade the *behaviour* an auditor owes
(does it announce when newly required, does it publish a judgment for what
it announced, does it announce the same report twice) from whichever shape
arrives, and name the wire divergence in one row of its own.

**N5 is parked instead — decided 2026-11-23.** Reading both shapes means
re-adding the decoder §28 deleted, to grade a wire format expected to stop
existing within weeks, producing rows about a node nobody will run again.
The project gets nothing from grading something that is about to change.
So N5 waits for `feat/tranche-redesign` to reach `main`, and the harness
spends the interval on a lane the redesign cannot invalidate.

Two things to carry forward when it is picked up, because both are easy to
forget by then:

- **The redesign makes N5 harder, not easier.** The old format declares
  the tranche and the cores; `aa0e2b8` declares neither, deriving both from
  the Bandersnatch VRF output. The harness has `ring_vrf` for tickets but
  no audit VRF and no core selection, and `ce141_145.rs:139` holds the
  signature as an opaque `[u8; 96]` it never verifies. Grading a
  conformant announcement means implementing the GP's core selection and
  tranche derivation — **from the GP, not from `block_tracker.rs`**, or
  the lane checks only that polkajam agrees with polkajam, which is §18's
  rule and the reason this note exists.
- **The two formats are separable by length**, if a tolerant reader is
  ever wanted after all. Old CE 144 messages are `98 + 34n` bytes; new ones
  are sums of 131 and 133. Enumerated to twelve batched announcements, the
  sets first meet at 1050 bytes (eight announcements against a 28-core old
  one) and nothing sends either. An earlier draft of the polkajam document
  claimed a size check could not separate them; that was asserted, not
  computed, and it was wrong.

**What it is not.** Not a reading the spec leaves open, unlike §4. The
revision is unambiguous and current, and the harness is pinned to it.

### Who has already fixed it

Checked 2026-11-20, before writing any patch, by looking for prior art on
the remote rather than assuming there was none. There is:
`origin/feat/tranche-redesign` implements `aa0e2b8` in full, and was last
pushed to on **2026-11-20**, the same day as this finding.

- `crates/node/src/auditing/np.rs` on that branch is a new file holding
  exactly the current shapes: `AnnouncementMessage { initiator,
  validator_index, intent, signature: vrf::Signature }` with
  `AnnouncementIntent::{Initial, Later(CoreIndex)}`, and
  `JudgementMessage` with `Validity::{Invalid(Slot, GuaranteeSignatures),
  Valid}`. The Bandersnatch signature is 96 bytes
  (`PREOUT_SERIALIZED_SIZE + PROOF_SERIALIZED_SIZE`).
- `communication.rs` sends and reads both as vectors —
  `write_encoded_seq` / `read_decoded_bounded_seq` — one message per
  stream, so `--> [Announcement]` and `--> [Judgment]` are right too.
- The tranche is derived rather than declared:
  `block_tracker.rs:1092` calls
  `later_tranche_from_entropy(announcement.signature.vrf_output(), …)`,
  and `:1070` calls `select_cores_to_audit(announcement.signature
  .vrf_output())` for the initial case. That was the part this finding
  flagged as the hard one, and it is done.
- It arrived as two reviewed PRs inside the branch: **#1359** "Auditing:
  align with CE 144/145 updates from NP" and **#1370** "Small refactorings
  after the NP's CE-144/145 re-implementation".

**Why it has not landed.** `feat/tranche-redesign` is 46 ahead of `main`
and 22 behind it (`git rev-list --left-right --count
origin/main...origin/feat/tranche-redesign`, re-measured 2026-11-22; an
earlier draft of this section had the two figures the wrong way round).
The branch is still being developed rather than landed — its newest commit
is #1411, 2026-11-21 — and the wire format is not separable from the rest.
The
current CE 144 cannot be cherry-picked onto `main`, because an
initial-tranche announcement declares no cores and a later-tranche
announcement declares no tranche, so a receiver needs
`select_cores_to_audit` and `later_tranche_from_entropy` to read either
one — and neither exists on `main` (`git grep` on `origin/main` under
`crates/node/src/auditing/` returns nothing for them or for
`ApprovalEntry`). The format rides on the tranche redesign; it is one
change, not two.

**So the finding is not "polkajam is behind".** It is that `main` — the
branch everything builds from, the one this harness pins, and the one a
conformance run will reach for — ships a wire format `jam-np` replaced on
2026-10-26, while the replacement sits on a long-running branch. That is a
release question, and it belongs to whoever owns the redesign's landing
plan.

### The branch against `simple.md`, line by line

Tracked 2026-11-22 against `origin/feat/tranche-redesign` at `ed60548c3`
and `simple.md` at `aa0e2b8`. Read, not run: every row below is a source
reading, and the byte counts are arithmetic over the spec's common types
(`:163-171`: `Validator Index = Core Index = u16`, `Slot = Epoch Index =
u32`, `Hash = [u8; 32]`, `Ed25519 Signature = [u8; 64]`).

| `simple.md` | Branch | Verdict |
| --- | --- | --- |
| `Announcement = Header Hash ++ Validator Index ++ Intent ++ Bandersnatch Signature` (`:778`) | `AnnouncementMessage { initiator, validator_index, intent, signature }`, `np.rs:52-64` | matches, field for field and in order |
| `Intent = 0 (Initial) OR 1 ++ Core Index` (`:777`) | `AnnouncementIntent::{Initial, Later(CoreIndex)}` at `#[codec(index = 0/1)]`, `np.rs:35-43` | matches |
| `Bandersnatch Signature = [u8; 96]` (`:776`) | `vrf::Signature`, `PREOUT_SERIALIZED_SIZE + PROOF_SERIALIZED_SIZE` | matches |
| `--> [Announcement]` — bare sequence (`:782`, notation `:148-152`) | `write_encoded_seq` / `read_decoded_bounded_seq`, `communication.rs:184`, `:224` | matches — no length prefix |
| `Judgment = Epoch Index ++ Validator Index ++ Validity ++ Work-Report Hash ++ Ed25519 Signature` (`:818`) | `JudgementMessage { signer: ValKey, validity, report_hash, signature }`, `np.rs:80-86`; `ValKey = (EpochIndex, ValIndex)` | matches — the pair encodes as the spec's first two fields |
| `Validity = 0 ++ Guarantee OR 1` (`:817`) | `Validity::{Invalid(Slot, GuaranteeSignatures), Valid}` at codec index 0/1 | matches |
| `Guarantee = Slot ++ len++[GuaranteeSignature]` (`:816`) | `Invalid(Slot, BoundedVec<ValSignature, ConstU32<3>>)` | matches — `len++` is the `BoundedVec` prefix |
| `GuaranteeSignature = Validator Index ++ Ed25519 Signature` (`:815`) | `ValSignature { val_index, signature }`, `extrinsic.rs:313-317` | matches |
| "at most 3 elements", "2 or 3 elements only" (`:812`, `:816`) | bound is `VALS_PER_CORE = 3`; `TryFrom` rejects `< GUARANTEE_MIN_SIGNATURES = 2`, `np.rs:95-97` | matches, both ends |
| "recipients derive [the cores] from the signature" (`:762`) | `select_cores_to_audit(announcement.signature.vrf_output())`, `block_tracker.rs:1070` | matches |
| "derive the tranche from its VRF output" (`:770`) | `later_tranche_from_entropy(announcement.signature.vrf_output(), max_tranche)`, `:1092` | matches |
| "recipients should verify the signature" (`:769`) | `vrf_verify` against `AuditInitial`/`AuditSubsequent` before either derivation, `:1064`, `:1085` | matches — verify precedes derive |
| "never announce … in more than one tranche" (`:757`) | `ApprovalEntry::announced`, set on queueing in `mark_reports_announced`, gating `assigned_report_if_due`, `:1303-1319` | matches |
| "reports audited as a result of … a negative judgment are not announced" (`:754`) | the negative path builds a judgement directly (`own_judgement_for_disputed_report`, `controller.rs:1519`) with no announce step | matches |
| "obtain the work-report using CE 136" on a negative judgment (`:799`) | `request_audit_check_if_required` → CE 136 fetch, `controller.rs:780-800` | matches |
| "broadcast to the validator set(s) succeeding the relevant auditor set(s)" (`:794`) | `select_unique_broadcast_recipients` sends to epoch *and* epoch+1, `controller.rs:2412-2446` | superset — sends to the auditor set too |
| "forwarded to all other known auditors that are neighbours in the grid" (`:801`) | broadcast to the whole set, not the grid neighbourhood | superset — more recipients than asked, not fewer |
| "For positive judgments, this broadcasting may optionally be deferred" (`:796`) | not deferred; positives go out immediately | conformant — the option is not taken |
| "Multiple announcements may be sent in a single message" (`:773`); "Judgments … may be batched together" (`:814-815`) | **was** `ConstU32<1>` on both receive caps | **the one gap** — see below |

**The one conformance gap in the new code**, offered rather than claimed,
since it was a deliberate and documented choice: `np.rs` capped both
messages at one entry (`MaxAnnouncementsPerMessage = ConstU32<1>`,
`MaxJudgementsPerMessage = ConstU32<1>`), commented "The NP does not yet
specify a maximum… The current implementation relies on broadcast, so only
1 message." Sending one is fine; refusing to *receive* more than one is the
part that does not follow, and it does not fail gracefully —
`read_decoded_bounded_seq` reads at most `cap × max_encoded_len` bytes, so
a two-item message overruns the read before the item count is ever
checked, and a failed read on these streams routes through
`peer_misbehaved`, which closes the connection. The asymmetry is the sharp
edge: an implementation that batches is dropped by one that does not, while
the reverse works, so the incompatibility is invisible from the batching
side.

Raised as a PR against the branch (`jv-ce144-145-recv-caps`, pushed
2026-11-22), lifting both to `MaxValCount` — one per validator, which
covers everything one auditor can say about a block, since `MaxValCount` is
three times the core count. A full batch is 136 KB on CE 144 and 313 KB on
CE 145, pinned by a test. The send side is unchanged.

**A residual difference the PR does not close**, and cannot: the NP
specifies *no* maximum for either message, so any finite cap is local
policy rather than spec. `MaxValCount` is a generous bound, not a derived
one — a single auditor batching judgments across more than three blocks'
worth of cores would still be refused. The honest fix is for the NP to
state a bound; until it does, every implementation picks its own and they
will not agree. That is the open question the PR ends on.

**What this cost, and the rule it earns.** A patch was nearly written
against `main` before the remote was checked. It would have duplicated
#1359 and #1370, conflicted with 22 commits of redesign, and had to
reinvent the tranche derivation to work at all. The rule: *before writing
a fix for someone else's repository, look for the branch where they have
already written it.* `git branch -r` filtered on the subject would have
answered this in one command, and did.

---

## 33. The harness put a length prefix on every CE 144 and CE 145 message — CLOSED 2026-11-20

**Status:** CLOSED 2026-11-20, same day. A harness defect, introduced by
§28's re-spec and found before N5 shipped — but only by accident, which is
the part worth recording.

**What was wrong.** `proto.rs` held CE 144 as `Vec<Announcement>` and CE 145
as `Vec<Judgment>`, encoded with `m.encode()` and decoded with
`decode_full::<Vec<_>>`. `Vec`'s derived codec writes a compact length in
front of the items. The spec does not:

> `len++` preceding a sequence indicates that the sequence should be
> explicitly prefixed by its length. If a sequence is not preceded by
> `len++`, the length is either fixed or implied by context. In the case of
> a message consisting of a single sequence, the length of the sequence is
> implied by the message size in bytes. (`simple.md:148-152`)

CE 144 is written `--> [Announcement]` (`:782`) and CE 145 `--> [Judgment]`
(`:825`), neither with `len++`. So every message the harness would have
sent carried one byte no conforming node expects, and every message it read
would have taken the first announcement's header hash to start one byte
late. N5's whole CE 144/145 half would have graded wrongly, in the
direction that fails a correct node.

**Why the tests did not catch it.** The protocol round-trip test encodes and
decodes with the same codec, so a spurious prefix survives the trip
perfectly and the test passes. This is §18's rule in its purest form: *a
test that supplies both sides of an equation cannot discover the equation
is wrong.* The fix adds `ce144_and_ce145_messages_are_bare_sequences`, which
counts bytes against the field widths the spec lists — 131 for an initial
announcement, 133 for a later one, 103 for a positive judgment — rather than
against what the harness itself produces. Reverting the codec makes it fail
with `left: 265, right: 264`, the one byte.

**How it was actually found**, which is the uncomfortable part. Not by
reading the spec, and not by any check in this repository. It surfaced while
reading polkajam's `feat/tranche-redesign` for §32: their
`read_decoded_bounded_seq` decodes items until the input is empty rather
than reading a count, and the question "why would they not use the length?"
led to `:148-152`. The spec had said so plainly the whole time, in the
notation section, which §28 never re-read when it re-pinned.

**What it corrects elsewhere.** §28 described both protocols as sending "a
length-prefixed vector" and §32 repeated it; both are fixed in place. §32's
CE 145 conclusion gets *stronger*: with no prefix, a single positive
judgment is byte-identical between a96dc6b and aa0e2b8, so polkajam `main`'s
CE 145 message is already exactly conformant, and the divergence is confined
to batching and the negative form.

**The rule.** §28's own policy was "diff, do not re-read, when moving to a
newer one", and it was right about the protocol sections. But a diff shows
what changed, not what you misread in what did not change — the notation
section was identical across the re-pin and wrong in the harness's head both
times. *When a re-spec introduces a new message shape, read the notation
that governs it, not only the lines that moved.*

---

## 34. DESIGN's N7 table expects more than the NP requires

**Status:** open, and it is a defect in our own design document rather than
in any node. Found 2026-11-23, writing the N7 lane.

**Numbering note.** §32 and §33 exist on the unmerged `jv-n5-auditing`
branch. This is §34 so the two cannot collide; if N7 lands first there will
be a gap until N5's branch merges.

DESIGN §11 N7 tabulates the robustness expectations, and marks these hard
by not marking them soft:

| Fault | Expected |
|---|---|
| Unknown stream byte (130, 200) | reset stream, connection stays up |
| Length prefix mismatch / truncated / trailing bytes | reset, no crash, connection reusable |

**The NP does not say this.** `simple.md:116-120` defines what a reset
*means* — "resetting/stopping of a stream by the stream acceptor should be
considered rejection of the request or failure to process the request" —
and nowhere obliges a node to reject that way rather than by closing the
connection. Searching `aa0e2b8` for "unknown", "unsupported" and
"unrecognised" returns nothing in the protocol sections: the document says
nothing whatever about a kind byte naming no protocol. The one circumstance
it names for closing a connection is a missing or invalid certificate
(`:20`).

So a lane that hard-failed a node here would be failing it on a rule nobody
wrote, which is the mistake §18 and §27 record and the reason
`n0::connection_close` is already **Soft** with that rationale spelled out.
Two lanes grading the same behaviour at two severities would also have been
its own defect.

**What N7 does instead.** Keeps N0's reading: *how* a node rejects is soft
and reported in the node's own words. One row is hard —
`n7_node_alive_after` — and it needs no spec text, because a node that a
malformed message takes down is broken under any reading of any document.

**What this is not.** Not an argument that closing the connection is fine.
§30 is open and the behaviour is bad: it takes every other protocol with
that peer down to refuse one stream. The claim here is narrower and only
about grading — that the harness may report the cost loudly without
asserting a conformance failure the spec does not define. The place to fix
this is the NP, and `ask_ce-144-145.md`'s third question already asks a
neighbouring version of it.

**The rule.** *A design document is not a source of requirements.* DESIGN
§11's tables were written to plan lanes, and a plan that says "expected:
reset" is a design intention; only `simple.md` decides what a node owes.
Every row's severity traces to spec text or to something true without it,
never to our own table — and where the table and the spec disagree, the
table is what changes.

---

## 35. The node contains an unassigned stream kind in range, and closes the connection for everything else

**Status:** open, node defect, and a refinement of §30 rather than a new
one. Measured 2026-11-23 against polkajam `main` at `d92cadd30`, in
`sessions/n7-1` and reproduced in `sessions/n7-2`. First results from the
N7 lane.

Four provocations, each on a connection of its own, from an ordinary
non-validator peer:

| sent | the node | connection after |
|---|---|---|
| stream kind **130** (unassigned, inside the CE span) | **reset the stream** | **usable** |
| stream kind **200** (unassigned, outside it) | closed the connection: `Bad incoming stream protocol 200` (257) | dead |
| CE 128 message, length prefix claims 4096, 8 bytes sent | closed: `Message size 4096 outside expected range 0..=37` (257) | dead |
| complete CE 128 request + 16 junk bytes | closed: `Data received but was expecting finish` (257) | dead |

The node stayed up throughout: `n7_node_alive_after` is a hard pass, on a
fresh connection after all four.

**The first row is the interesting one.** polkajam already does the right
thing for a kind it does not recognise *inside* the assigned span — resets
the stream, keeps the connection, and the harness went on to make an
ordinary CE 128 request on that same connection and get an answer. So the
graceful path exists and is reachable. Kind 200 takes a different path
purely because it is out of range, and that path kills the connection.

That makes §30 narrower and more actionable than it looked. It is not "the
node closes connections when it dislikes something"; it is that **one
branch handles the unknown gracefully and the others treat a malformed
stream as a connection-level offence.** The three closes are three
different code paths — an unknown protocol number, a message-size bound,
and trailing data — and all three could plausibly do what the first does.

**Why the harness reports this soft.** The NP does not require a reset over
a connection close; it defines what a reset means (`simple.md:116-120`) and
names one circumstance for closing a connection, a bad certificate (`:20`).
§34 records that reasoning in full. The rows say what the node did, in the
node's own words, and leave the question of whether it is permitted to the
spec's author. The cost is real regardless: a connection carries every
protocol with that peer, so refusing one stream this way takes block
requests, tickets, package sharing and availability with it.

**What the messages are worth to whoever fixes it.** All three name their
own cause precisely, which is more than §30 had — that finding had to infer
the provocation from timing. `Message size 4096 outside expected range
0..=37` even gives CE 128's exact request width (32 + 1 + 4). A node this
articulate about *what* it refused is a few lines from being equally
graceful about *how*.

**Two harness defects this run exposed**, neither of which any test caught:

- Every row printed the provoker as "validator 78" — `PROVOKER_PEER` is
  `0x4E`, outside the validator range on purpose, and the row formatted it
  as a validator index against a run whose set is 0..=5. That is §8's
  confusion exactly, reintroduced in the one file whose doc comment cites
  §8 as the reason the constant is out of range. The unit tests missed it
  because the fixture used `peer: 1`, a real validator, where the lane
  always uses the provoker. Fixed, the fixture now uses what the lane uses,
  and a test asserts no row calls the provoker a validator.
- The check and its rows shared a name, so the report read
  `n7_malformed_stream_contained.n7_malformed_stream_contained`. Checks are
  now named by topic (`n7_containment`, `n7_reuse`, `n7_liveness`) as every
  other lane names them.

**The rule.** *Read the first real report, not just the test output.* Both
defects were in code with passing tests, and both were obvious in the first
line of output from a live run. A fixture that differs from production in
one field is a fixture that cannot see bugs in that field.

---

## 36. The node has a protocol timeout and survives a restart

**Status:** open only as a record; both results are the node behaving
correctly. Measured 2026-11-23 against polkajam `main` at `d92cadd30`,
`sessions/n7-4` through `n7-6`. The second and third N7 rows from DESIGN
§11's table.

**Slow-loris.** A CE 128 stream opened, named, and then held silent for 30
seconds with the stream never finished: the node **reset the stream and the
connection stayed usable**. So polkajam does have a protocol timeout for a
stream whose first message never arrives, and it reclaims rather than
accumulating held streams. This is the second row polkajam passes outright,
and it is the same graceful path §35 found for an unassigned kind inside
the CE span.

**Kill and restart.** The node was killed mid-run and relaunched on the
same data directory. It came back on its port, answered an ordinary CE 128
request on a fresh connection (hard pass), and authored again — slot
9954365 in `n7-4`, 9954469 in `n7-6`.

So N7 now covers four of nine rows, and polkajam passes two of the five
provocations outright: an unassigned kind in range, and the slow-loris. The
three it does not are the three §35 records, all of which close the
connection.

### Two limits of the restart row, both worth knowing before trusting it

**The harness cannot always say when the node was next due to author.**
There is no "who authors slot `s`" oracle here: the reference chain authors
for every validator *but* the node, so the node's turns are the gaps, and
under Safrole those come from tickets rather than a rotation the harness
can infer. `next_due_slot` therefore infers a stride from the node's
earlier blocks and returns `None` unless that stride is regular — which, on
a ticketed chain, it usually is not.

The first version gated the whole authoring row on that inference and so
reported itself unexercised against a node that had visibly just authored
(`sessions/n7-4`). The row now passes on the authoring itself, which needs
no schedule — a block after the restart is evidence regardless — and uses
the due-slot control only for the ambiguous case, where the node authored
nothing and the question is whether it was broken or merely not called on.

**The recovery window is a probability, not a bound.** `n7-5` waited four
slots and the node never got a turn, so the row reported itself
unexercised; the window is now eight slots, which made it conclusive in
`n7-6`. Six validators means a turn roughly every six slots, but "roughly"
is doing real work there — a run can still legitimately end with nothing to
grade, and the row says so rather than inventing a verdict.

### What neither row can be tested against

Both are graded by unit tests over `RestartFacts` and by live runs, and by
nothing in between: `SimNode` runs inside the test process, so there is no
process to kill and no stand-in that can pose "came back but will not
serve". The same is true of `n7_node_alive_after`. Three of N7's rows
therefore have no fault-injection coverage, which is a real gap in §18's
terms — the rows have been seen passing against a live node and failing
against fabricated facts, but never failing against a *node* that is wrong.

**Why the restart is gated to N7-only runs.** Killing the node mid-window
destroys every other lane's subject — N1 loses the blocks it grades, N2's
tickets go unanswered, N3 has nobody to submit to — and a combined run
would report all of that as node defects. `LaneSet::restarts_the_node()`
requires N7 and nothing else. The malformed-stream provocations need no
such gate, because they go out on connections of their own; that is
measured, not assumed (`sessions/n0-control` against
`sessions/n7-3-combined`: 24 hard passes, 3 soft, and the same single known
failure either way).

---

## 37. The node serves everyone else through a 480-stream-per-second flood

**Status:** open only as a record; the result is the node behaving
correctly. Measured 2026-11-24 against polkajam `main` at `d92cadd30`,
`sessions/n7-flood-2`. The fifth of DESIGN §11 N7's nine rows.

One peer opened **2400 CE 141 streams in five seconds — 480/s against the
500/s DESIGN asks for** — while a second, ordinary peer on its own
connection asked for a block. The bystander was answered during the flood
and after it, the node went on serving, and it did not even drop the
flooder.

### The row asks about bystanders, not about the flooder

This is the part worth keeping. The obvious shape for a flood row is
"did the flooding connection survive?", and that shape grades the wrong
thing: **a node that throttles or drops a peer opening streams as fast as
it can is defending itself**, which is correct, and a row that failed it
would mark good behaviour wrong and reward a node that let itself be
swamped. Worse, it would pass a node that stayed polite to the flooder
while going silent for everyone else — the actual failure.

So the measurement is taken on a second connection doing nothing unusual,
and the flooder's own fate is recorded but not graded. A unit test pins
that: both values of `flooder_survived` must produce identical rows.

### Two harness defects this row found before the node was asked anything

**The flood ran at half the rate it claimed.** The first version opened
streams one at a time, so the loop was paced by each open's round trip
rather than by the target: 1140 streams in five seconds, **228/s against a
500/s target** (`sessions/n7-flood-1`). A flood test that quietly runs at
half the specified rate is not testing the specified thing. Opening in
concurrent batches, ten ticks a second, reached 480/s. What the carrier
will not grant still shows in the reported count rather than being hidden.

**"Still serving" was measured as "connection alive".** `connection_still_serves`
reads its verdict from `connection.end_reason()`, which is right after a
provocation the node may answer by closing the connection — and wrong under
load, where the failure is a node that answers nobody while leaving every
connection open. The stand-in refuses by resetting streams, so the first
version of this row reported a deliberately-broken node as healthy. Caught
by the sim test, which is what it is for. `connection_answers` is the
stricter measure and the flood row uses it; the provocation rows keep the
other, because they are asking a different question.

### What the result does and does not say

It says polkajam survives this rate from **one connection**. It does not
say it survives 500/s from twenty, and the limit reached here is partly the
carrier's: QUIC bounds concurrent streams per connection, and polkajam
takes quinn's defaults — `net/endpoint.rs` carries a `TODO @dave: Review
configuration` over the transport config, so those bounds are unreviewed
rather than chosen. A flood across many connections is a different test
and is not one of DESIGN's nine rows.

The authoring half of the row reported itself unexercised: the node
authored nothing in the two slots after the flood, and this harness cannot
say whether it was due to. That is the same limit §36 records for the
restart row, and the same honest answer.

---

## 38. Two of N7's rows need a fork the reference engine cannot author

**Status:** open, and it is a limit of the harness's design rather than a
defect in anything. Found 2026-11-24, starting N7's equivocation row.

DESIGN §11 N7 asks for two rows that both need the harness to hold a block
its own chain does not contain:

| row | needs |
|---|---|
| Equivocating emulated author | two validly-sealed blocks, same slot, same author |
| Reorg: emulated majority extends a sibling | a competing branch from an earlier parent |

**The reference engine will not author either.** `author_block_no_import`
takes a `head: Option<(HeaderHash, &Storage)>` and so looks like it can
build on any parent. It cannot. Measured directly against the oracle:

```
parent == the chain's best block  ->  Authored(Some(..))
parent == genesis, head elsewhere ->  Error("Best block changed")
```

The cause is in polkajam's authoring, not in the oracle: the preimage table
and the guarantee table are keyed to the chain's head, and authoring checks
`table.head() != parent` and bails (`chain/authoring/mod.rs:313`, `:374`).
The `head` parameter is an optimisation for a caller that already read the
head, not fork support.

**What was tried and reverted.** An `AuthorBlockFrom { session, slot,
parent }` message, through `m2-oracle-proto`, the oracle handler and
`RefChain`. It works only when the parent is already the head, which is the
one case nobody needs, so it was removed rather than left as protocol
surface that errors for its only purpose. The measurement above is what it
was worth.

**The tempting wrong fix.** Mutate an authored block to make a second one
with the same slot. Its seal no longer verifies, so the node rejects it on
the seal — and the row would be measuring seal validation while claiming to
measure equivocation handling. A row that passes for the wrong reason is
worse than an absent one, and this is `findings.md` §18's rule pointed at
ourselves.

**What it would take.** Either an engine entry point that authors against a
supplied parent without consulting the head-keyed tables, which is a change
inside polkajam rather than in this repository; or a second oracle session
driven down a different branch, which gives two chains but cannot guarantee
the same validator holds the slot on both — Safrole picks the author from
the state at the parent, and the two states differ. The second is cheaper
and weaker: it produces *a* fork, but not reliably an equivocation.

**So the two rows are blocked, not pending**, and should be marked that way
in DESIGN rather than left looking like unstarted work — the same
distinction §32 draws for N5. Of DESIGN's nine N7 rows: five done, two
blocked here, and two left that need nothing new — epoch-transition with a
validator-set change, and index rotation.

---

## 39. N0's sync rows pass at index 5 by luck of the grid

**Status:** open. Two defects, one in the harness and one a node/spec
divergence, found 2026-11-24 by the first use of N7's index-rotation row
and reproduced across two rounds of runs.

N0 graded at three validator indices, same seed, same window:

| index | result |
|---|---|
| 1 | 24 hard pass, 3 soft pass, 1 known failure |
| 3 | **18 hard pass, 3 soft pass, 3 failures** |
| 5 | 24 hard pass, 3 soft pass, 1 known failure |

```
ce128_serve.ce128_ascending_covers_reference — passed at [1, 5], failed at [3]
ce128_serve.ce128_both_halves_fin            — passed at [1, 5], failed at [3]
ce129_serve.ce129_served                     — passed at [1, 5], failed at [3]
```

All three fail the same way: the node resets the stream with
`Reset(91141958510814)` = `0x52e4a40fa8de`, which is polkajam's
`ErrorCode::TooMany`, *"Per-peer concurrency limit exceeded"*
(`net/error.rs:78`).

### Why the limit was hit with one stream open

It is not a concurrency limit in any ordinary sense. `node/config.rs:85-86`:

```rust
let mut as_val_from_non_neighbor = as_val_from_neighbor.clone();
as_val_from_non_neighbor[BlockOrStateRequest] = disallowed.clone();
```

`disallowed` is `max_per_peer: 0`, so **every** CE 128 or CE 129 stream from
a validator that is not a grid neighbour is refused, on the first one.
`TooMany` is the code for "the limit is zero" as much as for "you opened too
many".

With `W = floor(sqrt(6)) = 2`, the tiny grid gives NUT 3 the neighbours
{1, 2, 5}, NUT 1 {0, 3, 5}, and NUT 5 {1, 3, 4}. The sync probe runs on
whichever connection establishes first — `claim_sync_probe` is a race with
no neighbour check — so at index 3 it lands on a non-neighbour often enough
to fail every run of it so far, and at 1 and 5 it does not.

### The harness defect

**N0's CE 128/129 serve rows have been passing by luck of topology.** The
lane is the oldest in the project and these rows have read "26/27 hard
pass" for weeks against index 5. They would have failed the node at index 3
the whole time, for a restriction the node applies deliberately — which is
the harness accusing the node of a defect that is the harness's own
arrangement, the class of mistake §8 and §25 record and the reason §18
exists.

**Fixed.** `start_sync_probe` now claims only from a connection whose peer
is a grid neighbour of the node; `n6::grid_neighbours` already computed the
set, and the node's own index is derived from `emu_indices` — this harness
emulates every validator but one, so the node is the index missing from
that list.

Measured after the fix, same seed and window:

```
                       index 3                index 5
before   18 hard pass, 3 failures   24 hard pass, 1 failure
after    24 hard pass, 1 failure    24 hard pass, 1 failure

--compare sessions/rot3-k3 sessions/rot3-k5
  No row passed at one index and failed at another.
```

The one remaining failure at both indices is
`ce129_boundary_parent_before_child`, the node defect that has stood since
the first N0 runs.

**One consequence to know about.** If no grid neighbour ever connects, the
probe does not run and the CE 128/129 serve rows report nothing rather than
failing. That is the right answer — the harness cannot ask, so it cannot
grade — but it means those rows are now conditional on topology in a way
they were not before, and a run that reaches neither is a run that proved
nothing about sync serving.

### The node/spec divergence

Separately, and for whoever owns the NP: `simple.md` marks CE 128
**`Node -> Node`**, and says nothing about restricting it to grid
neighbours. The grid is introduced "primarily for the purpose of block and
preimage announcements" (`:184`), which is about *announcements*, not about
who may request a block. polkajam refusing CE 128/129 from a non-neighbour
validator is stricter than the protocol as written.

Whether that is the node being wrong or the NP being under-specified is not
ours to settle — a node that served every peer's block requests would be
trivially floodable, so the restriction is defensible engineering. But the
two documents disagree, and a conformance harness cannot grade this until
they agree.

### What the row cost and bought

The row found both on its first use, which is the argument for it. It also
needed almost no machinery: `--validator-index` already existed, so the
work was the comparison (`rotation.rs`) and recording the index in the
report, without which two reports cannot be compared at all.

**The comparison is deliberately conservative.** Which lane work fires
inside a window varies run to run at a *fixed* index too, so a row present
in one run and absent in another is reported separately and is not called a
disagreement. Only a row that passed at one index and failed at another is.
Four rows fell in the first bucket here and none of them means anything.

---

## 40. The spec can schedule a validator-set change; the reference chain cannot follow one

**Status:** open. A feasibility answer rather than a defect, 2026-11-24,
asked before building N7's last row because the two rows before it turned
out to need a capability nothing had (§38) and making that mistake twice in
one lane would be careless.

DESIGN §11 N7's last unbuilt row wants a run "with a scheduled
validator-set change". Two halves, and they have different answers.

### The spec can schedule one — yes

JAM rotates the sets at each epoch boundary, confirmed in polkajam
`chain/exec/safrole.rs:110`:

```text
lambda' <- kappa ; kappa' <- gamma_k ; gamma_k' <- iota
```

`tiny_spec` writes **one** keyset into all four slots — `Validators` (κ),
`Designates` (ι), `PrevValidators` (λ) and Safrole's `waiting_validators`
(γ_k) — which is precisely why no set change ever happens in a run today.
Writing a *different* set into `Designates` schedules one, active two epoch
boundaries later. Two tests in `spec.rs` establish both halves of that: the
four slots agree today, and a rotation is a genuinely different set.

A **rotation** is the right shape: every validator keeps its keys and its
address, and only its index moves. The harness already holds the six
keysets and already listens on their addresses, so the emulated side needs
nothing new, while every index-derived thing the node computes — grid
neighbours, shard index, authoring turns — moves, which is what the row is
about.

### The reference chain cannot follow one — no

The oracle builds its keystore **once, by index, at session open**
(`oracle/src/session.rs:80-86`):

```rust
let validators = SecretKeysets(FixedVec::from_fn(|i| {
    if held.contains(&(i as u16)) { SecretKeyset::trivial(i as u32) }
    else { SecretKeyset::trivial(NON_VALIDATOR_KEYSET) }
}));
```

Position `i` holds `trivial(i)`. After a rotation the validator at index
`i` holds `trivial((i + 1) % 6)`, so the keystore no longer matches the
active set and the harness can no longer author for it. There is no
re-keying path: `AuthoringHarness::new(chain_spec, validators, config)`
takes the keystore by value and exposes no setter, and pins one identity at
construction (`harness.rs:123`, `// pick one`).

So the chain would reach the boundary and then stall — the reference chain
stops authoring exactly when the row wants to watch the node across the
transition.

### What it would take

Re-keying the session's authoring harness at the boundary, which means
either rebuilding it over the same database at the new keyset or a polkajam
entry point that accepts one. That is a change in the oracle and probably
in polkajam, not in the lanes.

**So the row is blocked for the same class of reason as §38's two**, and
for the record that is three of DESIGN's nine N7 rows blocked on the
reference engine rather than on effort: equivocation and reorg need
authoring on a chosen parent, this one needs authoring under a changed
keyset. All three are the harness being unable to *drive* a scenario, never
the checks being hard to write.

N7 therefore stands at **five rows done and four blocked**, which is the
lane's honest ceiling until the oracle can do those two things.

---

## 41. Two more rows were index-dependent, and both were the harness's timing — CLOSED 2026-11-25

**Status:** closed. Found 2026-11-24 by rotating every lane rather than only
N0, which is what §39 bought. Diagnosed and fixed 2026-11-25. **Neither row
was a node defect.** They are the fourth and fifth index-dependent rows
found, after §39's three, and all five have been the harness accusing the
node of the harness's own arrangement — the mistake §8, §18 and §25 record
in forms that did not happen to follow the index.

Seven lanes at validator indices 1, 3 and 5, 300 s windows:

| index | rows | hard pass | failures |
|---|---|---|---|
| 1 | 703 | 463 | 5 |
| 3 | 667 | 421 | 4 |
| 5 | 630 | 408 | 3 |

```
n3_ce135_inclusion.n3_ce135_report_included            — passed at [3, 5], failed at [1]
n6_ce142_announce.n6_ce143_requested_after_announcement — passed at [5], failed at [1, 3]
```

Not run-to-run variance: both rows failed in three further runs at index 1
and passed at index 5. The two rows turned out to have **different causes
of the same shape** — each lane measured a precondition by a proxy, and the
distance between the proxy and the real condition moved with the index.

### N6: the lane announced before the request existed

The row reads "the NUT did not ask for the preimage b16ae7fe that service 0
had solicited on chain, within the 10000 ms the announcer held the
connection open". A node may only ask for a preimage the chain has asked
for (`simple.md:705-707`), so the lane has to wait for the solicit before
it announces. It waited for **a block carrying the soliciting package, plus
two slots**.

A package reaches a block at *inclusion*. The request only exists once the
package has **accumulated**, which waits on availability. Measured from the
three sessions, announcement against the node's own `Solicited` line:

| index | announced | solicit accumulated | row |
|---|---|---|---|
| 1 | 16:55:30 | 16:55:48 | announced 3 slots **early** — fail |
| 3 | 17:01:36 | 17:01:48 | announced 2 slots **early** — fail |
| 5 | 17:07:30 | 17:07:24 | announced 1 slot **late** — pass |

The node was right every time. At index 5 the two-slot lead happened to
clear the gap; at 1 and 3 it did not, and the harness graded a node for not
answering a request that did not yet exist. §5's mistake in a new place,
and the fourth row to make it.

**Fixed** by asking the state instead of approximating it.
`RefChain::preimage_requested` reads the `(service, hash, len)` request key
at the chain's best block and reports whether its slot sequence is still
empty — the same key the node reads before deciding whether to follow up,
so the gate *is* the condition rather than a lead that stands in for it.
A test drives the real engine through solicit, inclusion and accumulation
and pins the ordering; it does not reproduce the five-slot lag, which only
a real run shows.

### N3: the core was full when the node's one chance came

The row reads "the report 526a86e5c75c2de7 guaranteed on core 1 and
distributed in slot 9967152 was never included; the NUT's blocks carried
["04c74d2a848d2001"]". The node received the distribution in all three runs
— one 602-byte CE 135 `rx` at the distribution slot, identical in each
trace — so this was never about the wire.

Two rules decide whether a distributed report can be included at all, and
the old gate knew neither of them. It asked only whether the node authored
*any* block after the distribution.

1. **The guarantee goes stale.** polkajam refuses a guarantee from before
   the previous rotation: `guarantee_slot / rp + 1 < block_slot / rp` is
   `ReportRotationBeforeLast` (`chain/exec/reports.rs:504`). With
   `rotation_period = 4` the window is between one and eight slots
   depending on where in the rotation the report lands, and the node's
   authoring turns do not move with it.
2. **A core carries one report at a time.** A block that put some other
   report on that core had no room for this one.

At index 1 both bit. The distribution went out in slot 9967152 on core 1;
the node's only block inside the window was 9967158, and at slot 9967157 it
had refined a package of its own on core 1 (`@1#0 Bootstrap Service
Refine`) and carried that instead. At index 3 the node authored 9967213,
one slot after the distribution; at index 5, 9967274, two slots after. Both
included it.

Choosing between two reports for one core is a choice neither the GP nor
the NP takes away from a node. The row was failing the node for making it.

**Fixed** by `had_an_opportunity`, which requires a block that is after the
distribution, inside the guarantee's rotation window, and not already
carrying another report on that core. Without all three the row reports
itself unexercised. `N3Ctx::included` carries the core now, because that is
what says whether there was room.

**It is not exact.** A core engaged by an *earlier* block and not yet freed
by availability is still invisible, so a block can be counted an
opportunity when the core was in fact taken. That direction leaves the row
able to fail rather than quietly stopping it grading, which is the safer
way round for a row whose whole job is to fail. Narrowing it further needs
the per-slot engagement the emulator reads live
(`RefChain::engaged_cores`), recorded rather than sampled.

### Verified

Three runs at indices 1, 3 and 5 after the fix (`sessions/fix41-k1`,
`-k3`, `-k5`), same seed and window as the ones that found it:

```
--compare sessions/fix41-k1 sessions/fix41-k3 sessions/fix41-k5
  Compared validator indices [1, 3, 5].
  No row passed at one index and failed at another.
```

| index | `n3_ce135_report_included` | `n6_ce143_requested_after_announcement` |
|---|---|---|
| 1 | not exercised (was FAIL) | **HARD PASS** (was FAIL) |
| 3 | not exercised | not exercised (was FAIL) |
| 5 | **HARD PASS** | **HARD PASS** |

All three indices now fail exactly the same three rows, every one of them
index-independent and already known: `ce129_boundary_parent_before_child`
(a standing node defect), `n2_unknown_epoch_reset_observed`, and
`n3_ce146_oversized_refused` (the verdict §4 asks the NP owner about).

Index 1 reproduced the original N3 shape beat for beat, which is what makes
the diagnosis more than a plausible story: the distribution went out on
core 1 in slot 9977388, the node's only block inside the guarantee's window
was 9977394, and at 9977393 it had refined a package of its own onto core 1
(`@1#0 Bootstrap Service Refine`) and carried that. The next block, 9977398,
is past the window.

**Index 5 is the control that matters.** `n3_ce135_report_included` still
passes there, so the new gate has not quietly stopped the row grading —
which is the failure mode a gate like this invites and the one worth
checking for. The sim test `the_inclusion_check_catches_a_node_that_drops_a_distributed_report`
still shows it failing against a stand-in that drops the report.

**Two costs worth naming rather than burying.**

Neither row grades at index 1 any more. `n3_ce135_report_included` reports
itself unexercised because at that index the node genuinely never has a
free core inside the window. That is honest where a pass would not be, but
it is less coverage than the report used to claim, and it is §39's
consequence in a new place: a row that is now conditional on topology.

The index 3 run was degenerate for a reason that has nothing to do with
this finding — the node authored two blocks in the whole 300 s window
(against ten at index 1) and the soliciting package went out at slot
9977460, after its last authoring turn. So index 3 does not confirm either
row; it only fails to contradict them. A run that thin is its own question
and is not one this finding answers.

### What this says about the rotation row

Both causes were preconditions measured by proxy, and in both the proxy's
error moved with the index because the node's authoring turns do. **That is
what an index rotation is for.** Neither row could have been caught by
re-running at a fixed index: the failures were perfectly reproducible
there, three runs out of three.

It also sharpens §39's lesson. Of the five index-dependent rows found so
far, five were the harness's. A row that disagrees across indices is
evidence about the harness until proven otherwise, and the rotation's value
is not that it finds node defects but that it finds the rows that were only
ever passing by arrangement.
