# Open findings

Things the harness has measured but not settled. Each entry says what was
observed, what it is not, and what would close it.

---

## 1. Two core assignments, reading different entropy entries

**Status:** worked around, root cause not established. Opened 2026-11-11.

polkajam computes the core assignment two ways, and for a slot in the chain
head's own epoch they disagree.

| source | entropy used |
|---|---|
| `storage.core_assignments_for(slot)` | the entry `epoch_relation` selects: **2** for a slot in the head's epoch, **1** for the next |
| `EpochInfo::core_assignments(slot)` (cached, via `current_and_next_epochs`) | **entry 1**, whatever the slot |

Measured against a live node:

```
cached ee155ace9c402920  best-block[1] ee155ace9c402920
                         best-block[2] bb30a42c1e62f0af
```

So the two agree for a slot in the *next* epoch and disagree for one in the
head's own. A guarantor choosing who to share a work-package with uses the
cached view (`chain/guarantors/guarantor.rs`, `epoch.core_assignments(slot)`),
while the on-chain rule for a guarantee shuffles with entry 2
(`chain/exec/reports.rs`).

**Observed effect.** N3's CE 133 sharing row passed in one run and failed in
the next with no code change between them: the submission slot landed in the
head's epoch or the next one depending only on where in the epoch the run
started. Where they disagreed the node shared with one co-guarantor instead
of two and its guaranteed report carried two signatures rather than three.

**What it is not.** Not a stale cache. The cached epoch index matched the
best-block state epoch exactly (815264 against 815264) in the run that
produced the numbers above; the difference is which entry is read, not which
block. An earlier hypothesis that the cache lags finalization was tested and
refuted.

**Current workaround.** `plan_package_for_this_run` aims the submission into
the next epoch, where both sides provably read the same entropy, and waits
for the chain's cached epoch view to reach its own head epoch before
planning. The second half matters because the view resolves only the cached
epoch and the next, so a cache more than one epoch behind cannot answer for
a slot an epoch ahead and no plan is made at all.

Measured over four consecutive runs after that wait was added: **every run
exercised the lane**, where before roughly one in three had planned nothing.
Three scored 30 of 30; the fourth failed only the inclusion row, with both
views agreeing, which is a separate residual and not this one.

This is a workaround, not a resolution. It removes the lane's dependence on
a lagging cache without settling which view is authoritative.

**To close it, a follow-up session should establish:**

1. Which view is authoritative for a slot in the head's own epoch. The STF
   also computes `old_assignments` (`chain/exec/reports.rs`), so it may accept
   more than one rotation — in which case both views are valid inputs and
   nothing is wrong. That has not been checked.
2. If the STF accepts only entry 2, whether a guarantee formed over the
   cached entry-1 cohort can actually be included. If it cannot, a node
   sharing by the cached view is building guarantees the chain will reject,
   which is a polkajam defect and belongs upstream.
3. Whether the harness should then grade the sharing row against the on-chain
   rule and report the divergence as a finding, rather than working around it
   by choice of slot.

The diagnostics that produced this are `RefChain::epoch_views` and
`RefChain::assignment_entropy`, printed by the runner on every N3 plan.

---

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

## 3. The inclusion row fails when the submission waits a long time

**Status:** open, cause located, fix not found. Opened 2026-11-12.

The lane reaches 30 of 30 against a real node, but not every run, and the
outcome is now predictable from one number: the chain's phase within the
epoch when the run plans.

Ten consecutive runs, one row each, on the committed tree:

| epoch phase at plan | slots waited | outcome |
|---------------------|--------------|---------|
| 5, 3, 3, 2, 1 | 7 to 11 | inclusion row FAILS, all five |
| 10, 9, 8, 7 | 2 to 5 | clean 30 of 30, all four |

The separation is total. The lane aims at the next epoch, so a run planning
early in an epoch waits most of one before submitting, and a run planning
late waits a few slots. **Long waits fail, short waits pass.**

The likely mechanism is staleness: the distributed report is composed when
the run is planned, and a guarantee carries its compose-time slot while a
block accepts one only from its own rotation or the one before.

**Two fixes were tried and both are refuted.**

| where the report is composed | phases 1-5 | phases 7-11 |
|------------------------------|-----------|-------------|
| plan time (what is committed) | fail | **pass** |
| send time, no lead | -- | fail |
| send time, two slots early | fail | fail |

Composing at send time is strictly worse. Against the very head the
guarantee names a slot the reference has reached and the node has not, so it
is premature rather than stale; a two-slot lead, which is what makes the
*package* work, does not rescue it either. Both attempts are stashed as
`n3-report-send-time-compose`.

So the mechanism above is a guess that survives the correlation and not the
fixes. Something else about a long wait breaks inclusion.

**To close it:** take one failing run at a low phase and read the node's
debug log around the block it authors after the distribution -- whether it
received the guarantee, noted it, and what `select_viable_guarantees` did
with it. That is a single instrumented run, not another batch, and it would
replace the guess with the node's own account.

**A caution this entry has earned twice.** Six runs cannot tell a fix from
variance here. A one-line fix was nearly discarded on a bad batch and a
regression was committed on a good one, and the logging hypothesis that
once occupied this entry was itself refuted by a controlled A/B. Prefer
correlation over batch scores: the phase table above was worth more than
twenty runs of pass counts.
