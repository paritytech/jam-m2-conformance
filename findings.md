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
the next epoch, where both sides provably read the same entropy. This makes
the lane deterministic without choosing a side.

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

## 2. A distributed report is never included

**Status:** open, not investigated. Opened 2026-11-11.

With everything else in N3 passing, `n3_ce135_report_included` fails in every
run: the harness distributes a fully reference-guaranteed work-report over CE
135, on a core the NUT does not hold, and the node's blocks carry no
guarantees at all.

Before treating this as a node defect, a follow-up should rule out the
obvious harness-side explanations:

1. A report may only be includable once its bundle is available, which is
   N4's erasure-coding path and something this harness does not do at all.
   If so the row is not reachable until availability exists, and it should
   say so rather than fail.
2. The guarantee is composed over the storage view of the assignment
   (finding 1), so its signers may not be the cohort the node expects for
   that core, in which case the node is right to drop it.
3. The guarantee's slot must fall within the including block's rotation or
   the one before. The harness does not currently check that what it
   distributes is still includable when it arrives.
