# jam-m2-conformance

Conformance harness for JAM prize Milestone 2 ("AUTHORER": fully conformant, produces blocks,
including networking and off-chain duties).

The harness runs a node under test (NUT) as one of six tiny-spec validators, emulates the other
five over JAMNP-S with an **independent** protocol implementation (`jamnp-s`, written from
`jam-np/simple.md` — not polkajam's networking stack), and validates every block and off-chain
artefact the NUT produces against the polkajam `hazmat` reference engine.

## Status

**Implemented and green:** P0 infrastructure complete plus conformance lanes **N0**
(connectivity/sync), **N1** (block authoring) and **N2** (Safrole tickets), which run by default,
plus **N3** (guaranteeing) and **N4** (availability), which are graded by name — see the roadmap
below for why. See [DESIGN.md](DESIGN.md) for the design; this README documents the current
implementation state.

- Workspace: `cargo build --workspace` ✓, `cargo test --workspace` **546 passed / 0 failed** ✓,
  `cargo fmt --all --check` ✓, no `unwrap`/`panic`/`expect`/`todo!` in non-test code.
- Dry-run baseline: `cargo run -p m2-runner -- --preset mock --dry-run --session-dir /tmp/x`
  exits 0 with **all N0+N1+N2 checks HARD PASS** — the harness's own expectations are satisfiable.

## Crates

| Crate | Responsibility |
|---|---|
| `jamnp-s` | Independent JAMNP-S: QUIC/TLS endpoint (quinn 0.11 + rustls), Ed25519 cert + custom SAN, ALPN `jamnp-s/1/<8hex>[/builder]`, preferred-initiator rule, kind-once stream framing (`u32 LE` messages), typed codecs for every UP/CE protocol (UP 0, CE 128–148), message trace recorder, and the `transport` and `clock` boundaries (QUIC or an in-process mock; the machine's clock or a virtual one) that everything above it speaks through. |
| `m2-oracle-proto` | The wire protocol between the harness and the reference oracle: a 4-byte length prefix and a JAM-codec message, with the fuzz protocol's own tags kept where they were. |
| `m2-reference` | Client of the reference oracle: `RefChain` (tiny 6-validator chain, deterministic authoring of emulated slots), NUT-block import + state diff (`import.rs`/`state.rs`), ticket generation/planning/verification (`tickets.rs`), work packages and guaranteed reports (`reports.rs`), erasure-coded bundles and segment justifications (`availability.rs`). Holds a connection and a session id; the engine itself is in `oracle/`. |
| `oracle/` | **Outside the workspace.** The reference engine, behind a unix socket: the one crate that depends on polkajam's `jam-node` and its `hazmat` feature. Built by `scripts/prepare-nut.sh` from the same revision as the node under test, which is what makes its answers a standard to grade that node by. |
| `m2-emu` | Five emulated validators (skeletons — no core logic; all values/decisions injected from `m2-reference`): UP 0 announce, CE 128/129 serve, NUT-block fetch (N1), CE 131/132 ticket send/receive (N2), CE 133/146 submission and CE 134/135 share and report receive (N3), CE 137–140 and CE 148 fetch with CE 141 assurances (N4). |
| `m2-scenario` | The §5 DSL (`check`/`expect_subseq`/`log::check`) + hard-coded lanes: `n0.rs` (9 checks), `n1.rs` (6), `n2.rs` (7), `n3.rs` (6), `n4.rs` (6). A check reports one row per thing it graded, so a run's row count is far larger than its check count. |
| `m2-runner` | CLI: keygen → spec → NUT launch (docker/polkajam presets) → connectivity → scenario (N0–N4) → `report.md`/`findings.json`/trace → exit code. |
| `m2-sim` | A simulated node the harness can grade in-process: honest, or broken in one named way, so a check can be shown to fail when it should. |

## Build and run

```sh
cargo build --workspace

# The tests need the reference oracle, and so does a dry run: both build a
# real chain, and the engine that builds one lives outside this workspace.
# Once, and again after a re-pin:
./scripts/prepare-nut.sh          # third_party/bin/{polkajam,m2-oracle}
cargo test --workspace            # or set M2_ORACLE_BIN to one you built

# Dry-run baseline (no real NUT; fabricates a conforming observation log):
cargo run -p m2-runner -- --preset mock --dry-run --session-dir /tmp/m2-dry

# Real surface against the polkajam NUT:
# (the NUT and the oracle, both built by scripts/prepare-nut.sh)
PATH="$PWD/third_party/bin:$PATH" \
cargo run -p m2-runner -- --seed 1 --validator-index 5 --base-port 40000 \
  --preset polkajam --session-dir sessions/p0 --startup-timeout 60 --observe-secs 90
```

CLI: `--seed` (run seed), `--validator-index` (default 5 — index 0 is degenerate for the
preferred-initiator rule), `--base-port`, `--preset` (`polkajam`/`docker`/`mock`),
`--session-dir`, `--startup-timeout`, `--observe-secs` (observation window),
`--lanes` (which lanes to grade, default `n0,n1,n2`; a lane left out is neither graded nor
exercised, and `--lanes n0` skips ticket proving entirely), `--dry-run`.

## Real-surface results vs polkajam-as-NUT (2026-11)

The harness runs end-to-end against the polkajam NUT and produces a genuine conformance
report (`sessions/<id>/report/{report.md,findings.json}`, `traces/jamnp.{bin,json}`).
`M2-status.md` records the milestone evidence in full, and how to point the suite at a
third-party node.

Latest run, `sessions/ce134-3`, all five lanes over a 180 s window: **464 rows, three
hard findings.** None of the three is the harness's:

| row | what it is |
|---|---|
| `ce129_boundary_parent_before_child` | a node defect, standing since the first N0 runs |
| `n2_unknown_epoch_reset_observed` | a node defect: the ticket is rejected, the stream is not reset |
| `n3_ce146_oversized_refused` | `findings.md` §4 — the node applies the work-package size cap on CE 133 and not on CE 146. Whether the cap binds the receiver at all is unsettled, so this is a question rather than a verdict |

**Three where earlier runs reported seven, and every one of the four that went was ours.**
`n3_ce134_answered` was the harness sharing a bundle anchored to a block the node had
dropped from its eight-block recent window, so refusing it was correct (`findings.md` §5).
`n3_ce133_oversized_*` and `n3_ce133_extrinsic_mismatch_*` were the harness crediting the
node with accepting what it had in fact refused: polkajam enforces both size rules, and
refuses by closing the connection rather than by resetting the stream, which the lane could
not see (`findings.md` §8). Both rows pass now. The third, `n2_self_proxy_ce132_all_peers`,
was never an N2 defect either — the node had closed the connection to that peer over an
assurance it would not accept, so there was nothing there to reach (§29, §30).

All three were one blind spot: a refusal the harness could not read. It is now read once,
by the Soft row `rejection_keeps_the_connection`, which reports every connection the node
closed in the node's own words — eleven times in this run, twice over a size rule and nine
times over an assurance or a guarantee.

The count moves between runs, and 450 is a 150 s window rather than a baseline: the window
length sets the ceiling and the lottery sets the rest. `sessions/teardown-4` is the longest
recent run at 581 rows over 300 s.

- **N0 connectivity and sync**: 24/25 HARD PASS — real TLS 1.3 mutual handshake, Ed25519 cert +
  SAN, ALPN `jamnp-s/1/…` with a mismatched ALPN refused, preferred-initiator split, 21 `/builder`
  connections accepted, UP 0 handshake with genesis Final, and the node's own CE 128 and CE 129
  replies graded. One hard finding: `ce129_boundary_parent_before_child`. The lane also grades
  what becomes of the connections themselves: `rejection_keeps_the_connection` (Soft) reports
  every connection the node closed, with the code and reason it closed with.
- **N1 authoring**: the node authors, the harness imports and grades each block — parent,
  seal, prior and posterior state roots. No hard findings in the latest runs.
- **N2 Safrole tickets**: the node accepts the emulator's tickets, runs its own lottery and
  distributes to proxies; proofs, target epochs, attempt ranges, per-epoch caps, proxy
  routing, inclusion and the six deliberately-broken tickets are all graded. One hard
  finding: a ticket for an epoch past the node's horizon is rejected but the stream is not
  reset (`n2_unknown_epoch_reset_observed`). The proxy-forwarding duty
  (`n2_proxy_duty_forwarded`) passes — four times in `unitB-9`. Two soft rows there:
  the node refuses a bad-proof ticket (`invalid ticket signature` in its own log) without
  resetting the stream either, which is the same defect in a second place
  (`n2_proxy_duty_bad_proof_ignored`); and the stopping rule
  (`n2_forward_stops_at_finality`) reports itself unexercised, because polkajam sends each
  ticket to each peer exactly once and so never had a forward to stop. A second hard row,
  `n2_self_proxy_ce132_all_peers`, has failed in recent runs with one ticket short of one
  peer; it is in the table above and not yet written up.
- **N3 guaranteeing**: the node takes the harness's work packages over CE 133 and CE 146,
  shares each with both co-guarantors over CE 134 with the right segments-root mappings,
  and distributes a correctly-signed report over CE 135 that it then includes. Four
  deliberately-broken CE 133 submissions and one over CE 146 are each graded by their own
  rule, since two of them ask for a reset and two for silence. One hard row fails: §4's
  CE 146 oversize row. The other three that used to fail here were the harness's own —
  §4's CE 133 row and §8's extrinsic mismatch were refusals delivered at the connection
  that the lane could not read, and §5 was a bundle anchored past the node's recent
  window.
- **N4 availability**: the node serves CE 137, CE 138 and CE 139/140 with justifications
  that verify against the engine, declines CE 148 (which the spec permits, and the row
  records as Soft), and its CE 141 assurances are graded well-formed, correctly aimed, and
  to inclusion. No hard findings in the latest runs; §22 records what the node does to its
  own authoring instead.
- Runner exits 1 (correct — hard failures exist).

**Most hard failures the harness has ever reported against this node were its own.** In N0
to N2, five were found and closed, and they are one defect in five shapes: *the harness
grading the node against its own intentions rather than against what happened on the wire.*

- Ticket delivery ran on slot arithmetic with no readiness gate, so the first batch went out
  while the node was still finalizing the chain it had just been seeded. polkajam refused those
  tickets — `Error processing incoming ticket: finality lagging` — and the harness then graded
  it for not forwarding or including them. The sender now holds each ticket until the node's
  advertised finalized head is in the current epoch, and withholds one it cannot accept in
  time. `finality lagging` has not appeared in a run since.
- The lanes read the *plan* rather than the deliveries, so a ticket the emulator withheld was
  still demanded of the node. A ticket that never went out is now *not exercised*, not a failure.
- N1 demanded inclusion of the unknown-epoch probe — the one ticket the node is required to
  refuse.
- Each peer's plan was delivered out of slot order, so the ticket proxied to the NUT sat
  behind a broadcast scheduled several slots later and arrived past any forwarding window.
- **The CE 131/132 decoder rejected any ticket attempt above 1.** Under tiny a validator makes
  four attempts, so every ticket numbered 2 or 3 failed to decode and was dropped silently —
  a frame that will not decode is skipped, not reported. The node had sent it, the harness
  never saw it, and the lane recorded that the node had not sent it. This is what
  `n2_proxy_duty_forwarded` had been failing on all along: in `sessions/fwd-2` the node
  forwarded its one proxied ticket to all five validators one slot after receiving it and was
  graded as reaching none of them. A range the protocol parameters set does not belong in a
  decoder; the N2 lane judges it as `n2_gen_attempt_in_range`, where an out-of-range attempt is
  a reportable failure instead of an invisible one.

**A single run is not a baseline.** Check counts range from 82 to 278 across runs — the window
length sets the ceiling and the lottery sets the rest, since which slots the node wins and when
a proxied ticket arrives decide which rules can be demanded at all.
The run now waits for the node to be able to accept tickets before laying the plan out, and
trades a lottery it cannot exercise the proxy duty in for the next one, which makes the spread
narrower — but it does not remove it. Grade a client over several runs, read the soft
"not exercised" rows as coverage gaps rather than passes, and check a hard failure against the
node's own log before reporting it upstream.

**On reading the lanes.** Every check asserts what the *node* does. Several used to be recorded by
the emulator's own serve path — the harness answering the node, then entering a pass for itself —
so they could not fail; the CE 128 and CE 129 rows are now driven by requests the emulator makes
and graded on the replies (`m2-emu/src/sync_probe.rs`). A check that could only ever pass is worse
than a missing one, so findings carry the values that disagreed.

The same audit over N1 and N2 found the defect in five more shapes, every one of which made a
conforming node look wrong or a wrong one look conforming. Tickets were sealed against entropy
buffer entry 1 where a node checks entry 2, so **every ticket the emulator ever offered was
rejected** — invisible because the two entries agree whenever an epoch boundary happens to fall
between proving and delivery, which a genesis anchored 28 epochs in the past made likely. That
anchor was itself a defect: it was computed before the tiny protocol parameters were applied, so
it divided by an epoch period of 600 instead of 12. Tickets were also proved against the chain
*before* it was seeded, carrying genesis entropy; the node's own tickets were charged as tickets
nobody delivered, though a validator's own tickets belong in its own block; one block was asked to
carry every valid ticket of the epoch against a cap of three; and inclusion was judged on the
newest block even when it fell outside the epoch those tickets could be submitted in.

Where a rule genuinely was not exercised the harness now says so rather than passing: a ticket
that arrived too late in the lottery to demand a forward, an epoch with no NUT block to judge, and
a proof for an epoch the harness holds no context for are reported as soft "not exercised" rows.

The N2 lane had the same fault in a different form. It told a proxied ticket from a self-proxied
one by the peer index a frame arrived at, in a space where the node's own index never appears —
making two checks unfailable — while requiring frames from a peer the run never emulates, making
two others unpassable. The lane now reads CE 131 from CE 132 off the stream kind, takes the
emulated set from the run, counts tickets rather than frames, and derives the epoch a ticket must
name from the moment it was sent rather than pinning one for the whole run. Three further rules
are reported as **not exercised** rather than passed when a run cannot reach them: a proof for an
epoch the harness holds no ring for, a proxied ticket delivered too late in the lottery for any
forwarding window, and an unknown-epoch probe that was never scheduled.

## Dependency wiring

The workspace takes three polkajam crates as ordinary **git dependencies**
pinned to a commit in the root `Cargo.toml` (DESIGN.md §8): `jam-types` and
`jam-std-common` for the types and codecs the harness reads the wire with,
and `jam-bootstrap-service-common` for the payload shape the dev chain
spec's bootstrap service reads -- a work item that exports or imports
segments is an encoded `Instructions` addressed to it. It does not take
`jam-node`: `cargo tree -i jam-node` finds nothing here, because the engine
runs out of process. Nothing from polkajam is vendored into this
repository.

Not from crates.io, though the first two are published at the same 0.1.29
the pin carries. They are different code -- the published
`ServiceActivityRecord` has `provided_count: u16` where the pin has `u32`,
in a struct that derives `Encode` -- so a harness built against one and an
oracle built against the other would disagree about bytes in the state a
lane diffs. polkajam publishes 0.1.x from a moving trunk, so a version
number does not identify a revision; findings.md §6 has the diff and the
check to repeat on a re-pin.

The reference oracle (`oracle/`) is **outside the workspace** and pins the
same revision in its own `oracle/Cargo.toml`. `prepare-nut.sh` reads the pin
from there -- the oracle's manifest is the one that still names `jam-node` --
and refuses to build unless **every** polkajam dependency in the workspace
manifest is on that same revision. (It used to look for `jam-node` in the
workspace manifest, which has never had one, so the guard read an empty
string and could not fire.) The one that would drift quietly is
`jam-bootstrap-service-common`: the other two decode the node's own bytes
and would fail loudly, while a drifted payload shape encodes an instruction
the running service misreads, with every row still green. It produces both
binaries, from one revision, so the node under test and the engine that
grades it are the same build:

```sh
./scripts/prepare-nut.sh        # third_party/bin/{polkajam,m2-oracle}
export PATH="$PWD/third_party/bin:$PATH"
```

Two trees also mean two lockfiles, and both ask for `jam-codec` -- the codec
on the socket between them -- by a caret requirement. They resolved
differently once, and the harness ended up accepting a non-canonical length
the node under test rejects, with no error anywhere (`findings.md` §7). The
handshake now carries a probe of what each side's own codec does, and the
client refuses an oracle whose answers differ, naming the input they
disagree about.

`third_party/` is gitignored. The harness's own networking (`jamnp-s`) is an
independent implementation.

**Re-pinning policy.** Upstream HEAD has broken this workspace three times in
four weeks, so the revision moves deliberately: at most once per milestone, in
a commit of its own, recording what changed in the genesis writer
(`chainspec.rs`, `chain/exec/the_state.rs`) and the `hazmat` export list, with
a regenerated spec diffed against the old one. `POLKAJAM_REV` overrides the
revision for a one-off comparison and warns that the oracle no longer matches.

No patches are applied to the NUT. The ALPN patch this repository used to carry
(`jamnp-s/0` → `/1`) is obsolete: upstream carries `JAMNP_VERSION = 1` itself.
polkavm's generic sandbox is a one-line feature flip in the script, behind
`POLKAJAM_GENERIC_SANDBOX=1`, for hosts that deny unprivileged `userfaultfd`;
run the NUT with `POLKAVM_SANDBOX=generic` when it is enabled. The library
dependency needs neither, because the harness never runs polkajam's networking
and pins `PvmBackend::Interpreter`.

## Roadmap status (DESIGN §13)

| Phase | Content | Status |
|---|---|---|
| P0 | `jamnp-s`, runner skeleton, N0 | ✅ implemented |
| P1 | `m2-reference` (now an oracle client), N1 authoring, N2 tickets | ✅ implemented |
| P2 | N3 guaranteeing, N4 availability | ✅ implemented — graded by name (`--lanes n0,n1,n2,n3,n4`), not by default; see below |
| P3 | N5 auditing/disputes, N6 preimages | ⏳ |
| P4 | N7 adversarial, index rotation, IPv6, web UI | ⏳ |

**Why N3 and N4 are not in the default lane set.** A check nobody has seen
fail is a check nobody knows is a check. Every N4 check is now held to that
bar: `m2-sim/tests/n4_sim_it.rs` drives eleven faults through a simulated
guarantor for the serve and assurance rows, and
`m2-sim/tests/n4_inclusion_sim_it.rs` drives two more through a node that
mishandles the assurances it is sent. Writing the second found both of
`n4_ce141_inclusion`'s rows asking for the wrong block (`findings.md` §14).
N3's submission rows are now held to it too, by
`m2-sim/tests/n3_sim_it.rs`: a guarantor that refuses every package, one
that takes a package over its protocol's size cap, and one that shares with
a single co-guarantor each fail their own row, over CE 133 and CE 146 alike.
CE 148 is written and proven too, in N4 rather than N3: it asks by a
segments root the node exported, so it rides the same mid-run plan the rest
of availability does. CE 135 is proven at both ends:
`m2-sim/tests/n3_ce135_sim_it.rs` drives five faults through a guarantor
that distributes wrongly, and `m2-sim/tests/n3_ce135_inclusion_sim_it.rs`
drives one through a node that drops a report distributed to it.

CE 134 receive is proven too, by `m2-sim/tests/n3_ce134_sim_it.rs`: the
simulated node now refines a bundle it is sent and answers with the
report's hash, and three faults -- refusing a well-formed share, naming the
wrong hash, and taking a share coded for the wrong validator count -- each
cost their own row.

**Every row a node can cause in N3 and N4 has now been seen to fail.** The
last one that could not be reached was the CE 134 mapping row, and getting
to it found the row itself was wrong: it asked that the mappings name the
package being *shared*, when they name the package it *imports from*
(`findings.md` §27). It is now `n3_ce134_maps_the_imported_package`, the
run submits a package that imports a segment from an earlier one, and
`m2-sim/tests/n3_ce134_mappings_sim_it.rs` passes the honest pair and fails
three ways of getting it wrong -- including no mappings at all, which is the
case the old gate made unreportable.

**And every one of them has now been put to the real node.** The three
segment protocols were the last that had never been: until the harness
could build a package that *exports*, a run asked nothing over CE 139, CE
140 or CE 148 and all three reported themselves unexercised — truthfully,
and in a way that reads on a green report exactly like a node that
answered (`findings.md` §17). The dev bootstrap service turned out never to
have been the blocker, only unexplored. Opening that door immediately found
§26: the CE 140 justification check had been comparing each proof against
the size of the *request* rather than the tree it proves against, which no
simulated node could have caught, because the test held exactly as many
segments as it asked for.

So the coverage reason for keeping N3 and N4 out of the default set is
gone twice over, and what is left is a judgement rather than a gap:
`n3_ce133_oversized_refused` and `n3_ce146_oversized_refused` are Hard
against a reading of `simple.md` that §4 records as unsettled, and making
these lanes default would fail a third-party node on a **should**. They stay
opt-in until that is settled — the more so now that polkajam is known to
take the strict reading on one of the two protocols and the permissive one
on the other, which is how little the wording settles.

**N4's assurance rows have now been answered by a real node.** As of
2026-11-18 a live run grades `n4_ce141_well_formed`,
`n4_ce141_bits_have_reports` and both inclusion rows —
`n4_ce141_valid_assurance_included` and
`n4_ce141_invalid_assurance_excluded` — against polkajam, and it passes all
four. Getting there took seven runs and six harness fixes
(`findings.md` §19 to §25): until then no live run had ever
engaged a core, so the node never sent an assurance and the rows reported
themselves *not exercised* — which on a green report reads exactly like a
node that did nothing. §21's second half then closed too: the engaged cores
are read per slot rather than fixed when the plan is written. What is left
is on the node's side, written up as `findings.md` §22 — a core is engaged
for about one slot at a time, so an assurance is routinely valid when sent
and stale when the node authors with it, and polkajam refuses to author at
all rather than dropping it.

**The pin is on upstream main.** `Cargo.toml` and `oracle/Cargo.toml` point
at polkajam `d92cadd30`, which exports three things the harness cannot do
without.
`hazmat::merkle` is what checks and builds a CE 137 justification —
`merkle_root` to check one, `merkle_proofs` and `pack_erasure_tree_entry` to
build one, which is what lets a simulated node serve shards at all — and
`cd_proof_root_ph`, without which a CE 148 import proof cannot be checked by
anything outside the node crate. `AuthoringHarness::submit_assurance` is
what lets a simulated node carry an assurance it *received*, without which
the CE 141 inclusion rows cannot be shown to fail. See `findings.md` §9,
§14 and §16.

Those exports reached main as polkajam#1401, squash-merged to `d92cadd30`
(2026-11-18), and the pin moved there on 2026-11-19 — so the harness no
longer depends on an unmerged branch. Because it was a squash, the old pin
`b1ea8aca4` is not an ancestor of main and the move was to a different
commit rather than a fast-forward. Two other commits came with it: #1382
threads a chaos controller through the CE 133/134/146 receive path (gated
off in an ordinary run), and #1404 fixes an STF divergence, which is the
kind of thing that moves an N1 state diff without anyone intending it.
Neither moved a verdict — `sessions/repin-1` reports the same hard failures
as the run before, row for row.

Iterate-later items: full 2-epoch observation + epoch-boundary alignment of the ticket window;
independent (non-`import_block`) seal/entropy VRF re-verification; full M1-style keyvals diff on
state-root mismatch; emulator↔emulator links; `polkajam-fuzz` reuse for N3+ (provisioners still
private).

References:
- JAM prize: https://jam.web3.foundation/
- JAMNP-S spec: https://github.com/zdave-parity/jam-np (`simple.md`). Every `simple.md:NNN`
  in this repository refers to **a96dc6b** (2026-09-02); upstream has moved since, and
  `findings.md` §28 says what changed and which of it costs anything.
- Graypaper: https://graypaper.com/
- M1 conformance (fuzz-proto, reports): https://github.com/davxy/jam-conformance
