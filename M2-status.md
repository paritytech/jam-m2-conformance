# M2 Conformance — Status

Progress tracker for the M2 conformance harness. Three documents govern this project and
nothing else does:

| Document | Governs |
|---|---|
| `DESIGN.md` | the implementation — lanes, checks, wire formats, the NUT contract |
| `M2 Conformance - Delivery Plan.md` | the delivery plan — milestone ladder, effort, rollout |
| `M2-status.md` (this file) | progress against that ladder, and the evidence for it |

Last verified **2026-11-24** against polkajam @ `d92cadd30` (`polkajam 0.1.29`, GP 0.8.0),
`main` @ `590f07b`, with the spec pinned to `jam-np/simple.md` @ `aa0e2b8` (2026-10-26).

The dated sections below are kept as written — each records what was true when it was
taken, and several were superseded by the next one. §3 and the milestone ladder are the
current state; where an older section disagrees with them, the ladder is right.

### Re-pin, 2026-11-02: `940ef56c` → `e3d216c2`

Ten commits, `940ef56c` (2026-10-16, #1305) to upstream `main` `e3d216c2` (2026-11-02, #1352).
Cargo.toml's policy asks a re-pin to record what moved in the genesis writer and the hazmat
exports:

| | what moved |
|---|---|
| **Genesis writer** | `gen_spec` dropped `ProtocolParameters::large()` from its core-count lookup, because that preset was removed. The harness builds tiny (`core_count` 2) through `hazmat::dev_spec` and `StorageBuilder::RawFactory`, which are unchanged, and `jam-std-common` is untouched — so the genesis header and state keys, and therefore the genesis hash and the ALPN derived from it, are the same. |
| **Hazmat exports** | `exec::SafroleProgressor` added. `Harness::try_submit_guarantee` removed; the harness never used it. All eight symbols the harness imports (`AuthoringHarness`, `AuthoringHarnessConfig`, `ImportBlockParams`, `KeystoreSigner`, `SecretKeysets`, `StorageBuilder`, `default_dev_spec`, `dev_spec`) are unchanged. |
| **Ticket rules** | unchanged. `ticket_communication.rs`, `proxy.rs`, `error.rs` and `exec/safrole.rs` are byte-identical across the ten commits, so the attempt cap stays 4 (`m2_spec_parameters_match_the_engine` asserts it), as do the proxy-selection rule and the forwarding window. |
| **Ticket diagnostics** | `execute_block.rs` now returns `Safrole(e)` where it returned `BadSignature` for a bad ticket extrinsic, so a rejected import names `BadTicketAttempt` or `BadTicketEpoch` instead of a flat bad-signature. `m2-reference`'s `ImportOutcome::error` is an `Option<String>` that is reported and never matched on, so this is a free improvement to N1's findings. `ticket_table.rs` drops a full table's worst ticket at `Debug` rather than `Warn` — by design, and worth knowing if anything ever reads the node log for ticket evidence. |
| **State transition** | `execute_block.rs` moved `authorizations::progress` from before accumulation to after it, "from the queues that accumulation has set". This changes posterior state roots for blocks where accumulation sets an authorization queue. Harmless here only because the oracle and the NUT are the same build and move together — it is precisely the divergence the pin policy exists to prevent. |
| **Everything else** | the bulk is `polkajam-fuzz` (#1288, an STF-fuzzer overhaul). It is a workspace dependency but no harness crate imports it, and it does not compile as part of a workspace build. |

`/parity/polkajam` was *not* the source of this pin: that clone sits at `75e9061a`
(2026-03-13, #931), a direct ancestor of the old pin and seven months behind it. Reading it
as current is what produced the inverted parameter history now corrected in DESIGN §10.

Verified end to end, `sessions/repin-1`: the NUT binary rebuilt from `e3d216c2` reports
`polkajam 0.1.29 / GP 0.8.0`; 100 checks ran, 95 hard pass, 3 soft pass, and the same two
hard findings as before the re-pin — `ce129_boundary_parent_before_child` and
`n2_unknown_epoch_reset_observed`, both node defects of §3. N2 is otherwise green, including
`n2_proxy_duty_forwarded` and seven passes of `n2_gen_attempt_in_range`, and the node log
has no `finality lagging` at all.

### First live run of N3 and N4, 2026-11-18, pin `b1ea8aca4`

`sessions/n3n4-1` and `sessions/n3n4-2`: `--lanes n0,n1,n2,n3,n4`,
`--observe-secs 300`. Both lanes had been graded only against the dry-run
baseline and the simulated node until now. 332 checks, 49 findings, exit 1.

**Node behaviour the run reproduced.** Three findings previously seen once
and marked "reproduce before filing" came back with the same evidence:
`n3_ce133_oversized_reset` and `n3_ce133_extrinsic_mismatch_reset` (§4, §8),
and `n3_ce134_answered` — a well-formed CE 134 share reset with `0x100`,
`NoError` (§5), identical to the 2026-11-16 observation down to the core and
the code. §4 also extended itself: `n3_ce146_oversized_reset` failed against
CE 146's own 204,800-byte cap in the same run, so the node reads both
protocols' size caps the same wrong way. All of these remain questions for
the conformance group rather than filed defects, for the reasons §4 lists.

> **Corrected 2026-11-20.** **All three were the harness, not the node.**
> polkajam enforces both size rules and refuses by closing the connection,
> which the lane could not read and reported as acceptance (§8);
> `n3_ce133_oversized_*` and `n3_ce133_extrinsic_mismatch_*` pass now. The
> sentence above about the node reading "both protocols' size caps the same
> wrong way" is wrong: it reads CE 133's correctly, and only the CE 146
> failure was real. And `n3_ce134_answered` was the harness offering a
> bundle anchored past the node's eight-block recent window, so refusing it
> was correct (§5). Nothing in this paragraph was node behaviour. See the
> sections for PR #25 and PR #26 below.

**Harness defects the run found, all three fixed the same day.** This is
what the run was for, and the ratio is the point — three harness defects to
zero new node defects:

| | what it was |
|---|---|
| §18 | `n3_ce133_unauthorized_not_shared` and `n3_ce133_not_a_guarantor_ignored` correlated CE 134 shares to submissions **by time alone**, so a run with an honest submission behind a faulty one graded the faulty one against shares the node was right to make. Neither row could pass a conforming node. Now bounded by the next submission, and proven by a simulated node that ignores a misaddressed package while sharing the next one. |
| §19 | The CE 135 report plan was gated behind a `watch` that fires on the *ticket* plans, so every connection checked for a report plan that did not exist yet and gave up. Only one validator may distribute the report, so nothing ever did, and `n3_ce135_inclusion` reported *not exercised* for the whole run. |
| §20 | The assurance offers ran for a fixed twelve slots. The node authored eight blocks in the 50-slot window and none inside those twelve — the nearest was one slot past the last offer — so every `n4_ce141_inclusion` row reported *not exercised*. The offers now run for the rest of the window. |

Two of the three were invisible: a row that grades nothing and a row that
passed report the same way on a green page. Both now print why, which is
what named §19 and §20 in a single run.

**What the third run found, and what it means for the N4 verdicts.**
`sessions/n3n4-3` validated §19 — the CE 135 report was distributed, and
`n3_ce135_inclusion` was graded for the first time — and did not validate
§20. Widening the assurance window exposed why: **every assurance a live run
sends is for a core that carries nothing** (§21). The core is read off the
report the NUT *distributed*, distributing does not put a report on chain,
and nothing in the run ever puts one there. The node lost all three
authoring slots it owned inside the window to `assurances error: core not
engaged`, which also made `n3_ce135_inclusion` fail for a reason that is not
the node's (§22 records the node's side of the same event).

So **N4's assurance verdicts from the first three runs say nothing about
polkajam**: no valid assurance had ever been put in front of it. The serve
rows (CE 137/138) are unaffected and passed throughout.

**The fourth run, with §21's first half in.** The emulator now pools what
the NUT distributes, so a core engages. `sessions/n3n4-4` is the first run
in which polkajam sent an assurance of its own — 45 of them — and the first
in which `n4_ce141_valid_assurance_included` was graded at all. Two N4 rows
went from never-asked to asked.

It also ran a row nothing had ever reached, which turned out to be broken:
`n4_ce141_bits_have_reports` failed all 45 times, comparing core indices
against a **truncated slot number** read out of the wrong tuple element
(§23, fixed). Second-order lesson, and the same one as §18: a row can be
wrong indefinitely while nothing reaches it, and the thing that reaches it
is a live node doing something it had never been given the chance to do.

**The fifth run, with §23 in.** The first run whose N4 assurance verdicts
are about polkajam rather than about the harness:

| row | run 4 | run 5 |
|---|---|---|
| `n4_ce141_well_formed` | 50 pass | 50 pass |
| `n4_ce141_bits_have_reports` | **45 fail** | **50 pass** |
| `n4_ce141_valid_assurance_included` | 3 graded | **3 pass** |

`n4_ce141_valid_assurance_included` is the row PR #15 was written to fix.
This is the first time it has been put to a real node and answered. §18's
fix was confirmed at the same time: `n3_ce133_unauthorized_not_shared` and
`n3_ce133_not_a_guarantor_ignored` now pass, so both were harness artefacts
and neither is a polkajam defect.

The run also surfaced §24 — a reconnection re-fetching shards the node had
rightly let go, which failed the CE 137/138 serve rows 19 times each against
a conforming node. Latent before §20 widened the window from twelve slots to
the rest of the run; fixed by claiming the fetches once per validator.

**The seventh run.** Both of §14's inclusion rows have now been put to a
real node and answered: `n4_ce141_valid_assurance_included` three times and
`n4_ce141_invalid_assurance_excluded` once, all passing. Neither had ever
been exercised before today. The CE 137/138 serve rows are back to clean
passes with §24's regression gone.

It also found §25 by arithmetic rather than by failure: the availability
exchange was started only on connections the *node* opened, so under N0's
preferred-initiator rule roughly half the emulated validators never asked
it for anything. Three validators' fetches instead of five, and nothing red
to show for it.

**The eighth run, and where N3/N4 stand.** `sessions/n3n4-8`, with every
fix in: shard fetches for all five validators (three before §25), five
graded `n4_ce141_valid_assurance_included`, thirty assurances the node sent
graded well-formed and correctly aimed, and every N4 row passing. The hard
failures are down to the known set and nothing else:

| row | finding |
|---|---|
| `ce129_boundary_parent_before_child` | §3 |
| `n2_unknown_epoch_reset_observed` | §3 |
| `n3_ce133_oversized_reset` | §4 |
| `n3_ce146_oversized_reset` | §4 |
| `n3_ce133_extrinsic_mismatch_reset` | §8 |

All five are node behaviour, three of them questions for the conformance
group rather than filed defects.

> **Corrected 2026-11-20.** Two of those five were not node behaviour at
> all: `n3_ce133_oversized_reset` and `n3_ce133_extrinsic_mismatch_reset`
> were the harness reading a refusal it could not see as an acceptance
> (§8). The known-failure set is three. Across eight runs the harness produced
**seven defects of its own and no new defect in polkajam**, which is the
fair summary of what a first live outing of two lanes is worth.

**What is left.** §21's second half — reading the engaged cores at send time
instead of fixing them when the plan is written — is still open, and until
it lands a run still costs the node two or three of its authoring slots.

**What the run confirmed about §17.** `n4_ce139_140_not_exercised` and
`n4_ce148_not_exercised`, exactly as predicted: the submitted package
declares `export_count: 0`, so a live run asks nothing over any segment
protocol. The prediction was made by reading the code; it is now measured.

### After PR #16: §21 closed, CE 134 receive proven, 2026-11-18

**§21's second half.** `AvailPlan.cores` is gone; the engaged cores are
read per slot through a closure, exactly as the anchor is, answered by the
oracle from `Harness::engaged_cores()`. No upstream export was needed.
Measured over three runs, against the node's own authoring slots:

| | opportunities | lost to `core not engaged` | `valid_assurance_included` graded |
|---|---|---|---|
| neither half (`n3n4-4`) | 8 | 5 | 3 |
| first half (`n3n4-5`) | 5 | 2 | 5 |
| both (`n4-cores-1`) | 7 | 2 | **9** |

`n4_availability_threshold_reached` passed for the first time: a report the
harness assured actually became available.

**What the residual turned out to be.** Two slots still went, and a new
diagnostic that prints the engaged set whenever it moves says why: a core
is engaged for about **one slot at a time**.

That turnover was read, for a week, as the cause: an assurance valid when
sent and stale when the node authors with it. **It was not.** Re-diagnosed
2026-11-25, the losses split in two — a second race of the harness's own,
reading the anchor and the engaged set in separate oracle calls, and then
the harness's *deliberate* `EmptyCore` fault. With the race closed the
correlation is total: every block the node authored was before the first
faulty assurance, and every authoring slot it owned inside the fault window
was lost. §22 is rewritten around what that actually shows — **one peer can
stop a validator authoring, for as long as it keeps sending** — which is a
stronger finding than the one it replaces and is now reportable rather than
a candidate.

**CE 134 receive.** The simulated node refines a bundle it is sent and
answers with the report's hash; three faults cost `n3_ce134_answered`,
`n3_ce134_hash_equals_the_reference` and
`n3_ce134_wrong_shard_count_refused` one row each.

**Where that leaves the lanes.** Every row a node can cause in N3 and N4
has now been seen to fail, except one that cannot be reached at all:
`n3_ce134_shares_the_submitted_package` is gated on mappings, which map
imported segments, and no package this harness builds imports any. §17 now
lists four rows waiting on that one thing.

So the *coverage* reason for keeping N3 and N4 opt-in is gone. What remains
is a judgement: the two oversize rows are Hard against the reading §4
records as unsettled, and defaulting these lanes would fail a third-party
node on a **should**.

### After PR #18: the segment protocols reach a node, 2026-11-19

**§17 closed.** The dev bootstrap service was never the blocker. It reads
its payload as an encoded `Instructions` and carries an `Export { data }`
instruction, so the honest submission now exports four segments and a live
run asks for them. `sessions/n4-exports-3`: CE 139 and CE 140 answer and
verify five of five, and CE 148 is declined, which `simple.md:663` allows
and the row records as Soft. All three segment protocols have now been put
to a real node.

**§26, found the moment that door opened.** `n4_ce140_justifications_verify`
failed five of five against a node serving correctly, because the check
compared each proof against the size of the *request* rather than the tree
it proves against. Which number was right took two live runs: it is the
exports **plus their import-proof pages**, one per 64, appended before the
set is erasure-coded. `n4_sim_it` now holds four segments and asks for two,
and fails all five rows without the fix.

The simulated node could not have found this. It held two segments and
asked for both, so the two numbers were the same in every arrangement it
could make — a test that supplies both sides of an equation cannot discover
the equation is wrong.

**§27, found the same way one step further on.** The last row out of reach
was the CE 134 mapping row, and reaching it showed the row was wrong:
`n3_ce134_shares_the_submitted_package` asked that the mappings name the
package being *shared*, when they name the package it *imports from*. No
conforming node could have passed it, and nothing noticed because the gate
— mappings must be non-empty — never opened. That gate also made the
likeliest defect unreportable: a node that resolves its own imports and
never passes the resolution on sends no mappings at all.

It is now `n3_ce134_maps_the_imported_package`, in a check of its own with
its own control, grading both halves of the pair. A run submits a package
importing segment 0 of the first by work-package hash, gated on the
guarantee for that package having reached a block.
`n3_ce134_mappings_sim_it` passes the honest pair and fails three ways of
not sending it. Live (`sessions/n3-imports-1`): accepted, shared with both
co-guarantors, both shares carrying the right mapping, HARD PASS twice.

**Where that leaves the lanes.** Every row a node can cause in N3 and N4
has now been seen to fail, and every one of them has now run against the
real node. The coverage reason for keeping the lanes opt-in is gone twice
over; what remains is the §4 judgement, unchanged.

**Two things found while tidying.** `prepare-nut.sh`'s pin-agreement check
looked for `jam-node` in the workspace manifest, which has never had one,
so it read an empty string and could not fire; it now checks every
polkajam dependency against the oracle's revision. And §28: the harness
read `simple.md` at a96dc6b (2026-09-02) while upstream was at aa0e2b8
(2026-10-26), with CE 144 and CE 145 rewritten — which is to say **DESIGN's
N5 plan specified a wire format the spec had replaced**, before a line of
N5 was written. Re-pinned and re-specified on 2026-11-20; see the section
for PR #28 below.


### After PR #22: §29's cause, and a node that closes connections, 2026-11-19

**§29 closed, and its hypothesis was wrong.** The connection to validator 4
that died every few slots was not a dial collision. The node closes the
whole QUIC connection when it refuses a message, and says so in the close
frame: `Bad assurance: Invalid message (code 257)`, and on another
protocol `Invalid guarantee: Invalid work report hash (code 257)`. That is
§30.

The evidence is arithmetic. The harness spoils one assurance per validator
from a chosen slot, and which fault each poses is fixed by index: 0 and 3
send a wrong anchor, 2 claims an empty core, **1 and 4 sign with the wrong
key**. In `sessions/teardown-2`, after the spoil slot, validator 1 sent 16
assurances and lost 16 connections, validator 4 sent 8 and lost 8, and
validators 0, 2 and 3 sent 6, 18 and 18 equally invalid ones and lost
none. Validator 3 is dialled by the same side as 4 and sends in the same
instant: an assurance the node cannot *accept* is fine, an assurance it
cannot *verify* costs the connection.

**Why five sessions held the evidence and none of them showed it.** `handle_connection` discarded the
error that ended its accept loop, so every connection death looked alike.
And §29's own fix logged re-dials only on the side the harness dials —
validator 1 was being dropped twice as often, on a connection the node
re-dialled itself within the millisecond, and nothing said so. A log that
covers half the subject finds half the pattern and makes it look whole.

**What changed.** The transport now reports a connection's end as
`ConnectionEnd`: the peer's close with its code and reason, kept apart from
an idle timeout and from this side hanging up — the treatment
`ReadError::Reset` already had, for the same reason. `transport_it` proves
it over real QUIC and the mock alike. The emulator records every end, on
both halves, read as a snapshot when the window closes so that the teardown
that follows cannot be mistaken for the node.

**The row.** `rejection_keeps_the_connection` (Soft), reporting each close
with the node's own words and the instant, so the row points back into the
trace. Soft deliberately: `simple.md:115-120` gives the stream reset as the
way to reject but nowhere forbids closing the connection, and hard-failing
a node on a rule nobody wrote is the mistake §18 and §27 record.
`n0_connection_close_sim_it` grades both directions — both runs put the
same bytes on the wire and only the node's answer differs. Live
(`sessions/teardown-4`, 581 rows): thirteen closes and thirteen rows,
eleven of them over an assurance and two over a guarantee.

**One known failure explained.** `n2_self_proxy_ce132_all_peers`, "one
self-proxied ticket did not reach one peer, seen in consecutive runs and
not yet written up", is not an N2 defect: the node had closed the
connection to that peer, so there was nothing there to reach.

**Both write-ups are drafted** — `ask_dave_rejection.md` for whether the
escalation is allowed at all, `ask_polkajam_rejection.md` for the
behaviour — and neither is sent. Tracing the node for them confirmed the
measurement from the other side: `AssuranceTrackerError::is_misbehaviour`
is true for one variant, returned from the signature check alone, so three
of the five faults the harness poses cannot reach the close and two must.
The measured table is the source read back, not a sample. It also showed
the escalation is deliberate rather than an oversight, which is why both
documents ask a question instead of filing a defect.


### After PR #23: the two sides of the oracle socket must agree on a codec, 2026-11-19

**§7 closed.** The harness and the oracle are separate cargo trees with
separate lockfiles, and both ask for `jam-codec` -- the codec on the socket
between them -- by a caret requirement. They resolved differently once, and
the harness ended up accepting a non-canonical compact length that the node
under test rejects: laxer than the thing it grades, on every length prefix
on the wire, with no error anywhere. Both are pinned to 0.1.2 now, and until
this nothing checked that they still agree.

**Behaviour, not a version string.** §7 proposed reading each resolved
version out of its own `Cargo.lock` in a `build.rs` and comparing the two.
What was built compares what the codecs *do*: `codec_probe()` encodes ten
compact integers at the width boundaries and decodes five canaries, and the
handshake carries the answers. `m2-oracle-proto` is compiled once in each
tree against that tree's own codec, so one source runs in both places. A
version is a label, and two builds can carry one number and act differently.

Three canaries are the inputs that actually split 0.1.1 from 0.1.2, measured
against the published crates rather than assumed; a fourth is canonical and
a fifth is truncated, so the probe has cases both versions agree on -- a
probe whose every canary discriminates cannot tell a codec that disagrees
from one that refuses everything.

**Seen to fire.** `crates/m2-reference/tests/oracle_handshake_it.rs` stands a
fake oracle on a unix socket and drives the refusal through
`Oracle::connect`, with the lax probe set to 0.1.1's measured answers, plus a
control where the codecs agree and the connection is accepted. The
protocol-version guard, which had also never been driven over a socket, is
tested there too.

**`PROTOCOL_VERSION` is 9**, because `PeerInfo` changed shape. An oracle
binary older than that cannot report itself as a version mismatch -- reading
the version is what fails -- so the handshake names the likely cause and the
command that fixes it. **Anyone pulling this runs `./scripts/prepare-nut.sh`
once.**

**Found while there.** The oracle tree is outside the workspace, so
`cargo fmt --all` and `cargo clippy --workspace` never reached it, and it had
drifted. Formatted, and §6's reproduction commands now include
`(cd oracle && cargo test && cargo fmt --check)`.


### After PR #25: two hard findings were the harness crediting the node with accepting what it refused, 2026-11-20

**§8 closed, and it was ours.** The title it carried for three days --
"the node accepts a CE 133 extrinsic message of the wrong size" -- was the
thing that was wrong. The node refuses it. `read_exact` is not a byte read:
it is `read_range(n..=n)`, which checks the message's own declared size and
makes a mismatch a `Misbehaviour`, and a misbehaviour closes the connection.
The lane read the verdict off `ReadError::Reset` alone, so a refusal
delivered at the connection left `refused: false` and the row reported the
node as having accepted what it had rejected hardest.

Measured on both sides in `sessions/ce133-1`, with the node's own
misbehaviour logging turned up:

| | |
|---|---|
| node (`peer-misbehaved`) | `Message size 1 outside expected range 0..=0` |
| harness (`[submission]`) | `closed by the peer: Message size 1 outside expected range 0..=0 (code 257)` |

**§4 was built on a misreading of the same node.** It said polkajam bounds
CE 133's first message by a derived `max_encoded_len` "far above 200 KiB".
`WorkPackageWithCore` has a hand-written bound of
`CoreIndex::max_encoded_len() + SANE_MAX_PACKAGE_SIZE` = **204,802**, which
is the spec's `2 + (200 * 1024)` to the byte -- and the impl is
byte-identical at `b1ea8aca4`, the pin §4 was measured against. It was a
misreading when written, not a change in the node since.

**What survives is sharper than what it replaces.** The same run put 205,069
bytes on CE 146's work-package message against its 204,800-byte cap and the
node took it, with the honest CE 146 submission beside it taken and shared
normally. CE 133 reads the package as `WorkPackageWithCore`, which carries
the spec's number; CE 146 reads it as a bare `ImmutableWorkPackage`, which
carries the derived bound. One rule, two types, two answers.

**`ask_dave.md` was rewritten before being sent**, because the claim
corrected above was its central piece of evidence. The question survives and
is better for it: one implementation has taken both readings, one per
protocol, which is a stronger reason to ask what the wording means than a
node that simply ignored it.

**The fix.** `SubmittedPackage` carries the connection's end as well as the
stream's reset; `refused_either_way()` counts a reset or a close the *peer*
performed, and not a timeout or a hang-up on this side. The rows are renamed
`_reset` -> `_refused`, because they ask whether the rule was applied and
not where the answer landed -- that is one question about every protocol, so
N0's `rejection_keeps_the_connection` grades it once, and now sees the
builder's connection too. `BUILDER_PEER` moved to the lane that prints it,
so the row no longer reports the builder as "validator 176".

`n3_sim_it` grades the fix against a stand-in that closes on an over-cap
package in polkajam's own words, with a node that neither resets nor closes
as the control. Narrowing the predicate back to `refused` makes the new
assertion fail, which is how the guard was checked to be one.

**Known hard failures are four, where they were six**
(`sessions/ce133-2`, 450 rows over 150 s): `ce129_boundary_parent_before_child`
and `n2_unknown_epoch_reset_observed` (§3), `n3_ce146_oversized_refused`
(§4) and `n3_ce134_answered` (§5). Both of the two that went were the
harness's, so this round adds **two more harness defects found by live
runs and no new defect in polkajam**.


### After PR #26: the CE 134 share was anchored past the node's recent window, 2026-11-20

**§5 closed, and it was ours too.** The share the harness offered was
composed when the run was planned and sent nine slots later, by which point
its anchor had fallen out of the node's recent blocks -- eight of them. The
node said so once its guarantor logging was turned up
(`sessions/ce134-1`):

```
failed to receive WorkPackageSharing(0): guarantee table error:
  invalid anchor 0xdfa8dd97427288ed...
```

Refusing it was correct. And the refusal carried `0x100`, `NoError`, which
§5 read as the node declining without a reason; the node's own source says
it is the default on an error path with no code attached, in a TODO sitting
directly above that handler. The *shape* of the refusal was right --
`simple.md:115-120` gives the acceptor's reset as the way to reject -- so
there was nothing to report that polkajam has not already written down.

**The harness had fixed this once already, in the sender beside it.**
`spawn_report_sender`'s own comment records the identical failure for
CE 135: an anchor that "has aged out by the time it goes out seven to
eleven slots later". CE 134's sender never got the lead. It has one now,
the same two slots, for the same reason on both sides.

**The worse half.** Both shares -- the honest one and the one offering a
wrong shard count -- were being refused for that stale anchor, so
`n3_ce134_wrong_shard_count_refused` passed across two pins without the
shard count ever being the reason for anything. A reset carries no reason,
so the only thing that can attribute a refusal is the honest share beside
it being answered; that control was failing and the row took the credit.
It now reports itself unexercised when the control did not succeed.

**The false pass was written down three times and all three agreed**: the
row, the sim test (a stand-in refusing *every* share was required to leave
the row passing) and the unit test (the faulty share with no honest share
beside it, asserted to pass every row). The tests were written from the
same reading as the code, so they agreed with it rather than checking it.
All three are inverted now, and each fails if the gate is removed.

**Confirmed** (`sessions/ce134-3`, 464 rows over 180 s): `n3_ce134_answered`
and `n3_ce134_hash_equals_the_reference` pass, the first for the first time
since 2026-11-16, and the shard-count row passes for the reason it names:
`unacceptable shard count 5`, in the node's words.

**Known hard failures are three**, where this session began with six:
`ce129_boundary_parent_before_child` and `n2_unknown_epoch_reset_observed`
(§3), and `n3_ce146_oversized_refused` (§4). Every one of the three that
went was the harness's.

**One fragility exposed and not fixed.** A run between the two above sent no
share at all and the report said only "not exercised". The share plan is
claimed by the first connection to reach it and held across the nine slots
until the share is due, and a node that closes connections every few slots
(§30) can take it away meanwhile. The sender's two silent returns now say
which it was and quote the connection's end. Whether it should re-dial is
open; it has not recurred.


### After PR #27: the spec pin moves to aa0e2b8, and P3's plan is re-specified, 2026-11-20

**§28 closed.** The repository now reads `simple.md` at **aa0e2b8
(2026-10-26)**, re-pinned from a96dc6b (2026-09-02).

**What §28 got wrong about itself.** It said "Nothing is wrong in the code:
N5 and N6 do not exist yet." The *lanes* do not. The **codecs did**, and
they modelled the superseded wire in full: `AuditAnnouncementMsg` with its
`Tranche` byte, `Evidence` with `Tranche0`/`Subsequent` variants,
`SubsequentEvidence` with its no-show list, and a `Judgment` whose guarantee
was an `Option` appended after the signature. Fourteen tests asserted those
shapes, three of them hand-built byte vectors. §11 and §15 are the same
defect -- a codec that is a shape model rather than the wire -- and this is
a third instance, found before a lane was built on it rather than after.

**Three shape changes, now asserted rather than inferred:**

| | was | is |
|---|---|---|
| CE 144 tranche | a `Tranche` byte on the wire | an `Intent` byte, 0 or `1 ++ Core Index`; the tranche is derived from the signature's VRF output (`:769-771`) |
| CE 144 evidence | a second message with per-report no-show lists | gone; a later-tranche announcement proves itself with `S(r)` alone |
| CE 145 guarantee | an optional trailing message, present iff validity was 0 | inside the validity discriminator, so **before** the work-report hash (`:820-821`) |

Both protocols also batch now: `[Announcement]` and `[Judgment]`, and CE 145
may mix auditors, work-reports and epochs in one message (`:814-815`). A
lane expecting one value per message would fail a conforming node on its
first batch.

The CE 145 change is the one most likely to be got wrong by patching the old
struct: an `Option<Guarantee>` appended at the end still compiles, still
round-trips against itself, and is wrong on the wire by the width of a
guarantee. The codec's test asserts the hash's **position** after the
guarantee, not merely that both are present.

**The re-pin was not optional.** DESIGN §2 states the invariant: *"Every
`simple.md:NNN` in this repository refers to that revision."* Re-specifying
N5 against HEAD while the rest cited a96dc6b would have broken it, and a
repository carrying two spec revisions without saying which is which is the
defect class §6 and §7 record.

**How it was done, and what it cost.** Mechanically, against the old text
rather than by eye: each citation was read at a96dc6b, matched
byte-for-byte against aa0e2b8, and rewritten only where exactly one
candidate matched. **93 renumbered across 14 files**, 157 already identical,
and everything else reported rather than guessed.

Two lessons, both in §28:

- **Most citations moved by +3 and the ones that mattered did not.** CE
  144/145's moved by −2, −6, −8 or changed outright. A constant-offset
  renumber would have left the N5 citations plausible and wrong.
- **Do not run the renumberer over a file already written against the new
  revision.** Several citations in the rewritten codec were renumbered a
  second time, because their *old-revision* text happened to match
  elsewhere at HEAD: `:819` became `:811`, `:825` became `:819`. Caught by
  reading every citation in that file back against HEAD, which is the check
  to repeat on any future re-pin.

**What this does not close.** §4's question survives: the size-cap wording
is untouched since 2026-03-22, so it is still unanswered at HEAD.


### After PR #28: N6 is a running lane, 2026-11-20

**P3's smaller half is implemented and passing** (`sessions/n6-4`, 541 rows
over 240 s, six lanes). The same three hard findings as before, all node-side.

**The lane's hard part was never the wire.** `simple.md:705-707` makes the
node's duty conditional -- it follows up an announcement "provided the
preimage has been requested on chain by the given service" -- and polkajam
enforces it exactly: `note_preimage` returns `NotRequested` otherwise. So
the run has to get a `Solicit` accumulated before it says anything. The dev
bootstrap service takes one, the same way `Export` already serves §17.

**N6 is the only lane that speaks as an ordinary peer.** polkajam's
`as_val_from_ordinary[PreimageAnnouncement]` is unlimited while
`as_val_from_non_neighbor[PreimageAnnouncement]` is disallowed, so an
announcement from a validator the NUT does not neighbour is refused on the
peer class alone. And the announcer cannot send and leave: CE 142 and CE 143
run in opposite directions on one connection, so it holds for the ten
seconds `:708` names and serves whatever the node opens.

**Three live runs, three harness defects, and the node right every time.**

| run | what failed | what it was |
|---|---|---|
| `n6-1` | no announcement at all | the solicit package's hash was never recorded: a field declared and nothing written to it |
| `n6-2` | the node ignored the announcement | the solicit was on its own submission, which is never accumulated (§31). No service had asked for anything, so ignoring it was correct |
| `n6-3` | inclusion unexercised | the NUT authored no block after the announcement. The control working, not a defect -- `n6-4` authored one and the row passes |

Every one of those reported itself as unexercised or named the node's
correct behaviour. None invented a node defect, which is what the gating is
for and what §5 cost two pins for lacking.

**§31 is the constraint `n6-2` found**: only the first package a run submits
is ever accumulated, because the availability plan assures one report. The
solicit therefore rides the honest package, which is not where it belongs;
the comment says why it has to, so the next reader does not tidy it apart.

**N6 completed the same day.** The first cut graded the happy path and
nothing else: it showed the node asks when it should and nothing showed it
declining when it should not. Three rows closed that, and two of them had
been talked out of in DESIGN on reasoning that did not hold:

| row | what it catches |
|---|---|
| `n6_unsolicited_not_requested` (Hard) | a node that asks for anything it is told about, ignoring the on-chain condition |
| `n6_mismatched_preimage_not_included` (Hard) | a node that includes a blob failing its own hash -- Hard where inclusion is Soft, because the preimage extrinsic is keyed on the hash |
| `n6_gossip_reaches_neighbours` (Soft) | a node that gossips to some peer rather than to its grid neighbours |

**Two justifications in DESIGN were wrong and are recorded as such.** The
gossip row was skipped because the emulated validators were said not to
neighbour the NUT in every run -- but the grid is `index / W` and
`index % W` (`simple.md:188-189`), a function of the index alone, so who
neighbours whom never varies. And the unsolicited row was skipped because
its silence was said to be indistinguishable from an unmet precondition --
but the solicited announcement in the same run is its control, which is how
every N3 fault row already works. Both were rationalisations of a gap. They
are quoted in DESIGN beside the correction, because a wrong reason left in
place is worse than the gap: nobody re-examines it.

`grid_neighbours` is the one implementation, checked against the tiny grid
§2 names rather than copied from it. Its own test found a bug in it: an
index outside the set still shared a column with somebody, so neighbouring
stopped being mutual.

**Two checks earned their keep during verification.** Clippy's `unreachable
pattern` was a real defect, not a style nit -- `CE142` was not imported in
`emu.rs`, so the new match arm bound it as a *variable*, swallowing every
stream kind and making the refusal arm dead. It compiled and the tests
passed. And the dry-run baseline *failed* its own gossip row, because the
fabricated node announced to peers 1 and 3 where validator 0's neighbours
are 1, 2 and 4 -- a baseline that models a conforming node and fails is a
wrong fabrication, not a wrong node.

Confirmed (`sessions/n6-5`, 592 rows over 300 s): all five N6 rows pass
against polkajam. The node asks for the solicited preimage, leaves the
unsolicited one alone, and announces what it obtained to its grid
neighbours.

**The sim test found a tautology in a row written hours after §5.**
`n6_ce143_asked_for_what_was_announced` was emitted only for a request that
had already matched the announcement, then asserted it matched -- true by
construction. Posing the fault that asks for an unannounced hash made the
row *vanish* rather than fail. It now grades every request the node made
against what it was told about, and the test asserts the row **fails**
rather than merely not passing, which is the distinction that would have
hidden it.


## Milestone ladder

| Milestone | Lanes | Coverage | Status |
|---|---|---|---|
| **M2-A** — Foundations live | N0, N1 | 6 / 41 | ✅ **complete** — §1 |
| **M2-B** — Self-tested | N2 | 8 / 41 | ✅ **complete** — the N2 lane is complete, and the self-test mechanism now covers every implemented lane: 76 named faults, 24 integration tests, one file per lane. See below |
| **M2-C** — Guaranteeing | N3 | 21 / 41 | ✅ **complete** — the lane runs against polkajam and every submission row is held to the fault bar (`m2-sim/tests/n3_*_sim_it.rs`, 36 tests) |
| **M2-D** — Availability | N4 | 30 / 41 | ✅ **complete** — the lane runs; serve, assurance and inclusion rows all proven by injected faults (`n4_sim_it.rs`, `n4_inclusion_sim_it.rs`, 14 tests) |
| **M2-E** — Audit & preimages | N5, N6 | 41 / 41 | ◑ **half** — N6 complete and passing (2026-11-20, `n6_sim_it.rs`, 9 tests). **N5 parked**, see below |
| **M2-F** — Adversarial | N7 | + fault matrix | ◑ **as far as it goes** — six of DESIGN §11 N7's nine rows built; the other three are blocked, not unstarted (§34–40 of `findings.md`). See below |
| **M2-G** — Rollout | — | ecosystem-gated | ⏳ not started — one node has ever been graded |

**On N5, the one designed lane with no implementation.** Not blocked on effort. `jam-np`
replaced the CE 144/145 wire format on 2026-10-26 (`aa0e2b8`); polkajam `main` still speaks
the superseded one, and the replacement sits on an unmerged branch
(`feat/tranche-redesign`). Grading a format that is about to be replaced would produce rows
about a node nobody will run again, so the lane waits for the redesign to land.
`findings.md` §32 records the decision and two things that are easy to forget by then: the
redesign makes N5 *harder* rather than easier, because the current format derives the
tranche and cores from a Bandersnatch VRF output instead of declaring them; and the two
formats are separable by message length, if a tolerant reader is ever wanted.

**On N7.** Six rows of nine are built: unknown stream kind, malformed and truncated
messages, slow-loris, flood (§37), kill-and-restart, and index rotation (§39). **The
remaining three are blocked rather than unstarted** — equivocation and reorg both need
the harness to hold a block its own chain does not contain, which the reference engine
will not author (§38), and the epoch-transition row needs a validator-set change the
reference chain cannot follow (§40). Each would be easy to *check*; none can be
*driven*. Unblocking any of them means a change in the oracle or in polkajam's authoring
rather than in the lanes, so the milestone is as far as it goes rather than part-done, and
DESIGN §11 N7 marks the three in its own table.

Index rotation is unlike the other five: it grades across runs rather than within one, so
it produces no row in a single report. `--validator-index` re-runs the suite and
`rotation.rs` compares the reports, calling out only a row that passed at one index and
failed at another. It has found two things so far — §39 and §41 — and both were the
harness's, not the node's.

**Separately, and not the same three:** three of the rows that *are* built have no
fault-injection coverage and cannot get it from `m2-sim`, which runs in-process —
`n7_restart_serves_again`, `n7_restart_authors_again` and `n7_node_alive_after`. There is
no process to kill and no stand-in that can pose "came back but will not serve". §36
records that as a real gap in the terms the project holds every other lane to.

The flood rows **were** in that position and no longer are (§42, closed 2026-11-26). The
test proved the measurement — a stand-in that answers its bystander throughout against one
that stops — and asserted on `connection_answers` rather than on the row's verdict. It now
builds the `FloodFacts` the live runner builds and asserts the outcomes, and a mutation
confirms it fails when the row is rewired to pass regardless.

`n7_flood_authors` was the half §42 left open, and it is closed too (2026-11-27). The row
reported `true` or reported nothing, because the harness could not tell a missed turn from
no turn. §22's work had already built the answer — `drive_slots` records the slots the
reference engine declines, which is how it says a slot is the node's — and the row now
fails where the node owned a slot inside the flood window and no block of its for it ever
arrived. It under-counts in the two ways §22's own row does, and a mutation confirms both
of its losing arms.

**On M2-B.** Its bar is *"Safrole tickets covered, **and** the harness's own checks are proven
by deliberately faulty simulated clients"* — the delivery plan calls it the structural
milestone: *before it, the harness reports; after it, the harness can be trusted to judge.*

*Safrole tickets covered* now holds in full. As of 2026-11-03 every row of DESIGN §11 N2 is
implemented, the Faults column included: seven checks, graded live, with a catalogue of seven
deliberately-broken ticket shapes injected into each run as the ticket budget allows, and every
negative verdict gated on a control so that it cannot pass on a run in which the node did
nothing. Three rows deliberately assert less than the DESIGN wording reads like: the proxy
rule's set membership is unobservable with this topology, a hard bound at the forward
window's nominal upper edge would fail a conforming node under tiny, and "no forward" is not
assertable for a fault delivered over CE 132. DESIGN §10 and §11 N2 record each one.

*Proven by deliberately faulty simulated clients* now **holds across every implemented
lane**. The machinery — an in-process transport, a virtual clock and `m2-sim`, a node-shaped
stand-in that can be broken in one named way at a time — carries 76 named faults and 24
integration tests, one file per lane: each row is shown to pass against an honest simulated
node and to *fail, present in the report*, against one that gets exactly that thing wrong.

The distinction this closes is not pedantic, and the project kept earning it. Two of the four
hard failures ever observed were harness defects of exactly the kind a faulty client catches.
Writing N4's inclusion faults found both of `n4_ce141_inclusion`'s rows asking for the wrong
block (`findings.md` §14). Writing N6's found a row that *vanished* instead of failing when
the node asked for the wrong preimage. Writing N7's found two defects in its own rows —
caught not by a test but by reading the first real report, which is the rule §35 ends on.

What remains: N7's two restart rows and its liveness row, which cannot be covered this
way at all, because `m2-sim` runs in the test process and there is no process to kill
(§36); and the fact that nothing drives a
simulated run from the CLI — the proofs live in the test suite, which is where they run on
every commit.

This document records what each milestone required, the evidence that it holds, what is not
covered, and how to point the suite at a third-party node.

---

## 1. M2-A — complete

| Criterion | Status | Evidence |
|---|---|---|
| Five peers register with the NUT | ✅ | 45 consecutive `Net status: 5 peers (5 vals)` samples in the NUT log |
| The chain advances | ✅ | reference chain authors every emulated slot; NUT imports and re-announces |
| The NUT's slots are left unclaimed | ✅ | harness keystore holds no key for the NUT index; NUT authors its own slots |
| A non-vacuous run exists | ✅ | 82–122 graded checks per run, with real findings, exit code 1 |

The three blockers that defined P0 are closed. The harness now produces a conformance verdict
that depends on what the node actually does, which is the property M2-A exists to establish.

---

## 2. What M2-A required

Three confirmed blockers stood between the harness and a verdict that meant anything. They were
recorded in the September planning drafts, since superseded by this file. Before they were fixed
the only all-green evidence was a `--dry-run` that fabricated its own input.

| # | Blocker (as recorded) | Status |
|---|---|---|
| 1 | NUT registers zero peers — `0/0 active peers`, no UP 0 handshake ever completed | closed |
| 2 | The harness steals the NUT's slots — measured 96/96 slots claimed, 18 as the NUT | closed |
| 3 | Genesis sits ~8.8M slots behind the wall clock, so ticket distribution is refused | closed |

### Blocker 1 — peer registration

Five emulated validators complete the UP 0 handshake and stay registered for the whole
observation window:

```
INFO jam_node::node  Net status: 5 peers (5 vals)
INFO jam_node::node  Sync status: Idle, 3 peers
```

(`sessions/m0-verify/logs/nut.stderr.log`, repeated every 2 s until teardown.)

### Blocker 2 — NUT slots left unclaimed

The fix is structural rather than conditional: the harness keystore is built with a keyset that
belongs to no genesis validator in the NUT's position, so the authoring harness has no key to
claim that slot with and skips it.

`crates/m2-reference/src/chain.rs`:

```rust
/// The keyset handed to the NUT's slot in the harness keystore.
///
/// The keystore is a fixed-length vector with one slot per validator, so the
/// NUT's slot cannot simply be left out. `trivial(u32::MAX)` is a well-formed
/// keyset that belongs to no genesis validator, so the harness never matches it
/// against an author index and never claims a slot with it.
const NON_VALIDATOR_KEYSET: u32 = u32::MAX;
```

Confirmed live: the NUT authors, and the N1 lane imports and grades those blocks — parent,
seal, prior and posterior state roots.

### Blocker 3 — genesis anchoring

Genesis is anchored to the start of the current epoch rather than slot 0. Two defects had to be
fixed together for this to hold:

- `current_epoch_start_slot()` divides the wall-clock slot by `epoch_period`, which is
  **process-wide state**. Read before the tiny parameters are applied it uses 600 rather than 12,
  which anchors genesis up to 599 slots back instead of at most 11. `run` now applies
  `ProtocolParameters::tiny()` before anything reads a parameter.
- A ticket is sealed against entropy buffer **entry 2**, which is what a node validates against.
  The harness used entry 1. Entry 1 is what entry 2 *becomes* after the next epoch change, so the
  two agree whenever an epoch boundary happens to fall between proving and delivery — which the
  mis-anchored genesis made likely. Each bug masked the other.

Result: the node accepts every ticket the emulator offers. `invalid ticket signature` went from
20 occurrences per run to 0.

---

## 3. Harness state

| | |
|---|---|
| Crates | 7 (`jamnp-s`, `m2-oracle-proto`, `m2-reference`, `m2-emu`, `m2-scenario`, `m2-runner`, `m2-sim`) |
| Rust | 40.3k lines under `crates/*/src`, 46.0k with the integration tests |
| `cargo test --workspace` | **592 passed / 0 failed** (plus the oracle tree's own) |
| Lanes implemented | N0, N1, N2, N3, N4, N6, and N7 — six of N7's nine rows, the other three blocked rather than unstarted. N5 parked — see the ladder |
| Fault injection | 76 named `SimFault` variants, 24 integration tests across 17 files, one per lane |
| `cargo fmt --all --check` | clean |
| `cargo clippy --workspace --all-targets` | 3 warnings, all pre-existing |
| Dry-run baseline | exits 0 — 137 rows, 122 hard and 15 soft, all passing |
| Live run | exits 1 — correct; hard findings exist |
| Spec pin | `jam-np/simple.md` @ `aa0e2b8` (2026-10-26) |
| Node pin | polkajam `d92cadd30` (`polkajam 0.1.29`, GP 0.8.0) |

### Live results vs polkajam-as-NUT

Verification run (`sessions/m0-verify`, 2026-10-28): **82 checks, 5 findings, 4 distinct hard
failures**, exit code 1. Five peers registered and stayed registered for the whole window
(45 consecutive `Net status: 5 peers (5 vals)` samples).

Run-to-run check counts vary between roughly 82 and 278 — a 90 s window grades a fraction of
what a 300 s one does — because which slots the node wins and
when a proxied ticket arrives decide which rules get exercised. A single run is not a stable
baseline, and the set of findings is not stable either — see the caution below.

**Current, `sessions/status-all` (2026-11-24), all seven lanes over a 300 s window: 631
rows — 406 hard passes, 40 soft passes, 3 hard findings.**

| Lane | Protocols | Rows | Result |
|---|---|---|---|
| N0 connectivity and sync | UP 0, CE 128, CE 129 | 43 | 1 hard failure: `ce129_boundary_parent_before_child`, a node defect standing since the first runs |
| N1 authoring | asserted over UP 0 and CE 128 | 67 | clean; parent, seal and prior/posterior state roots graded per block |
| N2 Safrole tickets | CE 131, CE 132 | 133 | 1 hard failure: `n2_unknown_epoch_reset_observed` — the ticket is refused, the stream is not reset |
| N3 guaranteeing | CE 133, CE 146, CE 134, CE 135 | 74 | 1 hard failure: `n3_ce146_oversized_refused` — `findings.md` §4, **confirmed a node bug** by polkajam 2026-11-25 |
| N4 availability | CE 137–141, CE 148 | 297 | clean on hard rows; 127 soft rows are one unexercised control |
| N6 preimages | CE 142, CE 143 | 5 | clean |
| N7 adversarial | malformed streams, restart | 12 | 6 soft failures — `findings.md` §35; the restart row is correctly unexercised outside an N7-only run |

The three hard findings are the same three the previous run reported, and none is the
harness's. The older narrative below records how four earlier ones were closed, every one of
them ours.

Four distinct hard failures have been observed. Reading the node's own log alongside them shows
that **only two are node defects**; the other two are the harness blaming the node for a refusal
it was right to make.

| Check | Verdict | Seen |
|---|---|---|
| `ce129_boundary_parent_before_child` | node defect | every run |
| `n2_unknown_epoch_reset_observed` | node defect | every run |
| `n2_proxy_duty_forwarded` | **harness-induced — fixed 2026-10-29 and 2026-10-30** | was intermittent |
| `n1_extrinsic_includes_delivered` | **harness-induced — fixed 2026-10-29** | was every run |

**Update, 2026-10-30.** Every hard failure but the two node defects is closed. §3.1 records four
delivery fixes and §3.2 three more, with the evidence for each. `n2_proxy_duty_forwarded` took
both rounds: the gate of §3.1 got tickets accepted at all, and the decoder fix of §3.2 got the
node's forwards seen. The latest run (`sessions/unitB-9`, 2026-11-03, a 300 s
window) reports **278 checks and two hard findings, both node defects** — the same two, now
against a run that also injects six deliberately-broken tickets, grades every block of the
submission epoch on what the node did with them, and exercises the proxy duty four times.

That run adds two soft rows. `n2_proxy_duty_bad_proof_ignored`: the bad-proof fault reached
the node (its own log says `Error processing incoming ticket: invalid ticket signature`), so
it detected the forgery and refused it — but did not reset the stream it arrived on. That is
`n2_unknown_epoch_reset_observed`'s defect in a second place, and the harness now sees both.
`n2_forward_stops_at_finality` reports itself unexercised: the node sends each ticket to each
peer exactly once, so it never had a forward to stop, which is the expected verdict against
this node rather than a gap to close (DESIGN §11 N2, "The stopping rule").

**Five runs, 2026-11-09: what is stable and what is not.** The transport and clock work was
verified by running the same 300 s command on the branch and on unmodified `main`, alternating,
on one machine. The findings are not identical run to run, which is itself the most useful
thing the exercise produced.

| session | code | checks | findings |
|---|---|---|---|
| `control-1` | `main` | 256 | ce129, `n2_gen_proof_verified` ×4, finality-control, unknown-epoch |
| `control-2` | `main` | 244 | the same five |
| `transport-1` | branch, transport | 233 | the same five |
| `clock-2` | branch, transport + clock | 267 | the same five, **plus** `n1_timing_within_slot` |
| `clock-1` | branch, transport + clock | 273 | ce129, unknown-epoch, **`n2_proxy_duty_forwarded`**, bad-proof, repeat-control |

**Stable in all five**, on both codebases: the two known node defects, and four
`n2_gen_proof_verified` failures in four of the five -- every ticket the node generated for the
run's *final* epoch, with the fifteen-odd before them passing. The four proofs are
byte-identical across runs, so the node is deterministic here and the harness reaches the same
verdict every time. These had never appeared before 2026-11-09, including in `unitB-9`, which
saw 13 CE 131 tickets where these runs see 19. The likeliest reading is that a run reaching one
epoch further than earlier ones asks the reference chain to verify a ring it has not caught up
to -- a harness gap of the kind §3 already has two of, the harness failing the node for
something it cannot yet check. `ticket.verified` is `Some(false)` rather than `None`, so the
lane believed it held the context; if the context is in fact absent, the honest row is the soft
`n2_gen_proof_unjudged` it already has. **Hypothesis, not diagnosis, and open.**

**Intermittent**, each seen in exactly one run of five: `n2_proxy_duty_forwarded` (a ticket
delivered on the wire and in time, forwarded to no peer at all, one slot before an injected
bad-proof ticket the node also failed to reset the stream on) and `n1_timing_within_slot` (a
block announced 8.7 s into a 6 s slot, on a machine that was building and grading at the same
time). Neither reproduced on a second run of the same code, and neither is attributable to the
transport or clock work: the branch produced the stable set in two runs of three, and `main`
produced it in both of its own.

**What this says about the harness.** Five runs of one command against one node produced four
different finding sets. Check counts were already documented as varying; *findings* varying is
a stronger statement, and it means **a single live run is not a verdict** -- not of a node, and
not of a change to the harness. Attribution here needs alternating runs on both codebases, and
even then an intermittent row cannot be pinned by one appearance. This is the gap M2-B exists
to close: a simulated node on a virtual clock is reproducible by construction, and would turn
each of these rows into something that either always happens or never does.

#### 3.1 The delivery fixes, 2026-10-29

Three of the four hard failures above were the harness grading the node against its own
intentions rather than against what happened on the wire. Four changes closed them.

**1. A readiness gate on ticket delivery.** A node validates an incoming ticket against finalized
state, so one whose finalized head is still behind the current epoch refuses every ticket it is
offered — polkajam's `ticket_preflight` returns `FinalityLagging` when `final_slot /
epoch_period < curr_slot / epoch_period`. That is the normal state for a second or two after the
harness seeds a chain the node must import, which is exactly when the first tickets went out.
Every UP 0 message the node sends carries its finalized block, so the emulator now keeps a
watermark of the highest finalized slot the node has advertised and holds each ticket until that
head is in the current epoch. A ticket the node cannot accept inside its submission window is
**withheld** rather than sent into a refusal.

The gate is on the epoch, not on "the finalized head reaches the seeded head" as §5.7 used to
put it: finality trails the chain head by a slot or two indefinitely, so the literal version
waits for something that may never happen while the node has long been able to accept tickets.

**2. The lanes grade deliveries, not plans.** The gate alone would have produced the same false
failures from the other side, because `n2_proxy_duty`, `n2_inclusion` and `n2_unknown_epoch_reset`
read the *plan*. `EmuTicket` now carries `delivered_at_ms: Option<u64>`, and a ticket that never
went out is reported as **not exercised** rather than failed. `n2_inclusion` also emits a soft row
naming how many were withheld, so a run that withheld most of its tickets cannot pass on a
near-empty expectation and look like coverage it never had.

**3. The unknown-epoch probe is never owed.** The probe names an epoch past the node's horizon on
purpose and the node is *required* to refuse it. It is the epoch after the plan's, which is
exactly the submittable epoch of a block one epoch further into the run — so `N1` demanded that
the node include the one ticket it was obliged to reject. It only fired in runs long enough to
author such a block, which is why it read as intermittent and unexplained. `DeliveredTicket` now
carries `probe`, and nothing is ever owed on it.

**4. Each peer's plan is delivered in slot order.** A peer's sender walks its plan one entry at a
time, sleeping until each ticket's slot, and the plan was built in ticket order. A peer's CE 132
slot is spread by author index while its CE 131 slot is the window's first, so for every author
but the first the ticket proxied to the NUT sat behind a broadcast scheduled several slots later
and arrived that late — past the window any proxy could still forward in. Predicted and observed
send phases agreed exactly (authors 0, 3, 4 → phases 3, 6, 7 against a plan that said 3 for all).

| Evidence | Before | After |
|---|---|---|
| `finality lagging` in the node log | every run | **0** across 7 runs (`sessions/gate-1`…`gate-7`) |
| `n1_extrinsic_includes_delivered` | every run | gone |
| `n2_proxy_duty_forwarded` | failed, never passed | **3 hard passes** in `sessions/gate-6` |

`sessions/gate-6` is the first run in which the proxy-forwarding rule was ever *exercised*: five
tickets reached the node at epoch phase 4 and it forwarded at phase 5.

**Resolved since.** Two of those five forwards were not observed, and the batch split
`ceil(pending / remaining_win_slots)` fitted the three-then-two shape exactly. It was the wrong
explanation: the node had forwarded all five. See §3.2.

#### 3.2 The decoder defect and the scheduling fixes, 2026-10-30

Three more changes, and one of them explains every remaining `n2_proxy_duty_forwarded` failure
the project has ever recorded.

**1. The CE 131/132 decoder rejected any ticket attempt above 1.**

```rust
let attempt = input.read_byte()?;
if attempt > 1 {
    return Err(codec::Error::from("ticket attempt must be 0 or 1"));
}
```

`tickets_per_validator` is a protocol parameter — four under tiny — not a wire constant, so
every ticket numbered 2 or 3 failed to decode. `collect_nut_tickets` skips a frame that will not
decode, silently, because an undecodable frame is not evidence of anything. So the node sent the
ticket, the harness never saw it, and the lane recorded that the node had not sent it.

The evidence is in the traces that were already on disk:

| run | tickets proxied to the NUT | attempts | forwarded by the node | graded as forwarded |
|---|---|---|---|---|
| `sessions/gate-6` | 5, all arriving at phase 4 | 1, 1, 1, 2, 3 | all 5, to all 5 validators — 3 at phase 5, 2 at phase 6 | 3 |
| `sessions/fwd-2` | 1, arriving at phase 1 | 2 | 1, to all 5 validators, at phase 2 | 0 |

The three-then-two split in `gate-6` really is polkajam's batching, and it is also exactly where
the attempt numbers happen to divide — which is how a correct mechanism came to look like the
cause. `fwd-2` has no batching to hide behind: one ticket, forwarded to everyone one slot after
it arrived, graded as reaching nobody.

The range check is gone from the decoder. A decoder decodes the wire; a parameter range is the
lane's business, and the N2 lane already judges it as `n2_gen_attempt_in_range`, where an
out-of-range attempt is a **reportable failure instead of an invisible one**. The blast radius
was wider than the one check: the same drop shortened `own_ticket_ids` for N1, `nut_tickets` for
all of N2, and on the inbound path classified a conforming ticket as a malformed frame.

**2. The plan is laid out after the node can accept tickets.** The readiness gate of §3.1 holds
tickets back while the node finalizes the seeded chain, so a schedule written before that hold
names slots the tickets will not arrive in — and the proxy-forwarding duty is owed on arrival,
not on intent. `sessions/fwd-1` planned its one proxied ticket for phase 2 and the gate released
it at phase 7, past any forwarding window, with the plan none the wiser. The runner now waits for
the node's advertised finalized head to reach the current epoch before proving and planning;
ticket senders wait for a plan to exist rather than reading an empty map at connect time. The
wait is bounded at half the observation window, capped at an epoch: a node that never finalizes
has a defect of its own, and the run should go on to report it.

**3. A lottery that cannot exercise the proxy duty is traded for the next one.** A CE 131
delivery goes out at the submission window's first slot. If that slot is already past the
forwardable phases, nothing in the epoch can be, and the duty is reported as not exercised
however well the node behaves (`sessions/gate-7`, every CE 131 planned at phase 8). The runner
already waited out an epoch whose window had closed outright; it now also waits out one that is
open but too late to forward in — and only when the plan actually proxies something to the NUT,
since otherwise the wait buys nothing. `m2-reference` plans against the rule and `m2-scenario`
judges by it from different crates, so `forwardable_phases_match_the_judged_rule` compares the
phases they admit directly.

**Evidence.**

| | `gate-6` (2026-10-29) | `fwd-3` / `fwd-4` (2026-10-30) |
|---|---|---|
| Checks | 125 | 130 / 107 |
| Hard findings | 4 | **2 / 2**, both node defects |
| `n2_proxy_duty_forwarded` | 3 pass, 2 fail | **1 pass / 5 pass, none failing** |
| `n2_inclusion_covers_valid` | pass | pass |
| `finality lagging` in the node log | 0 | 0 |

The two that remain are `ce129_boundary_parent_before_child` and
`n2_unknown_epoch_reset_observed` — the two node defects of §3.

#### `ce129_boundary_parent_before_child` — node defect

> CE 129 put a boundary node at index 1 before its parent at index 3, of 11

`simple.md:275-281` requires a CE 129 response's boundary nodes to hold no duplicates and never
place a node before the node that references it. The check needs no knowledge of node layout: a
branch node carries its children's hashes, so if some 32-byte half of node *i* is the reference
to node *j*, then *j* is that node's child and must come after it.

One caveat on confidence: the check assumes a reference is blake2b-256 with the top bit of the
first byte cleared, that bit being the branch/leaf discriminator. If polkajam uses a different
convention the match is a coincidence. Cross-check against the node's trie code before raising
this upstream.

#### `n2_unknown_epoch_reset_observed` — node defect

> 1 of 1 ticket(s) for an epoch past the NUT's horizon were delivered and not refused; it must reset the stream each arrived on

`simple.md:335-337` requires a ticket for an epoch the node cannot know yet to make it reset the
stream. The node detects the ticket correctly —

```
WARN authoring  Error processing incoming ticket: bad ticket epoch value 797852
```

— rejects it, and then lets the stream finish cleanly. The emulator records a reset only on a
genuine `ReadError::Reset`, deliberately: a connection that died for its own reasons must not be
credited as a refusal. So the node is right semantically and wrong at the transport layer.

The verdict is unchanged by the 2026-11-02 attribution work, but its basis is firmer. The check
used to ask whether *any* reset had been seen in the run; it now asks whether the probe itself was
refused, which is the question the rule poses. Both answers happen to agree here because the probe
is the only ticket a run currently offers that the node is meant to reject.

#### `n2_proxy_duty_forwarded` — harness-induced (closed, §3.1)

> a ticket proxied to the NUT in slot 9574202 must be forwarded via CE 132 to every validator;
> it reached peer(s) [] and not [0, 1, 2, 3, 4]

The node never forwarded the ticket because it never accepted it — one of two causes, the
other being §3.2:

```
10:00:09.504  WARN authoring  Error processing incoming ticket: finality lagging (final: 9574199, curr: 9574201)
10:00:09.505  WARN authoring  Error processing incoming ticket: finality lagging ...
10:00:09.506  WARN authoring  Error processing incoming ticket: finality lagging ...
10:00:09.508  WARN authoring  Error processing incoming ticket: finality lagging ...
```

Slot 9574202 begins at 10:00:12. The harness delivered four tickets 2.5 s earlier — correct by
its own arrival-lead rule — but that was seconds after launch, while the node was still
finalizing the chain it had just been seeded. It refused all four on a finality-lag guard, and
the harness graded it for not forwarding one of them. See §5.7.

This check is also intermittent for an unrelated and legitimate reason: the rule can only be
demanded when a proxied ticket reaches the node early enough in the lottery for a forward to be
meaningful. Arriving late, it is reported as a soft "not exercised" row instead — which is how
`sessions/n2-9` recorded it, at phase 8 of the lottery.

#### `n1_extrinsic_includes_delivered` — harness-induced (closed, §3.1)

> block at slot 9574202 owed 4 ticket(s), could carry 3, carried 0
> block at slot 9574214 owed 1 ticket(s), could carry 1, carried 0

The first is the same four tickets refused for finality lag — same slot, same cause, not a node
defect.

The second was not explained by anything in the log at the time of writing. It is now: the
ticket the node "owed" was the unknown-epoch probe, which it is required to refuse — see §3.1,
fix 3. The original reasoning, kept because it shows how the wrong conclusion was reached: By 10:01:24 finality was tracking one block
per slot and no rejection was recorded, so the node appears to have accepted a ticket, held it
with the full 2 s lead, authored a block in a slot that accepts tickets, and left it out. The
check's guards are sound: it demands only tickets delivered at least `TICKET_ARRIVAL_LEAD_MS`
before the slot began, targeting the epoch that slot submits into, outside the tail, and not
already on chain. What it did not guard was the probe: a ticket the harness sends precisely so
the node will reject it. **Closed.**

Note that `n2_inclusion_covers_valid` passed in the same run. The two lanes judge different
blocks — L2 takes the newest block in the submission epoch, L1 grades every block — so L1's
per-block rule is the stricter of the two.

#### Reading these over several runs

**A single run can miss a real defect, and can invent one.** Grade a client over several runs,
read the soft "not exercised" rows as coverage gaps rather than passes, and check a hard failure
against the node's own log before reporting it: two of the four above look like protocol
violations and are not.

### A caution about "green"

Every check in these lanes once passed while measuring nothing. The ticket lanes in particular
had never tested a node: every emulated ticket was rejected, and the checks that should have
caught it were written so they could not fail. Two unit tests asserted the defective behaviour
and so pinned it in place. The current lanes were audited for that defect class and six distinct
instances were fixed. Treat any future all-green run as a claim to be checked rather than a
result — confirm the checks were *exercised*, not merely *not failed*.

---

## 4. What is not covered yet

Six of the seven designed lanes are implemented and one is parked, so what follows is a
list of real gaps rather than of unstarted work.

- **Protocols asserted:** UP 0, CE 128, CE 129, CE 131, CE 132, CE 133, CE 134, CE 135,
  CE 137–141, CE 142, CE 143, CE 146, CE 148. **Not asserted: CE 136, CE 144, CE 145, CE 147**
  — the auditing and disputes protocols, which belong to the parked N5 lane. CE 136 and
  CE 147 have codecs and no lane driving them.
- **Self-testing is built and used throughout.** M2-B's criterion is *transport and clock
  injectable, QUIC behaviour unchanged*, and all three pieces are built: `jamnp_s::transport`
  with a QUIC carrier and an in-process mock, `jamnp_s::clock` with the machine's clock and a
  virtual one, and `m2-sim`, a node-shaped stand-in that can be broken one named way at a time
  (DESIGN §3). **No crate above `jamnp-s` depends on `quinn`**, so that half is enforced by the
  build.

  **§4.1 and §4.2 below are stale and have not been re-derived.** They were written when N0,
  N1 and N2 were the only lanes and they count 65 rows, of which 38 were then proven. That
  arithmetic no longer describes anything: four more lanes have landed, each with its own
  fault file. Rather than invent a new total, the current state is the per-lane files
  themselves — `crates/m2-sim/tests/`, 17 of them, 24 tests, 76 named faults. The two
  sections are kept for the method they describe and the ten rows they rule out of scope,
  not for their totals.
- **Negative testing now exists in every implemented lane.** 75 named `SimFault` variants
  and 24 integration tests, one file per lane, each showing a row passing against an honest
  stand-in and failing against one broken in exactly that way. The exception is N7's two
  restart rows and its liveness row, which cannot be covered this way: `m2-sim` runs in the
  test process, so there is no process to kill and no stand-in that can pose "came back but
  will not serve" (`findings.md` §36). These are three of the six N7 rows that exist, and
  not the three that DESIGN §11 N7 marks blocked.

- **One real node has been graded, and the bar it clears is the harness's own.** Several
  rows assert deliberately less than DESIGN's wording reads like, each recorded where it is
  made: N2's proxy membership is unobservable with this topology, N7's containment rows are
  soft because the NP defines what a stream reset *means* but never requires one over a
  connection close (§34), and the preimage lane's precondition is on chain rather than on
  the wire.
- **Still only polkajam.** The suite has never been pointed at a second implementation,
  which is the one thing that would test whether these rows encode the spec or encode
  polkajam. §5 documents how to do it.

### 4.1 Re-estimating the transport and clock work

> **Stale, 2026-11-24.** The work it estimates is done; kept for the record of what it cost.

*Measured 2026-11-09, on `main` at `b6a9f79`.* The delivery plan put this at "only 10 call
sites". That number was an undercount, but the more useful correction is that it measures
the wrong thing: the call sites are the refactor, and the refactor is not the deliverable.

**The refactor is bounded, and smaller than it looks.** `quinn` appears at **33 sites above
`jamnp-s`** — 30 in `m2-emu` (20 of them in `emu.rs`, 6 in `sync_probe.rs`, 2 each in
`ticket_io.rs` and `nut_block.rs`) and 3 in `m2-runner/src/connectivity.rs` — not all in
`m2-emu`, as earlier revisions of this section said. The surface those sites use is narrow:
`Connection`, `SendStream`, `RecvStream`, and six methods — `open_bi`, `accept_bi`,
`write_all`, `finish`, `stop`/`reset` — plus five raw read loops. Framing is already
byte-level and transport-agnostic (`FrameReader` takes `&[u8]`), so none of the codec layer
moves. One semantic has to survive the abstraction and is easy to lose in one: **a stream
reset must stay distinguishable from any other read error**, because `quinn::ReadError::Reset`
is how the harness sees a node refuse a ticket, and two N2 checks are built on it.

**The clock is smaller still, and buys less than it appears to.** There are **22 direct
`sleep`/`SystemTime::now`/`Instant::now` sites** above `jamnp-s` (17 in `m2-runner`, 3 in
`m2-emu`, 2 in `m2-reference`), up from 18 before the N2 work — the coupling grows with each
lane. Only about eight are protocol timing that a virtual clock must own: the wall-clock to
slot mapping in `m2-reference/src/chain.rs`, the genesis alignment in `run.rs`, the sender's
slot-target sleep in `ticket_io.rs`, the initiator grace, the probe delay and the observe
window. The rest are process orchestration — waiting for a node process to come up, naming a
session directory — and stay on the real clock. Note also that against a **real** node the
virtual clock cannot make a run faster: the node's slots take six real seconds whatever the
harness believes. Sub-second deterministic runs are a property of runs where the node under
test is itself simulated, which is exactly the self-test case M2-B is about.

**What the call-site count misses.** M2-B's bar is *checks proven by deliberately faulty
simulated clients*, and a simulated client here is a **node in the NUT slot** — it has to
connect, answer CE 128/129, author blocks, run the ticket lottery and respond to CE 131/132,
or the lanes have nothing to grade. That is new code of roughly lane scale, reusing
`m2-reference` and much of what `m2-emu` already does, plus one deliberately-broken variant
for each harness defect class the suite wants to prove it catches. None of it is in the 33
or the 22.

So: the refactor is the small half and is well-defined; the simulated node is the large half
and has not been scoped at all. Scope that before scheduling either.

**Built since, 2026-11-09.** The refactor half is done, and the estimate above held. The
boundary is `jamnp_s::transport`: `Transport`, `Listener`, `Incoming`, `Connection`,
`SendStream` and `RecvStream`, with `transport::quic` over `quinn` and `transport::mock`
between tasks in one process. All 33 call sites moved; `quinn` is gone from `m2-emu`'s and
`m2-runner`'s manifests, so the count above is now **zero above `jamnp-s`** and cannot drift
back without someone adding the dependency again. The two properties §4.1 flagged as easy to
lose are asserted against *both* carriers by one set of tests
(`crates/jamnp-s/tests/transport_it.rs`): a reset arrives as a reset carrying its code, and
streams are independently numbered. `quinn` is still the only thing that authenticates — the
mock has no TLS, certificate or ALPN — so the N0 rules about those remain gradable only over
QUIC, which is recorded in DESIGN §3 rather than left for a reader to discover.

*QUIC behaviour unchanged*, the other half of the criterion, is verified against a live node
rather than asserted: `sessions/transport-1` (the ported harness) and `sessions/control-1`
(unmodified `main`, same machine, same command) report the **same seven findings and the same
set of exercised checks**. §3's five-run table has the fuller picture, including what varies
between runs of identical code.

**The clock, 2026-11-09.** `jamnp_s::clock` followed, and the count held too: eleven waits
moved onto it — the slot boundary, the epoch wait, the ticket sender's delivery target and its
readiness poll, the node-acceptance budget, the initiator grace in two places, the CE 129 probe
delay, the observation window, and the two slot-clock readings in `m2-reference` — against the
"about eight" estimated. The rest stayed on the machine's clock on purpose: waiting for a node
process to come up or a port to answer is not protocol time, and virtualising it would mean a
run that believes a program started when it has not.

`trace::mono_ts` and `trace::wall_ts` read the installed clock, which is the part that makes it
coherent rather than merely injectable: the lanes compute slots from trace timestamps, so a run
whose waits were virtual and whose timestamps were real would grade frames against a calendar
nothing was keeping. `crates/jamnp-s/tests/clock_it.rs` holds exactly that property — an epoch
of protocol waiting advances the trace's clock by 72 seconds and costs no real time.

The speed is latent, not yet banked: a virtual clock is only virtual on a runtime started
paused, and nothing starts one yet because there is no simulated node to run there. Against a
real node the clock is and must remain the machine's.

**The simulated node, 2026-11-09.** `m2-sim` is the third piece, and the scoping question in
this section is now answered by a working example rather than an estimate. A node-shaped
stand-in that an N0 lane can grade is about 250 lines: accept a connection, answer UP 0 with a
handshake, re-announce what it is told about, serve CE 128 and CE 129 — reusing the reference
chain the harness already holds and `m2-emu`'s own `serve_ce128`/`serve_ce129`, since the point
is to exercise the checks, not to write a second node.

`SimFault` is the part that earns the milestone: one named deviation at a time, each the
smallest change that should cost exactly one row. Five are built — silent on UP 0, a finalized
head that is not genesis, never re-announcing, a descending CE 128 walk, and no CE 128 answer
at all — and each is asserted to make its row **fail and appear**, not merely stop passing. A
row the grading never produced caught nothing; treating its absence as proof would repeat the
defect the lanes' own controls were added to prevent. The test's own negative control was run
by hand: pointing a row at the honest node makes it fail with `must make
nut_reannounces_learned_block fail; it reported Some(Pass)`.

What is left of M2-B is coverage, not mechanism: 27 reachable rows unproven, listed in §4.2.

### 4.2 What each check row's evidence is, and the 27 a node could still be made to fail

> **Stale, 2026-11-24.** Written against N0/N1/N2 only. The enumeration and its totals
> predate N3, N4, N6 and N7; the method and the out-of-scope reasoning still hold.

*Counted 2026-11-09 from `m2-scenario/src/scenarios/{n0,n1,n2}.rs`, excluding test code.* The
lanes report **75 rows**. "Unproven" below means *unproven end to end by a faulty client*,
which is M2-B's bar — not untested. There are three grades of evidence that a row can fail,
and they are not interchangeable:

| evidence | rows | what it establishes |
|---|---|---|
| a lane unit test asserts the row failing | 56 | the **predicate** is right, against a fabricated context |
| the row has failed in a live run | 11 | the predicate *and* the pipeline that fed it, for one shape of failure |
| a faulty simulated client makes it fail | 38 of 65 | predicate and pipeline, for a failure chosen on purpose |

The difference between the first grade and the others is the whole point of M2-B. A unit test
hands the check a context built by hand; it cannot catch a context *builder* that never
produces the faulty shape, and both harness defects of §3 lived exactly there — in how the
harness spoke to the node and what it recorded, not in any predicate.

**The bar, and why it is not 75.** A faulty client can only prove a row that some *node*
behaviour makes fire. Nine of the 75 are not like that:

| row | why no node can cause it |
|---|---|
| `emulated_author_announces` | asserts the *emulator* announced |
| `n2_gen_proof_unjudged`, `n2_self_proxy_proof_unjudged` | the harness holds no ticket context for that epoch |
| `n2_proxy_duty_ticket_delivered` | the harness never put the ticket on the wire |
| `n2_proxy_duty_delivered_in_time` | the harness delivered too late to demand a forward |
| `n2_inclusion_every_ticket_delivered` | the harness withheld planned tickets |
| `n2_unknown_epoch_probed` | the harness scheduled no probe |
| `n2_fault_injected` | the harness injected no fault |
| `n2_self_proxy_none` | `log::check(.., true, Hard)` — a literal `true`, so it cannot fire at all |
| `ce129_len_prefixed_values` | reads `probe.decoded`, which is true exactly when `probe.error` is none — and the row is only reported when it is |

Eight of those belong to the lane unit tests, which already drive most of them by
under-exercising the harness; the last two are defects -- rows that cannot fail are not checks,
by the standard the N0 audit set, and both should be soft and renamed. **So M2-B's reachable
target is 65 rows, and 38 of them are proven.** A control row *is* in scope where a node causes
it — `n2_forward_repeat_control_absent` fires because a node never repeats a forward, and
`n2_inclusion_no_block_in_epoch` because it authored nothing.

**Proven by a faulty client (15).** N0: `up0_kind_byte_0`, `up0_final_is_genesis`,
`nut_reannounces_learned_block`, `ce128_ascending_covers_reference`, `ce128_ascending_ordered`.
N1: `n1_timing_within_slot`. N2: `n2_gen_ce131_observed`, `n2_gen_epoch_target`,
`n2_gen_attempt_in_range`, `n2_gen_proof_verified`, `n2_gen_not_before_epoch_start`,
`n2_gen_proxy_matches_rule`, `n2_gen_one_proxy_per_ticket`, `n2_self_proxy_ce132_all_peers`,
`n2_self_proxy_proof_verified`, `n2_proxy_duty_forwarded`,
`n2_proxy_duty_bad_proof_ignored`, `n2_unknown_epoch_reset_observed`,
`n2_inclusion_covers_valid`, `n2_forward_stops_at_finality`,
`n2_proxy_forward_after_arrival`, `n2_forward_repeat_control_absent`,
`n2_fault_not_forwarded`, `n2_fault_not_included`, `n2_inclusion_sorted_dedup`,
`n2_inclusion_empty_at_tail`. N0 adds `ce128_respects_max`, `ce128_both_halves_fin`,
`ce129_served`, `ce129_keys_sorted`, `ce129_boundary_parent_before_child` and
`ce129_size_cap`. N1 adds `n1_extrinsic_includes_delivered`, `n1_extrinsic_no_repeat`,
`n1_extrinsic_empty_at_tail` and `n1_header_seal_import_ok`. N0 adds
`nut_initiates_where_preferred` and `nut_waits_where_not_preferred`, on a node that decides for
itself which peers to dial.

**Only one of the N1 four is isolated.** Leaving a delivered ticket out of the block fails
`n1_extrinsic_includes_delivered` and nothing else, and the test asserts that the seal, parent,
repeat and tail rows all stay passing. The other three need a rewritten body, which fails the
seal row by construction -- so the test asserts the company rather than claiming an isolation it
does not have. `n1_parent_is_reference_best` also fails under those faults, but as a
*consequence*: the harness cannot adopt a block whose body does not match its header, so the
reference chain stops advancing. That is not a parent defect and it is not counted as proven.

**What is left in N0 is the QUIC half.** Ten rows -- `tls_cert` ×4, `alpn` ×3, `builder` ×3 --
need a node carried over QUIC with a deliberately bad certificate or ALPN, which
`jamnp_s::endpoint` has no way to present; that is a build of its own and it touches the live
grading path. Two more are reachable in principle but not with this setup:
`nut_initiates_within_grace` reads the runner's fallback dial, which the self-test does not
perform, and `endpoint_dialed_exact_addr` needs a node that does not listen where it said it
would.

Two of those needed the check read closely rather than guessed at. `ce128_both_halves_fin` is
not reachable by never finishing: the probe has no timeout, so a node that holds the stream
open produces no probe at all and the row is never reported. The reachable defect is a dirty
close -- FIN in the middle of a frame -- where the complete response still decodes and only the
end of the stream is wrong. And `ce129_boundary_parent_before_child` needs a parent built from
blake2b-256 of the child's 64 bytes with the top bit cleared, that bit being the branch/leaf
discriminator; two arbitrary nodes in the wrong order do not trip it.

The last of those is a *control* row, and it counts: a node that never repeats a forward is
what makes it fire, so it is caused by node behaviour and is now shown to happen. Most of the
coverage rows below are not like that -- they fire when the harness fails to exercise
something, and no node can produce them.

The last one could not have been proven any other way. polkajam sends one CE 132 frame per
ticket per peer and never repeats, so against it the rule holds however it is written and the
row reports itself unexercised -- which is what `sessions/unitB-9` recorded and what this
check was written expecting. The simulated node supplies the behaviour the rule bounds:
`RepeatsForwards` repeats a forward *before* finality, which the rule permits and which the
test asserts passes, and `ReForwardsAfterFinality` forwards again once a block of the node's
own carried the ticket and was announced as final. Both controls are exercised in the same
test, including the one that fires against an honest node
(`crates/m2-sim/tests/n2_finality_sim_it.rs`).

Two things reading the N2 checks closely settled, both of which shape what is left:

- **A bad proof is isolable, but only by corrupting the right bytes.** A ticket's id *is* the
  first 32 bytes of its ring signature, and the id decides the designated proxy, so breaking
  the proof there moves the ticket to another proxy and fails the routing rows too. Flipping a
  byte past the first 32 breaks verification and leaves id, attempt and proxy exactly where they
  were, which is what makes `n2_gen_proof_verified` and `n2_self_proxy_proof_verified` provable
  on their own. The test asserts the routing rows stay passing, so the isolation is held rather
  than assumed.
- **One pair of rows cannot be separated.** `n2_gen_one_proxy_per_ticket` and
  `n2_gen_proxy_matches_rule` both require `peers.len() == 1`, so a ticket sent to two
  validators fails both; the test asserts that explicitly rather than pretending otherwise.
- **`n2_gen_attempt_in_range` *is* isolable, but only with a real signature.** An earlier
  version relabelled an honest ticket with an over-cap attempt, which also broke its proof and
  its count. `RefChain::generate_ticket_at` signs at the cap attempt instead, so the proof and
  per-epoch-count rows keep passing and the test asserts that. `n2_gen_within_attempts_per_epoch`
  remains unproven: it counts *distinct* tickets, so exceeding the cap needs a fifth valid
  ticket, which fails the attempt-range row in the same breath.

The N1 one is the first row proven on a block the simulated node *authored*
(`crates/m2-sim/tests/n1_sim_it.rs`). The node keeps its own reference chain -- one that holds
its key rather than treating it as the absent validator -- imports what the emulated validators
produce, and authors its own slot on top; the harness then learns of the block the only way it
can, an announcement over UP 0 followed by a fetch by hash over CE 128. The facts are assembled
by `m2_runner::real::build_n1_ctx`, the function a live run uses, which is the point: the lane's
unit tests already prove the predicates, and the step that has twice gone wrong here is the one
in between.

`SimFault::AnnouncesLate` holds the block byte-for-byte and announces it two slots late, so the
timing row fails while the parent, seal and state-root rows are asserted to stay passing. That
discipline is what the N1 faults will keep running into: most deviations worth testing -- a
forged parent, a stale state root -- break the seal as well, so several rows fail at once and
the verdict stops saying which check caught what. Faults that leave the block intact are the
ones that isolate a row, and there are not many of them.

**No evidence of any kind (14).** These have never been seen to fail, in a test or in a run:
`tls_cert_ed25519_sig_alg`, `tls_cert_key_matches_onchain`, `alpn_offered_when_initiating`,
`endpoint_dialed_exact_addr`, `emulated_author_announces`, `ce128_respects_max`,
`ce128_both_halves_fin`, `ce129_served`, `ce129_len_prefixed_values`, `no_nut_blocks_observed`,
`n2_gen_ce131_observed`, `n2_self_proxy_none`, `n2_self_proxy_proof_verified`,
`n2_self_proxy_proof_unjudged`.

One of those cannot fail at all: `n2_self_proxy_none` is `log::check("n2_self_proxy_none",
true, Severity::Hard)` — a literal `true`. It marks "this run self-proxied nothing", which is
ordinary, but it reports as a **hard pass**, which claims a guarantee the harness never made.
By the standard the N0 audit set, that is not a check; it should be soft and named for what it
is. Open.

*Caveat on the 56:* counted by a row name appearing within 300 characters of a failure
assertion in the same test module, so it is an upper bound — a test asserting one row may
mention another nearby. The N2 figure was cross-checked by a second, stricter method and
agreed.

**N0 — 22 unproven of 27.**

| check | rows | what proving them needs |
|---|---|---|
| `tls_cert` | `tls_cert_ed25519_sig_alg`, `tls_cert_key_matches_onchain`, `tls_cert_single_san_e_base32`, `tls_cert_connection_established` | a **QUIC-carried** sim node with a bad certificate — the mock has no TLS, so these cannot be reached on it at all |
| `alpn` | `alpn_version1_accepted`, `alpn_offered_when_initiating`, `alpn_wrong_version_rejected` | a QUIC-carried sim node that negotiates ALPN wrongly |
| `builder_slots` | `builder_slots_ge_20`, `alpn_builder_suffix_accepted`, `ce133_accepted_on_builder` | a QUIC-carried sim node that refuses builder connections |
| `preferred_initiator` | `nut_initiates_where_preferred`, `nut_waits_where_not_preferred`, `nut_initiates_within_grace` | a sim node that **dials**, or refuses to; today it only listens |
| `endpoint_decoding` | `endpoint_dialed_exact_addr` | a sim node that dials the wrong address |
| `up0_announce` | `emulated_author_announces` | nothing a node does: it asserts the *emulator* announced, so only a broken harness could fail it |
| `ce128_serve` | `ce128_respects_max`, `ce128_both_halves_fin` | reachable today — a `SimFault` that over-serves `max_blocks`, and one that leaves a half open |
| `ce129_serve` | `ce129_served`, `ce129_keys_sorted`, `ce129_boundary_parent_before_child`, `ce129_size_cap`, `ce129_len_prefixed_values` | reachable today, but the stand-in serves an *empty* state, so each needs it to serve a populated one first |

**N1 — 12 unproven of 13** (`n1_timing_within_slot` is proven). `n1_parent_is_reference_best`,
`n1_parent_is_known`, `n1_parent_no_equivocation`; `n1_header_seal_import_ok`;
`n1_state_root_prior_matches`, `n1_state_root_posterior_matches`;
`n1_extrinsic_includes_delivered`, `n1_extrinsic_no_undelivered`, `n1_extrinsic_no_repeat`,
`n1_extrinsic_empty_at_tail`; `n1_skipped_slots_valid_parent`, `no_nut_blocks_observed`.

The authoring stand-in they were waiting on now exists, so these are no longer blocked on
mechanism — they are blocked on **faults that do not break the seal**. Authoring on the wrong
parent or with a doctored state root changes the header, and the header is signed, so
`n1_header_seal_import_ok` fails alongside whatever was meant to be tested. Reaching them needs
either a way to author a *validly sealed* block that is nonetheless wrong — which the reference
engine can do for the parent case, by authoring on an older head — or acceptance that some rows
can only be shown to fail in company.

**N2 — 15 unproven of 35.** Twenty are proven. Nine on the generation side
(`crates/m2-sim/tests/n2_sim_it.rs`): the simulated node runs a real Safrole lottery -- ring
signatures over its own key, from its own chain's entropy -- and distributes what it wins, CE
131 to the proxy its id names and CE 132 to everyone for the ones it proxies itself. The facts
come from `m2_runner::real::collect_nut_tickets`, the harness's own trace-to-facts step, which
is the one that has actually failed: the CE 131 decoder defect closed on 2026-10-30 made the
node's whole ticket output invisible and every check above it read the silence as a node that
had sent nothing.

The node is validator **2** in that test, and the choice is load-bearing rather than tidy. A
ticket's proxy follows from its id, so the entropy decides which rules a run exercises: at the
test's clock anchor, validator 2 proxies two of its four tickets itself and sends the other two
on, and it is the only index of the six that exercises the CE 131 path and the CE 132 broadcast
in one run. As validator 0 -- the first configuration tried -- all four tickets go to other
validators and `n2_self_proxy_ce132_all_peers` is never produced, so the fault for it could not
have been proven. That is the same not-exercised trap the lane's own controls guard against,
met from the other side.

Still unproven (15): `n2_gen_proof_unjudged`, `n2_gen_within_attempts_per_epoch`,
`n2_self_proxy_none`, `n2_self_proxy_proof_unjudged`, `n2_proxy_duty_ticket_delivered`,
`n2_proxy_duty_delivered_in_time`, `n2_forward_finality_control_absent`,
`n2_inclusion_every_ticket_delivered`, `n2_inclusion_no_block_in_epoch`,
`n2_inclusion_control_absent`, `n2_inclusion_no_extra`, `n2_unknown_epoch_probed`,
`n2_fault_injected`, `n2_fault_forward_control_absent`, `n2_fault_inclusion_control_absent`.
Fourteen of those fifteen fire when the *harness* did not exercise something, so no node can
produce them; `n2_inclusion_no_extra` is the one that wants a fault nobody has found yet.

The receiving half exists too (`crates/m2-sim/tests/n2_proxy_sim_it.rs`): the harness delivers
tickets to the node, the node refuses what it cannot act on by resetting the stream -- a forged
proof, or an epoch past its horizon -- and forwards what it is proxy for over CE 132. Three more
rows are proven there, each with its negative control run by hand.

Four things that cost real debugging and are worth not rediscovering:

- **A node must serve streams on connections it dialled**, not only on ones dialled to it. The
  emulator's ticket sender uses whichever connection it has, so a stand-in that only served
  inbound connections silently ignored every ticket proxied to it, and `n2_proxy_duty_forwarded`
  failed for a reason that had nothing to do with forwarding.
- **The node's chain must not drift from the harness's.** A block of its own the harness never
  imported moves its entropy, and the harness's ring proofs then fail to verify against the
  node's context -- so it refuses every honest ticket, and the bad-proof row passes for the
  wrong reason.
- **A block has to be announced, not just authored.** The harness learns what the node considers
  final only from the node's re-announcement, and the ticket sender gates on it; authoring
  without broadcasting leaves the gate shut and every delivery withheld.
- **A deliberately stale ticket has to be marked as a fault** or the sender withholds it, since
  sending a stale ticket would manufacture a refusal the node was right to make.

**Inclusion is built too** (`crates/m2-sim/tests/n2_inclusion_sim_it.rs`): the node pools what
it is sent through a new `RefChain::submit_tickets` passthrough, and the blocks it authors carry
three tickets each. `n2_inclusion_covers_valid` is proven -- the honest node carries what it was
sent, `OmitsDeliveredTickets` carries nothing -- and the honest and faulty paths are one line
apart, both sealing validly, which is the isolation N1's faults could not get.

Getting there needed three corrections that are worth not repeating:

- **A node's chain must hold only its own keys.** `RefChain::tiny(k)` holds every key *but*
  `k`, and an authoring harness runs the Safrole lottery for every key in its keystore -- so a
  node simulated on such a chain authors blocks carrying five validators' tickets and looks, to
  the lane, like one inventing tickets nobody sent. `RefChain::tiny_for(index)` is the
  complement, and is what a node holds.
- **A ticket for any epoch but the next one must be refused**, not merely one past the horizon.
  polkajam refuses both -- its log says `bad ticket epoch value` -- and a node that pooled a
  stale ticket put in its block something the harness never owed it.
- **A peer's plan is taken once.** `set_ticket_plans` called a second time is never sent,
  because the first connection to a peer takes its plan and the sender runs once. The first
  version of the test re-planned every epoch and graded an epoch whose tickets had gone out an
  epoch earlier.

**`n2_inclusion_no_extra` was recorded as unprovable here. That was wrong**, and the correction
is worth more than the claim was. The blame fell on the authoring engine pooling its own lottery
tickets; the real cause was the simulated node pooling tickets it should have refused -- one
misrouted to it over CE 131, and one over the per-validator attempt cap. Both are rules DESIGN
§11 N2 states and the node did not implement. With them in, the honest node passes the row.

No fault makes it fail yet: the node's blocks carry only what it was sent, so planting an
unaccounted id means getting one into the authoring pool that the harness has no record of, and
withholding one of the node's own winnings does not do it -- the engine does not pool them.

**`n2_inclusion_sorted_dedup` and `n2_inclusion_empty_at_tail` are proven, but only in
company.** The authoring engine cannot be made to break either: its pool rejects duplicates and
orders by id, and past the tail its provisioner offers no tickets at all. Reaching them means
rewriting the body of the block the node *serves*, leaving the header -- and so the hash the
harness fetches by -- untouched, which is the technique `m2-reference`'s own import test uses.
The body then disagrees with the header's extrinsic hash, so `n1_header_seal_import_ok` fails
with them. The test grades N1's seal row on the same blocks and asserts exactly that, rather
than claiming an isolation it does not have.

**A caveat on what "proving" a row means here.** Thirteen of the 70 are *not* assertions about
the node: they report that a run did not exercise something (`n2_fault_injected`,
`n2_inclusion_control_absent`, `n2_forward_*_control_absent`, `n2_self_proxy_none`,
`no_nut_blocks_observed`, `n2_proxy_duty_delivered_in_time` and the `_unjudged` pair among
them). Making one of those fire means under-exercising the *harness*, not breaking the node,
and several already have unit tests in their own lane doing exactly that. They are counted here
because they appear in the report as rows, but a faulty client is the wrong instrument for
them.

---

## 5. Running the suite against a third-party node

### 5.1 Topology

Every run uses the same fixed topology: six tiny-spec validators (`V=6`, `C=2`, `E=12`,
`ticket_submission_end=10`, 6 s slots). Five are emulated by the harness; one is the node under
test. The harness speaks its own independent JAMNP-S implementation — not any node's networking
stack — and grades what the NUT emits against polkajam's `hazmat` engine as reference oracle.

By default the NUT takes **validator index 5** and listens on `base_port + 5` (`40005`); the five
emulated validators occupy `40000`–`40004`. Index 5 rather than 0 is deliberate: at index 0 with
trivial keys the preferred-initiator rule is degenerate — the NUT is never the preferred
initiator, so the NUT-initiated N0 checks can never fire.

### 5.2 What the harness hands the node

Written into `<session-dir>` before launch:

| File | Contents |
|---|---|
| `spec-m2.json` | the M2-standard spec: `parameters`, `genesis_header`, `genesis_state` (21 key/values), `bootnodes` |
| `spec.json` | the same chain in polkajam's native spec format |
| `nut_ed25519.hex`, `nut_bandersnatch.hex` | the NUT's 32-byte secrets, hex |

`genesis_header` plus `genesis_state` key/values is the same shape every M1 target already parses
from fuzz-proto `Initialize`. Validator metadata is `PeerAddr { ip: [u8;16], port: u16 LE }` first
(18 bytes, as in jam-np), then the P-256 id, then filler. IPv4 loopback is written IPv4-mapped
(`::ffff:127.0.0.1`).

Secrets are handed over explicitly rather than as a single seed, so no team is forced onto one
derivation scheme.

### 5.3 The environment contract

The `docker` preset launches the node with host networking — QUIC is UDP, and the node must be
able to *initiate* connections under the preferred-initiator rule — and passes:

| Variable | Meaning |
|---|---|
| `JAM_M2=1` | enable M2 conformance mode |
| `JAM_M2_SPEC` | path to the spec file |
| `JAM_M2_ED25519_SECRET` | hex, 32 bytes |
| `JAM_M2_BANDERSNATCH_SECRET` | hex, 32 bytes |
| `JAM_M2_LISTEN` | `[::]:<port>` |
| `JAM_M2_PUBLIC_ADDR` | `<ipv6>:<port>` as carried in genesis metadata |
| `JAM_M2_DATA_PATH` | writable state directory |
| `JAM_M2_LOG_LEVEL` | log level |

The image is taken from the `JAM_M2_IMAGE` environment variable of the *runner* process
(default `polkajam`).

### 5.4 Running it

```sh
# 1. Build the harness.
cargo build --workspace

# 2. Sanity-check the harness against its own expectations (no node, no network).
cargo run -p m2-runner -- --preset mock --dry-run --session-dir /tmp/m2-dry
#    Expect exit 0 and every check HARD PASS.

# 3. Grade a third-party node image.
JAM_M2_IMAGE=ghcr.io/<team>/<client>:<tag> \
cargo run -p m2-runner -- \
  --preset docker \
  --seed 1 \
  --validator-index 5 \
  --base-port 40000 \
  --session-dir sessions/<team>-01 \
  --startup-timeout 60 \
  --observe-secs 90
```

For a node that runs as a local binary rather than an image, the `polkajam` preset is a worked
example of a command-template launch; the template placeholders are `{spec}`,
`{ed25519_secret}`, `{bandersnatch_secret}`, `{listen}`, `{public_addr}`, `{data}`,
`{log_level}`.

Use `--observe-secs 90` or more. The window must span enough slots for the node to win some and
for a ticket submission window to open; shorter runs leave rules unexercised and report soft
"not exercised" rows rather than verdicts.

### 5.5 Exit codes and output

| Code | Meaning |
|---|---|
| 0 | every hard check passed, no startup failure |
| 1 | a hard check failed, or the NUT did not come up in time |
| 2 | internal harness error |

Output lands in `<session-dir>`:

```
report/report.md        human-readable coverage table and findings
report/findings.json    machine-readable findings
traces/jamnp.bin        full wire trace
traces/jamnp.json       decoded trace
traces/{tx,rx}/         per-message frames
logs/nut.{stdout,stderr}.log
```

Every finding cites `traces/jamnp.bin` as evidence, so a disputed verdict can be re-derived from
the wire.

### 5.6 What the node must implement, in the order the run exercises it

A node that fails an early stage produces a run that cannot reach the later ones, so read the
report top-down.

1. **QUIC + TLS 1.3, mutual auth.** Ed25519 self-signed certificate, exactly one SAN carrying
   the 53-character peer id (`e` + base32 of the Ed25519 public key), key matching the one in
   genesis.
2. **ALPN.** Offer and accept `jamnp-s/1/<first 8 hex of genesis header hash>`, accept the
   `/builder` suffix, and **refuse** a mismatched version.
3. **Preferred-initiator rule.** Initiate where preferred, wait where not, and initiate within
   the grace period.
4. **Builder slots.** Accept at least 20 `/builder` connections and serve CE 133 on them.
5. **UP 0.** Kind byte 0; handshake announcing genesis as Final; announce blocks it authors;
   re-announce blocks it learns.
6. **CE 128 / CE 129.** Serve block requests ascending and ordered, respect the maximum, FIN
   both halves; serve state requests with sorted keys, a size cap, and length-prefixed values.
7. **Authoring (N1).** Author in its own slots with the correct parent, a valid seal, and
   correct prior and posterior state roots; carry the tickets it has been delivered.
8. **Safrole tickets (N2).** Run the lottery, send over CE 131 to its proxy and CE 132 to every
   validator, respect target epoch, attempt range and the per-epoch cap, and reset the stream on
   a ticket for an unknown epoch. Forward a ticket you are proxy for to all five, after it
   arrives and inside the lottery. Expect deliberately broken tickets as well as honest ones: a
   bad proof, a ticket naming you as proxy when the rule names someone else, a stale epoch, one
   past slot 10, and a duplicate. None of those may be forwarded or reach a block — except the
   duplicate, which the block still owes a place, once.

A node that implements only part of this still gets a useful report: checks that could not be
exercised are reported as soft "not exercised" rows, distinct from failures.

### 5.7 Known gaps that affect third-party runs

These are limitations of the harness as it stands, not of any node. They should be closed before
the suite is offered to other teams. The struck-through rows are closed; they are kept because
each one produced false failures against polkajam, and a client that behaves the same way would
have been failed for it.

| Gap | Impact | Fix |
|---|---|---|
| ~~**Ticket delivery begins before the node has finalized the seeded chain**~~ | **closed 2026-10-29** — the sender now holds each ticket until the node's advertised finalized head is in the current epoch, and withholds one it cannot accept in time. See §3.1 | — |
| ~~**CE 131 deliveries are scheduled into the submission window, not the forwarding one**~~ | **closed 2026-10-30** — the plan is laid out only once the node can accept tickets, and a lottery with no forwardable slot left is traded for the next one. See §3.2 | — |
| ~~**The proxy-forward rule does not model batching or pruning**~~ | **closed 2026-10-30, as not-a-defect** — the node had forwarded every ticket; the harness's decoder was dropping the frames. The batch split fitted the symptom by coincidence. See §3.2 | — |
| ~~`JAM_M2_SPEC` receives `spec.json` (polkajam's native format), not `spec-m2.json`~~ | **closed 2026-10-30** — `LaunchConfig` carries both paths behind a `{spec}` and a `{m2_spec}` placeholder, and the docker preset passes the M2 one | — |
| ~~`--lanes` is parsed but never consumed~~ | **closed 2026-10-30** — parsed into a `LaneSet` (an unknown lane name is refused rather than ignored) and consumed by `evaluate`. A lane left out is neither graded nor exercised: `--lanes n0` skips ticket proving entirely | — |
| ~~`spec-m2.json` declares three ticket attempts per validator; the run uses four~~ | **closed 2026-11-02** — a third-party node configured from the §7 environment contract would have made three attempts an epoch and been graded against four, and the fourth attempt of every emulated author would have looked to it like a ticket over the cap. polkajam never saw it: it reads its own `spec.json`. The nine named parameters are now derived from `jam_types` rather than hand-written literals, so the contract cannot drift from the run | — |
| No capability handshake | the report cannot distinguish *not attempted* from *not exercised* | declared-lane negotiation, per the delivery plan's rollout section |
| The `docker` preset has never been exercised live | only its command string is under test; the polkajam preset is the only path with live evidence | run it against a real image before onboarding anyone |
| The oracle is polkajam | a genuine state-transition disagreement between a third-party node and polkajam surfaces as an N1 state-root failure | expected; M1 state-transition conformance is `davxy/jam-conformance`'s job, and a client should be M1-green before attempting M2 |

---

## 6. Reproducing these results

```sh
# Build the node under test and the oracle from the pinned revision.
./scripts/prepare-nut.sh

# Harness checks.
cargo test --workspace            # 592 passed / 0 failed
cargo fmt --all -- --check
cargo clippy --workspace --all-targets

# The oracle is a separate tree, so none of the above reaches it.
(cd oracle && cargo test && cargo fmt --check)

# Dry-run baseline: exit 0.
cargo run -p m2-runner -- --preset mock --dry-run --session-dir /tmp/m2-dry

# Live surface: exit 1. Two node defects remain (§3); every harness-induced
# failure was closed on 2026-10-29 (§3.1) and 2026-10-30 (§3.2).
PATH="$PWD/third_party/bin:$PATH" \
cargo run -p m2-runner -- --seed 1 --validator-index 5 --base-port 40000 \
  --preset polkajam --session-dir sessions/m0-verify \
  --startup-timeout 60 --observe-secs 90
```

The polkajam revision is pinned in `oracle/Cargo.toml` and read from there by
`scripts/prepare-nut.sh`, which also checks it against the workspace's pin, so the node
under test and the engine that grades it are the same build.

---

## References

- `DESIGN.md` — design contract; §7 environment contract, §11 check catalogue, §13 roadmap
- `M2 Conformance - Delivery Plan.md` — milestone ladder keyed to JAMNP-S coverage
- `README.md` — build, run, and current implementation state
- JAMNP-S: https://github.com/zdave-parity/jam-np (`simple.md`)
- M1 conformance: https://github.com/davxy/jam-conformance
