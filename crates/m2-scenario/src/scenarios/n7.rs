//! N7 — adversarial and robustness (DESIGN.md §11).
//!
//! Every other lane sends the node things it should accept and grades the
//! answer. This one sends it things no conforming peer would send, and grades
//! what survives. The provocations are deliberate and named, which is the
//! difference between this lane and `n0::connection_close`: that row reports
//! connection closes that happened to occur during a run, so what provoked
//! them is inferred afterwards from the node's own close message. Here the
//! harness knows exactly what it sent and when.
//!
//! **What the spec actually requires, which is less than it looks.**
//! `simple.md:116-120` says what a reset *means* — "resetting/stopping of a
//! stream by the stream acceptor should be considered rejection of the
//! request or failure to process the request" — but nowhere obliges a node to
//! reject that way rather than by closing the connection. The one
//! circumstance the spec names for closing a connection is a missing or bad
//! certificate (`:20`), and it says nothing at all about unknown stream
//! kinds: a search of the document for "unknown", "unsupported" and
//! "unrecognised" returns nothing in the protocol sections.
//!
//! So DESIGN §11 N7's table, which marks "reset stream, connection stays up"
//! as a hard expectation, asks for more than the NP gives. Grading it hard
//! would fail a node on a rule nobody wrote — the mistake `findings.md` §18
//! and §27 record, and the reason `n0::connection_close` is already Soft with
//! that rationale written out. This lane keeps N0's reading: **how** a node
//! rejects is soft, and reported in the node's own words.
//!
//! One row here is hard, and needs no spec text to justify it: after being
//! sent a malformed stream the node must still be running and still serving.
//! A node that dies is a defect under any reading.

use crate::dsl::{check, log, Check, Control, Severity};

/// The peer index N7's provocations are recorded under.
///
/// Outside the validator range, like `n6::ORDINARY_PEER` (`0x6E`) and
/// `n0::BUILDER_PEER` (`0xB0`), so a row naming it cannot be mistaken for a
/// validator that exists — the confusion `findings.md` §8 records.
pub const PROVOKER_PEER: u16 = 0x4E;

/// What a kill-and-restart of the node under test produced.
///
/// DESIGN §11 N7: "Kill and restart NUT mid-epoch | re-syncs via CE 128/129;
/// authors again in its next slot."
#[derive(Debug, Clone)]
pub struct RestartFacts {
    pub killed_at_wall_ms: u64,
    pub restarted_at_wall_ms: u64,
    /// Whether the node answered an ordinary CE 128 request after coming
    /// back. `None` where the run never got to ask.
    pub served_again: Option<bool>,
    /// Slots the node authored a block in *after* the restart.
    pub authored_after: Vec<u32>,
    /// The first slot it was the scheduled author for after the restart, if
    /// the run could work one out.
    ///
    /// Without this the authoring row has no subject: "it authored again"
    /// is only meaningful against a slot it owed a block in.
    pub first_due_slot: Option<u32>,
}

/// What the harness sent to provoke the node, and what came back.
#[derive(Debug, Clone)]
pub struct Provocation {
    /// Which peer connection it was sent on.
    pub peer: u16,
    /// What was sent, for the row's detail text.
    pub fault: Fault,
    /// How the node's side of that stream ended.
    pub outcome: StreamOutcome,
    /// Whether the connection the provocation was sent on was still usable
    /// afterwards, measured by making an ordinary CE 128 request on it and
    /// getting an answer.
    ///
    /// `None` where the run did not get as far as asking, which is not the
    /// same as `Some(false)` and must not be graded as one.
    pub connection_reusable: Option<bool>,
    pub at_wall_ms: u64,
}

/// The malformed thing the harness sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// A stream opened with a kind byte the NP does not assign. 130 and 200
    /// are both unassigned at `aa0e2b8`: CE kinds run 128..=148 with gaps,
    /// and 130 sits in one of them.
    UnknownKind(u8),
    /// A valid kind, then a message whose u32 length prefix claims more bytes
    /// than are sent before FIN (`simple.md:128-131`).
    TruncatedMessage { kind: u8, claimed: u32, sent: u32 },
    /// A valid kind and a complete, well-formed message, followed by bytes
    /// that are not a message.
    TrailingBytes { kind: u8, extra: usize },
    /// A valid kind byte and then nothing: the stream is held open, never
    /// finished, and no message is ever sent.
    ///
    /// The protocol is in force from the kind byte on (`simple.md:122-124`),
    /// so the node is waiting for a message that will not come. A node that
    /// waits forever keeps a stream — and whatever it allocated for it — for
    /// as long as the peer cares to hold the connection, which is the point
    /// of the fault.
    SlowLoris { kind: u8, silence_ms: u64 },
}

impl Fault {
    /// How the row names it.
    pub fn describe(&self) -> String {
        match self {
            Fault::UnknownKind(k) => format!("a stream opened with unassigned kind {k}"),
            Fault::TruncatedMessage {
                kind,
                claimed,
                sent,
            } => format!(
                "a CE {kind} message whose length prefix claims {claimed} bytes with {sent} sent"
            ),
            Fault::TrailingBytes { kind, extra } => {
                format!("a well-formed CE {kind} message followed by {extra} junk bytes")
            }
            Fault::SlowLoris { kind, silence_ms } => format!(
                "a CE {kind} stream opened and then held silent for {} s",
                silence_ms / 1000
            ),
        }
    }
}

/// How the node's half of the provoked stream ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamOutcome {
    /// The node reset or stopped the stream. This is the NP's way of saying
    /// "rejected" (`simple.md:116-120`).
    Reset,
    /// The node closed the stream cleanly without answering.
    FinishedSilently,
    /// The node answered. Worth recording rather than assuming impossible:
    /// an answer to a malformed request is itself a finding.
    Answered { bytes: usize },
    /// The node closed the whole QUIC connection, with what it said.
    ConnectionClosed { code: u64, reason: String },
    /// Nothing happened before the harness gave up waiting.
    TimedOut { after_ms: u64 },
}

impl StreamOutcome {
    /// Whether the node disposed of the stream without taking anything else
    /// down with it. A silent FIN counts: it is not the NP's stated rejection
    /// signal, but it rejects the request and costs the connection nothing.
    pub fn is_contained(&self) -> bool {
        matches!(
            self,
            StreamOutcome::Reset | StreamOutcome::FinishedSilently | StreamOutcome::Answered { .. }
        )
    }

    /// How the row says it.
    pub fn describe(&self) -> String {
        match self {
            StreamOutcome::Reset => "reset the stream".to_string(),
            StreamOutcome::FinishedSilently => "closed the stream without answering".to_string(),
            StreamOutcome::Answered { bytes } => format!("answered it with {bytes} bytes"),
            StreamOutcome::ConnectionClosed { code, reason } => {
                format!("closed the whole connection with \"{reason}\" (code {code})")
            }
            StreamOutcome::TimedOut { after_ms } => {
                format!("did nothing for {after_ms} ms")
            }
        }
    }
}

/// Everything N7's rows read.
#[derive(Debug, Clone)]
pub struct N7Ctx {
    /// Each provocation the run sent, in the order it sent them.
    pub provocations: Vec<Provocation>,
    /// Whether the node was still reachable at the end of the run: a fresh
    /// connection was made and an ordinary CE 128 request answered on it.
    ///
    /// `None` where the run never tried, which reports as unexercised rather
    /// than as a dead node.
    pub alive_after: Option<bool>,
    /// The kill-and-restart, where the run did one. `None` otherwise, and
    /// the rows report themselves unexercised rather than passing.
    pub restart: Option<RestartFacts>,
}

/// The control every row here depends on: a provocation actually went out.
fn sent_control(ctx: &N7Ctx) -> Control {
    Control::new(
        "n7_not_exercised",
        "a malformed stream sent to the node",
        !ctx.provocations.is_empty(),
    )
}

/// Did the node dispose of a malformed stream without taking the connection
/// with it?
///
/// **Soft.** The NP does not require a reset over a connection close; see the
/// module note. The row reports what the node did, per provocation, in the
/// node's own words where it gave any.
pub fn malformed_stream_contained(ctx: &N7Ctx) -> Check {
    let provocations = ctx.provocations.clone();
    let control = sent_control(ctx);
    check("n7_containment", Severity::Soft, move |_obs| {
        if !control.present() {
            return vec![control.absent("n7_malformed_stream_contained")];
        }
        provocations
            .iter()
            .map(|p| {
                log::check_detail(
                    "n7_malformed_stream_contained",
                    p.outcome.is_contained(),
                    Severity::Soft,
                    || {
                        format!(
                            "sent {} on {}'s connection at wall {} ms; the node {}",
                            p.fault.describe(),
                            peer_name(p.peer),
                            p.at_wall_ms,
                            p.outcome.describe()
                        )
                    },
                )
            })
            .collect()
    })
}

/// After a malformed stream, does the connection still carry other protocols?
///
/// **Soft**, for the same reason, but this is the row that says what the
/// behaviour costs. A connection carries every protocol the harness has with
/// that validator; closing it to refuse one stream takes block requests,
/// tickets, package sharing and availability down with it, none of which had
/// anything to do with the message that offended.
///
/// Reported only where the run actually tried to reuse the connection.
pub fn connection_reusable(ctx: &N7Ctx) -> Check {
    let provocations = ctx.provocations.clone();
    let control = sent_control(ctx);
    check("n7_reuse", Severity::Soft, move |_obs| {
        if !control.present() {
            return vec![control.absent("n7_connection_reusable")];
        }
        let tried: Vec<&Provocation> = provocations
            .iter()
            .filter(|p| p.connection_reusable.is_some())
            .collect();
        if tried.is_empty() {
            return vec![log::check_detail(
                "n7_connection_reuse_not_attempted",
                false,
                Severity::Soft,
                || {
                    "every provocation went out, but the run never tried the connection \
                     afterwards, so whether it survived is unmeasured"
                        .to_string()
                },
            )];
        }
        tried
            .iter()
            .map(|p| {
                log::check_detail(
                    "n7_connection_reusable",
                    p.connection_reusable == Some(true),
                    Severity::Soft,
                    || {
                        format!(
                            "after {}, an ordinary CE 128 request on {}'s same \
                             connection got no answer; the node {}",
                            p.fault.describe(),
                            peer_name(p.peer),
                            p.outcome.describe()
                        )
                    },
                )
            })
            .collect()
    })
}

/// Is the node still running after everything above?
///
/// **Hard**, and the only hard row in this lane. It needs no spec text: a
/// node that a malformed message takes down is broken under any reading of
/// any document. Measured on a *fresh* connection, so it is liveness of the
/// node and not of the connection the provocations went to — those are
/// different questions and `connection_reusable` asks the other one.
pub fn node_alive_after(ctx: &N7Ctx) -> Check {
    let alive = ctx.alive_after;
    let faults: Vec<String> = ctx
        .provocations
        .iter()
        .map(|p| p.fault.describe())
        .collect();
    let control = sent_control(ctx);
    check("n7_liveness", Severity::Hard, move |_obs| {
        if !control.present() {
            return vec![control.absent("n7_node_alive_after")];
        }
        match alive {
            Some(true) => vec![log::check("n7_node_alive_after", true, Severity::Hard)],
            Some(false) => vec![log::check_detail(
                "n7_node_alive_after",
                false,
                Severity::Hard,
                || {
                    format!(
                        "after {}, a fresh connection to the node could not be made or could \
                         not get an ordinary CE 128 request answered",
                        faults.join(", then ")
                    )
                },
            )],
            None => vec![log::check_detail(
                "n7_liveness_not_measured",
                false,
                Severity::Soft,
                || {
                    "provocations went out but the run never re-checked the node afterwards, \
                     so a crash would have gone unnoticed"
                        .to_string()
                },
            )],
        }
    })
}

/// Did the node come back and serve again after being killed?
///
/// **Hard**, and for the same reason `node_alive_after` is: no spec text is
/// needed to say that a node which cannot be restarted is broken. A node
/// restarted onto the same data directory that then cannot answer a block
/// request has lost something it should have persisted.
///
/// Measured by an ordinary CE 128 request, so a node that is up but not
/// serving counts as not recovered — which is the case worth catching.
pub fn restart_resyncs(ctx: &N7Ctx) -> Check {
    let restart = ctx.restart.clone();
    check("n7_restart", Severity::Hard, move |_obs| {
        let Some(restart) = &restart else {
            return vec![log::check_detail(
                "n7_restart_not_exercised",
                false,
                Severity::Soft,
                || {
                    "the run did not kill and restart the node, so nothing is known about \
                     whether it recovers"
                        .to_string()
                },
            )];
        };
        match restart.served_again {
            Some(true) => vec![log::check("n7_restart_serves_again", true, Severity::Hard)],
            Some(false) => vec![log::check_detail(
                "n7_restart_serves_again",
                false,
                Severity::Hard,
                || {
                    format!(
                        "the node was killed at wall {} ms and restarted at {} ms, and did \
                         not answer an ordinary CE 128 request afterwards",
                        restart.killed_at_wall_ms, restart.restarted_at_wall_ms
                    )
                },
            )],
            None => vec![log::check_detail(
                "n7_restart_recovery_not_measured",
                false,
                Severity::Soft,
                || "the node was restarted but never asked for anything afterwards".to_string(),
            )],
        }
    })
}

/// Did it author again once it was back?
///
/// **Soft.** DESIGN says "authors again in its next slot", and the next slot
/// is a strict bar: a node that has just restarted has to catch up before it
/// can build on the right parent, and missing one slot to do that is a
/// reasonable node rather than a broken one. So the row reports which slot
/// it resumed at and fails only where it never resumed at all.
///
/// Reported only where the run knew of a slot the node owed a block in.
/// Without that there is no claim to make: a node that authored nothing
/// during a window it was never scheduled in has done nothing wrong.
pub fn restart_authors_again(ctx: &N7Ctx) -> Check {
    let restart = ctx.restart.clone();
    check("n7_restart_authoring", Severity::Soft, move |_obs| {
        let Some(restart) = &restart else {
            return Vec::new();
        };
        // Authoring at all is positive evidence and needs no control: a
        // node that produced a block after being killed has resumed, and
        // which slot it was due in does not change that.
        if let Some(resumed) = restart.authored_after.iter().min().copied() {
            return vec![log::check_detail(
                "n7_restart_authors_again",
                true,
                Severity::Soft,
                || format!("resumed at slot {resumed}"),
            )];
        }
        // Silence is the ambiguous case, and the only one needing a
        // control. A node that authored nothing may be broken or may simply
        // not have had a turn -- and this harness cannot always tell, since
        // under Safrole the node's slots come from tickets rather than a
        // stride it can infer. Where it cannot, the row says so instead of
        // failing a node for the harness's ignorance (`findings.md` §5).
        let control = Control::new(
            "n7_restart_authoring_not_exercised",
            "a slot the node was known to be scheduled to author in after the restart",
            restart.first_due_slot.is_some(),
        );
        vec![log::negative(
            "n7_restart_authors_again",
            &control,
            false,
            Severity::Soft,
            || {
                format!(
                    "the node was due to author in slot {} after its restart and authored \
                     nothing through the end of the window",
                    restart.first_due_slot.unwrap_or_default()
                )
            },
        )]
    })
}

/// Name the connection a provocation went out on.
///
/// `PROVOKER_PEER` is `0x4E`, outside the validator range on purpose — so
/// printing it as "validator 78" names a validator that does not exist,
/// which is the confusion `findings.md` §8 records and is exactly what the
/// first run of this lane against the real node printed.
fn peer_name(peer: u16) -> String {
    if peer == PROVOKER_PEER {
        "the provoker".to_string()
    } else {
        format!("validator {peer}")
    }
}

/// Every N7 check, in reporting order.
pub fn all(ctx: &N7Ctx) -> Vec<Check> {
    vec![
        malformed_stream_contained(ctx),
        connection_reusable(ctx),
        node_alive_after(ctx),
        restart_resyncs(ctx),
        restart_authors_again(ctx),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsl::{ObsLog, Outcome};

    fn provocation(outcome: StreamOutcome, reusable: Option<bool>) -> Provocation {
        Provocation {
            // The peer the lane really uses: a fixture on a validator index
            // would have hidden the naming bug this file's own test catches.
            peer: PROVOKER_PEER,
            fault: Fault::UnknownKind(130),
            outcome,
            connection_reusable: reusable,
            at_wall_ms: 1_000,
        }
    }

    fn run(check: Check) -> Vec<(&'static str, Outcome)> {
        let obs = ObsLog::new();
        (check.run)(&obs)
            .into_iter()
            .map(|r| (r.name, r.outcome))
            .collect()
    }

    fn ctx(provocations: Vec<Provocation>, alive_after: Option<bool>) -> N7Ctx {
        N7Ctx {
            provocations,
            alive_after,
            restart: None,
        }
    }

    fn restarted(served_again: Option<bool>, authored_after: Vec<u32>, due: Option<u32>) -> N7Ctx {
        N7Ctx {
            provocations: vec![provocation(StreamOutcome::Reset, Some(true))],
            alive_after: Some(true),
            restart: Some(RestartFacts {
                killed_at_wall_ms: 10_000,
                restarted_at_wall_ms: 12_000,
                served_again,
                authored_after,
                first_due_slot: due,
            }),
        }
    }

    #[test]
    fn a_reset_stream_passes_and_a_connection_close_fails() {
        let reset = ctx(
            vec![provocation(StreamOutcome::Reset, Some(true))],
            Some(true),
        );
        assert_eq!(
            run(malformed_stream_contained(&reset)),
            [("n7_malformed_stream_contained", Outcome::Pass)]
        );

        // The §30 behaviour. Soft, but it must fail rather than pass.
        let closed = ctx(
            vec![provocation(
                StreamOutcome::ConnectionClosed {
                    code: 257,
                    reason: "Bad assurance: Invalid message".into(),
                },
                Some(false),
            )],
            Some(true),
        );
        assert_eq!(
            run(malformed_stream_contained(&closed)),
            [(
                "n7_malformed_stream_contained",
                Outcome::Fail(Severity::Soft)
            )]
        );
    }

    /// The close message must reach the report, or the row says a node did
    /// something wrong without saying what it said about it -- which is what
    /// made §29 take two rounds to diagnose.
    #[test]
    fn a_connection_close_is_reported_in_the_nodes_own_words() {
        let closed = ctx(
            vec![provocation(
                StreamOutcome::ConnectionClosed {
                    code: 257,
                    reason: "Bad assurance: Invalid message".into(),
                },
                Some(false),
            )],
            Some(true),
        );
        let obs = ObsLog::new();
        let results = (malformed_stream_contained(&closed).run)(&obs);
        let detail = results[0]
            .detail
            .as_ref()
            .expect("a failure carries detail");
        assert!(
            detail.contains("Bad assurance: Invalid message") && detail.contains("257"),
            "the row must quote the node; it said: {detail}"
        );
        assert!(
            detail.contains("unassigned kind 130"),
            "and must name what provoked it; it said: {detail}"
        );
    }

    /// The provoker is not a validator, and a row must not call it one.
    ///
    /// `PROVOKER_PEER` is `0x4E`, so the first version of this row printed
    /// "validator 78" against a run whose validator set runs 0..=5 -- the
    /// confusion `findings.md` §8 records, reintroduced in the one place
    /// whose doc comment cites it. Caught by reading the first real report,
    /// not by any test, which is why this one exists.
    #[test]
    fn a_row_does_not_call_the_provoker_a_validator() {
        let closed = ctx(
            vec![provocation(
                StreamOutcome::ConnectionClosed {
                    code: 257,
                    reason: "Bad incoming stream protocol 200".into(),
                },
                Some(false),
            )],
            Some(true),
        );
        let obs = ObsLog::new();
        for check in [
            malformed_stream_contained(&closed),
            connection_reusable(&closed),
        ] {
            for row in (check.run)(&obs) {
                let Some(detail) = row.detail else { continue };
                assert!(
                    !detail.contains("validator 78") && !detail.contains("validator 0x4E"),
                    "a row named the provoker as a validator: {detail}"
                );
                assert!(
                    detail.contains("the provoker"),
                    "and it must name it as what it is: {detail}"
                );
            }
        }
    }

    /// A node that comes back and serves passes hard; one that does not,
    /// fails hard. This is the row that would catch a node whose restart
    /// loses state it should have persisted.
    #[test]
    fn a_node_that_does_not_recover_fails_hard() {
        assert_eq!(
            run(restart_resyncs(&restarted(Some(true), vec![9], Some(9)))),
            [("n7_restart_serves_again", Outcome::Pass)]
        );
        assert_eq!(
            run(restart_resyncs(&restarted(Some(false), vec![], Some(9)))),
            [("n7_restart_serves_again", Outcome::Fail(Severity::Hard))]
        );
    }

    /// A run that never restarted anything must not collect a pass for it.
    #[test]
    fn a_run_without_a_restart_reports_it_unexercised() {
        let no_restart = ctx(
            vec![provocation(StreamOutcome::Reset, Some(true))],
            Some(true),
        );
        let rows = run(restart_resyncs(&no_restart));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "n7_restart_not_exercised");
        assert!(rows[0].1 != Outcome::Pass);
        // And the authoring row says nothing at all rather than passing.
        assert!(run(restart_authors_again(&no_restart)).is_empty());
    }

    /// Recovery unmeasured is not recovery confirmed.
    #[test]
    fn unmeasured_recovery_does_not_pass() {
        let rows = run(restart_resyncs(&restarted(None, vec![], Some(9))));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "n7_restart_recovery_not_measured");
        assert!(rows[0].1 != Outcome::Pass);
    }

    /// The authoring row needs a slot the node owed a block in. Without one
    /// a silent node has done nothing wrong, and the row must say the
    /// control was missing rather than fail the node for the run's timing --
    /// the mistake §5 cost two pins.
    #[test]
    fn authoring_without_a_due_slot_grades_nobody() {
        let rows = run(restart_authors_again(&restarted(Some(true), vec![], None)));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "n7_restart_authoring_not_exercised");
        assert!(rows[0].1 != Outcome::Pass);
    }

    /// With a due slot, authoring nothing fails and authoring something
    /// passes.
    #[test]
    fn authoring_after_a_restart_is_graded_against_a_due_slot() {
        assert_eq!(
            run(restart_authors_again(&restarted(
                Some(true),
                vec![],
                Some(9)
            ))),
            [("n7_restart_authors_again", Outcome::Fail(Severity::Soft))]
        );
        assert_eq!(
            run(restart_authors_again(&restarted(
                Some(true),
                vec![11],
                Some(9)
            ))),
            [("n7_restart_authors_again", Outcome::Pass)],
            "resuming a slot or two late is still resuming"
        );
    }

    /// A node that authored after the restart passes even where the harness
    /// could not work out which slot it was due in.
    ///
    /// This is the case the first version got wrong, and the first real run
    /// caught it: under Safrole the node's slots come from tickets, so the
    /// stride inferred from its earlier blocks is usually irregular and
    /// `first_due_slot` is `None`. Gating the whole row on that control made
    /// it report itself unexercised against a node that had visibly resumed
    /// -- `sessions/n7-4`, where the node authored slot 9954365 and the row
    /// said it had not been exercised.
    #[test]
    fn authoring_passes_without_a_due_slot_when_it_actually_authored() {
        assert_eq!(
            run(restart_authors_again(&restarted(
                Some(true),
                vec![9_954_365],
                None
            ))),
            [("n7_restart_authors_again", Outcome::Pass)],
            "a block after the restart is evidence regardless of the schedule"
        );
    }

    /// A node that answers a malformed request has not contained it in the
    /// sense that matters, but it has not taken the connection down either.
    /// The row passes and the oddity is visible in the trace rather than
    /// being graded here, where there is no rule to grade it against.
    #[test]
    fn answering_a_malformed_request_is_not_a_containment_failure() {
        let answered = ctx(
            vec![provocation(
                StreamOutcome::Answered { bytes: 12 },
                Some(true),
            )],
            Some(true),
        );
        assert_eq!(
            run(malformed_stream_contained(&answered)),
            [("n7_malformed_stream_contained", Outcome::Pass)]
        );
    }

    /// A hang is a containment failure: the stream is neither rejected nor
    /// answered, and the harness is left holding it.
    #[test]
    fn a_hung_stream_fails_containment() {
        let hung = ctx(
            vec![provocation(
                StreamOutcome::TimedOut { after_ms: 30_000 },
                Some(true),
            )],
            Some(true),
        );
        assert_eq!(
            run(malformed_stream_contained(&hung)),
            [(
                "n7_malformed_stream_contained",
                Outcome::Fail(Severity::Soft)
            )]
        );
    }

    #[test]
    fn a_dead_node_fails_hard_and_a_live_one_passes() {
        let dead = ctx(
            vec![provocation(StreamOutcome::Reset, Some(true))],
            Some(false),
        );
        assert_eq!(
            run(node_alive_after(&dead)),
            [("n7_node_alive_after", Outcome::Fail(Severity::Hard))]
        );

        let live = ctx(
            vec![provocation(StreamOutcome::Reset, Some(true))],
            Some(true),
        );
        assert_eq!(
            run(node_alive_after(&live)),
            [("n7_node_alive_after", Outcome::Pass)]
        );
    }

    /// A run that sent nothing grades nobody. Without this, a lane that failed
    /// to provoke anything would report three passes and look like evidence.
    #[test]
    fn a_run_that_provoked_nothing_reports_itself_unexercised() {
        let nothing = ctx(Vec::new(), Some(true));
        for check in all(&nothing) {
            for row in run(check) {
                // Each check names its own absence -- the provocation rows
                // report `n7_not_exercised`, the restart rows their own --
                // and none of them may pass.
                assert!(
                    row.0.contains("not_exercised") || row.0.contains("not_measured"),
                    "an unprovoked run must report absence, not {}",
                    row.0
                );
                assert!(row.1 != Outcome::Pass, "{} must not pass", row.0);
            }
        }
    }

    /// Liveness unmeasured is not liveness confirmed. The hard row must not
    /// pass on a `None`, or a run that forgot to check would certify the node
    /// as alive.
    #[test]
    fn unmeasured_liveness_does_not_pass() {
        let unmeasured = ctx(vec![provocation(StreamOutcome::Reset, Some(true))], None);
        let rows = run(node_alive_after(&unmeasured));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "n7_liveness_not_measured");
        assert!(rows[0].1 != Outcome::Pass);
    }

    /// Likewise for reuse: never having tried is not the same as having tried
    /// and failed, and must not be reported as either a pass or a defect.
    #[test]
    fn unattempted_reuse_is_neither_pass_nor_defect() {
        let untried = ctx(vec![provocation(StreamOutcome::Reset, None)], Some(true));
        let rows = run(connection_reusable(&untried));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "n7_connection_reuse_not_attempted");
        assert!(rows[0].1 != Outcome::Pass);
    }

    /// One row per provocation, so a lane that sends three faults and has one
    /// rejected badly reports that one rather than a single merged verdict.
    #[test]
    fn each_provocation_gets_its_own_row() {
        let mixed = ctx(
            vec![
                provocation(StreamOutcome::Reset, Some(true)),
                Provocation {
                    fault: Fault::TruncatedMessage {
                        kind: 128,
                        claimed: 4096,
                        sent: 8,
                    },
                    ..provocation(
                        StreamOutcome::ConnectionClosed {
                            code: 257,
                            reason: "Invalid message".into(),
                        },
                        Some(false),
                    )
                },
                Provocation {
                    fault: Fault::TrailingBytes {
                        kind: 128,
                        extra: 16,
                    },
                    ..provocation(StreamOutcome::Reset, Some(true))
                },
            ],
            Some(true),
        );
        let rows = run(malformed_stream_contained(&mixed));
        assert_eq!(rows.len(), 3, "one row per provocation");
        assert_eq!(rows[0].1, Outcome::Pass);
        assert_eq!(rows[1].1, Outcome::Fail(Severity::Soft));
        assert_eq!(rows[2].1, Outcome::Pass);
    }
}
