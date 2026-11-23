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
    check(
        "n7_malformed_stream_contained",
        Severity::Soft,
        move |_obs| {
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
                                "sent {} to validator {}'s connection at wall {} ms; the node {}",
                                p.fault.describe(),
                                p.peer,
                                p.at_wall_ms,
                                p.outcome.describe()
                            )
                        },
                    )
                })
                .collect()
        },
    )
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
    check("n7_connection_reusable", Severity::Soft, move |_obs| {
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
                            "after {}, an ordinary CE 128 request on the same connection to \
                             validator {} got no answer; the node {}",
                            p.fault.describe(),
                            p.peer,
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
    check("n7_node_alive_after", Severity::Hard, move |_obs| {
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

/// Every N7 check, in reporting order.
pub fn all(ctx: &N7Ctx) -> Vec<Check> {
    vec![
        malformed_stream_contained(ctx),
        connection_reusable(ctx),
        node_alive_after(ctx),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsl::{ObsLog, Outcome};

    fn provocation(outcome: StreamOutcome, reusable: Option<bool>) -> Provocation {
        Provocation {
            peer: 1,
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
            let rows = run(check);
            assert_eq!(rows.len(), 1);
            assert_eq!(
                rows[0].0, "n7_not_exercised",
                "an unprovoked run must say so, not pass"
            );
            assert!(rows[0].1 != Outcome::Pass, "and must not pass");
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
