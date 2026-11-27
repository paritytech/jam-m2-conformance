//! Can the N7 checks fail?
//!
//! N7 provokes the node with streams no conforming peer would open, so the
//! lane's own risk is the opposite of the other lanes': not that it fails a
//! good node, but that it *passes* a bad one. A node that closes the whole
//! connection, and a node that hangs, both leave the harness holding a dead
//! or stuck stream — and a row that read either as "rejected, fine" would
//! report a clean lane against the defect `findings.md` §30 records.
//!
//! So the control here is a node that disposes of an unknown kind quietly,
//! and the faults are the two other ways it can go. Each must fail the
//! containment row rather than make it disappear.
//!
//! What these cannot pose is the hard row. `n7_node_alive_after` asks
//! whether the node survived, and a stand-in that is still answering is the
//! only kind this harness can build: killing it would end the test process's
//! own task, not simulate a crash. That row is graded by its unit tests in
//! `scenarios::n7`, where liveness is an input rather than a process.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use ed25519_consensus::SigningKey;
use jamnp_s::clock::{self, VirtualClock};
use jamnp_s::endpoint::EndpointConfig;
use jamnp_s::trace::Trace;
use jamnp_s::transport::mock::MockNetwork;
use jamnp_s::transport::Transport;
use m2_emu::robustness::{self, UNASSIGNED_IN_RANGE};
use m2_reference::chain::RefChain;
use m2_scenario::dsl::{Outcome, Severity};
use m2_scenario::scenarios::n7::{self, N7Ctx, StreamOutcome};
use m2_sim::{SimFault, SimNode};

const NUT_INDEX: usize = 2;
const PEER: u16 = 1;

/// Which provocation a test sends.
#[derive(Clone, Copy)]
enum Provoke {
    UnknownKind,
    SlowLoris,
}

/// Provoke a simulated node and grade what came back.
async fn provoke(fault: SimFault) -> (n7::Provocation, Vec<(&'static str, Outcome)>) {
    provoke_with(fault, Provoke::UnknownKind).await
}

async fn provoke_with(
    fault: SimFault,
    which: Provoke,
) -> (n7::Provocation, Vec<(&'static str, Outcome)>) {
    let transport = Arc::new(MockNetwork::new()) as Arc<dyn Transport>;
    let oracle = m2_reference::oracle::Oracle::for_tests();
    let node_chain = Arc::new(RefChain::tiny_for(&oracle, NUT_INDEX).expect("the node's chain"));
    let genesis = node_chain.genesis_hash();

    let node = Arc::new(SimNode::at_index(Arc::clone(&node_chain), fault, NUT_INDEX));
    let (nut_addr, serving) = Arc::clone(&node)
        .listen(
            Arc::clone(&transport),
            SigningKey::from([0x96u8; 32]),
            "127.0.0.1:9740".parse::<SocketAddr>().expect("an address"),
        )
        .await
        .expect("the simulated node binds");

    let connection = transport
        .connect(
            EndpointConfig {
                genesis_hash: genesis,
                builder: false,
            },
            SigningKey::from([0x7eu8; 32]),
            san_of(NUT_INDEX),
            nut_addr,
        )
        .await
        .expect("the peer connects");

    let trace = Mutex::new(Trace::default());
    let provocation = match which {
        Provoke::UnknownKind => {
            robustness::unknown_kind(&connection, PEER, UNASSIGNED_IN_RANGE, &trace).await
        }
        Provoke::SlowLoris => {
            robustness::slow_loris(
                &connection,
                PEER,
                jamnp_s::framing::CE128,
                std::time::Duration::from_secs(30),
                &trace,
            )
            .await
        }
    };

    let ctx = N7Ctx {
        provocations: vec![provocation.clone()],
        // Not measured here; the module note says why.
        alive_after: Some(true),
        // No process to kill: SimNode runs in this test's own process.
        restart: None,
        // The flood has its own test; it does not go through this helper.
        flood: None,
    };
    let obs = m2_scenario::dsl::ObsLog::new();
    let rows = n7::all(&ctx)
        .into_iter()
        .flat_map(|check| (check.run)(&obs))
        .map(|row| (row.name, row.outcome))
        .collect();

    serving.abort();
    (provocation, rows)
}

fn san_of(index: usize) -> String {
    use ed25519_consensus::VerificationKey;
    use jam_std_common::SecretKeyset;
    let secret = SecretKeyset::trivial(index as u32).ed25519;
    jamnp_s::cert::san_for_key(&VerificationKey::from(&SigningKey::from(secret.to_bytes())))
}

fn outcomes_of<'a>(rows: &'a [(&'static str, Outcome)], row: &str) -> Vec<&'a Outcome> {
    rows.iter()
        .filter(|(name, _)| *name == row)
        .map(|(_, o)| o)
        .collect()
}

/// A node that quietly disposes of an unknown kind passes containment, and
/// the two bad answers fail it.
///
/// Both faults are run through the same provocation as the control, so a
/// difference in the verdict is the node's behaviour and not the setup.
#[tokio::test(start_paused = true)]
async fn the_containment_row_catches_a_node_that_kills_the_connection() {
    clock::install(Arc::new(VirtualClock::starting_at(2_100_000_000_000)))
        .expect("nothing has read the clock yet");

    // The control: an unserved kind, disposed of without collateral.
    let (quiet, rows) = provoke(SimFault::None).await;
    assert!(
        quiet.outcome.is_contained(),
        "a node that drops an unserved stream has contained it; it {}",
        quiet.outcome.describe()
    );
    assert_eq!(
        outcomes_of(&rows, "n7_malformed_stream_contained"),
        [&Outcome::Pass],
        "so the row must pass"
    );

    // §30's behaviour: the whole connection goes.
    let (closed, rows) = provoke(SimFault::ClosesConnectionOnUnknownKind).await;
    assert!(
        matches!(closed.outcome, StreamOutcome::ConnectionClosed { .. }),
        "the fault must be read as a connection close, not as a reset; it was {}",
        closed.outcome.describe()
    );
    assert_eq!(
        outcomes_of(&rows, "n7_malformed_stream_contained"),
        [&Outcome::Fail(Severity::Soft)],
        "and the row must fail rather than vanish"
    );
    // The node's own words have to survive into the row, or the report says
    // something went wrong without saying what the node said about it.
    let StreamOutcome::ConnectionClosed { code, reason } = &closed.outcome else {
        unreachable!("matched above");
    };
    assert_eq!(*code, 257);
    assert!(
        reason.contains("Unknown stream kind"),
        "the close reason must reach the row; it was {reason:?}"
    );
}

/// A node that takes the stream and says nothing forever is not rejecting
/// it, and must not be graded as though it had.
///
/// This is the outcome most likely to be mistaken for a pass: nothing has
/// failed, no connection died, and a row that only asked "did the connection
/// survive?" would report a clean result against a node that stopped
/// answering.
#[tokio::test(start_paused = true)]
async fn a_hang_is_not_mistaken_for_a_rejection() {
    let (hung, rows) = provoke(SimFault::HangsOnUnknownKind).await;
    assert!(
        matches!(hung.outcome, StreamOutcome::TimedOut { .. }),
        "a node that never answers must be read as a hang; it {}",
        hung.outcome.describe()
    );
    assert!(
        !hung.outcome.is_contained(),
        "and a hang is not containment"
    );
    assert_eq!(
        outcomes_of(&rows, "n7_malformed_stream_contained"),
        [&Outcome::Fail(Severity::Soft)]
    );
}

/// The reuse row must not claim a verdict it never measured.
///
/// `robustness::unknown_kind` leaves `connection_reusable` as `None` — the
/// provocation does not try the connection afterwards, the lane does. A row
/// that read `None` as a failure would blame the node for the harness not
/// having asked.
#[tokio::test(start_paused = true)]
async fn an_unmeasured_connection_is_not_reported_as_broken() {
    let (provocation, rows) = provoke(SimFault::ClosesConnectionOnUnknownKind).await;
    assert_eq!(
        provocation.connection_reusable, None,
        "the provocation does not measure reuse"
    );
    assert!(
        outcomes_of(&rows, "n7_connection_reusable").is_empty(),
        "so no verdict may be reported for it"
    );
    let unmeasured = outcomes_of(&rows, "n7_connection_reuse_not_attempted");
    assert_eq!(unmeasured.len(), 1, "it must say so instead");
    assert!(unmeasured[0] != &Outcome::Pass);
}

/// A node that reclaims an idle stream passes; one that holds it forever
/// does not.
///
/// The fault here is the absence of a timeout, which is invisible in every
/// other way: nothing is malformed, no connection dies, and the node is
/// still serving everyone else. Only the held stream shows it, and only if
/// the harness waits long enough to be sure the node was not merely slow.
#[tokio::test(start_paused = true)]
async fn the_slow_loris_row_catches_a_node_that_never_reclaims_a_stream() {
    // The control: a stand-in with a protocol timeout gives the stream up.
    let (reclaimed, rows) = provoke_with(SimFault::None, Provoke::SlowLoris).await;
    assert!(
        matches!(reclaimed.outcome, StreamOutcome::Reset),
        "a node with an idle timeout reclaims the stream; it {}",
        reclaimed.outcome.describe()
    );
    assert_eq!(
        outcomes_of(&rows, "n7_malformed_stream_contained"),
        [&Outcome::Pass]
    );

    // The fault: it waits for a message that will never come, for as long
    // as we are willing to hold the connection open.
    let (held, rows) = provoke_with(SimFault::HoldsIdleStreams, Provoke::SlowLoris).await;
    assert!(
        matches!(held.outcome, StreamOutcome::TimedOut { .. }),
        "a node without one holds it; it {}",
        held.outcome.describe()
    );
    assert_eq!(
        outcomes_of(&rows, "n7_malformed_stream_contained"),
        [&Outcome::Fail(Severity::Soft)],
        "and that must fail the row rather than pass quietly"
    );
    // The row has to say what was held and for how long, or a reader cannot
    // tell this from any other containment failure.
    let obs = m2_scenario::dsl::ObsLog::new();
    let ctx = N7Ctx {
        provocations: vec![held.clone()],
        alive_after: Some(true),
        restart: None,
        flood: None,
    };
    let detail = (n7::malformed_stream_contained(&ctx).run)(&obs)[0]
        .detail
        .clone()
        .expect("a failure carries detail");
    assert!(
        detail.contains("held silent for 30 s"),
        "the row must name the fault; it said: {detail}"
    );
}

/// Can the flood row tell a node defending itself from a node falling over?
///
/// The distinction is the whole row. A node that throttles or drops the
/// flooding peer is correct; a node whose other connections stop being
/// answered is not. So the measurement is taken on a *second* connection
/// that is doing nothing unusual, and the control is a stand-in that serves
/// it throughout.
#[tokio::test(start_paused = true)]
async fn the_flood_row_measures_bystanders_not_the_flooder() {
    let transport = Arc::new(MockNetwork::new()) as Arc<dyn Transport>;
    let oracle = m2_reference::oracle::Oracle::for_tests();

    // Both halves of the experiment, so the only difference is the fault.
    for (fault, bystander_should_be_served) in [
        (SimFault::None, true),
        (SimFault::StopsServingUnderLoad, false),
    ] {
        let node_chain =
            Arc::new(RefChain::tiny_for(&oracle, NUT_INDEX).expect("the node's chain"));
        let genesis = node_chain.genesis_hash();
        let node = Arc::new(SimNode::at_index(Arc::clone(&node_chain), fault, NUT_INDEX));
        let (nut_addr, serving) = Arc::clone(&node)
            .listen(
                Arc::clone(&transport),
                SigningKey::from([0x96u8; 32]),
                "127.0.0.1:0".parse::<SocketAddr>().expect("an address"),
            )
            .await
            .expect("the simulated node binds");

        let dial = async |seed: u8| {
            transport
                .connect(
                    EndpointConfig {
                        genesis_hash: genesis,
                        builder: false,
                    },
                    SigningKey::from([seed; 32]),
                    san_of(NUT_INDEX),
                    nut_addr,
                )
                .await
                .expect("the peer connects")
        };
        let flooder = dial(0x7f).await;
        let bystander = dial(0x7e).await;
        let trace = Mutex::new(Trace::default());

        // The flood and the bystander's question run together, as the live
        // runner does it: asking only after the flood stopped would measure
        // recovery, which is the other row.
        let duration = std::time::Duration::from_millis(500);
        let flooding = robustness::flood_streams(
            &flooder,
            PEER,
            jamnp_s::framing::CE141,
            500,
            duration,
            &trace,
        );
        let watching = async {
            // Let the flood build before asking, or the question lands while
            // the node is still idle and answers something that proves nothing.
            clock::current().sleep(duration / 2).await;
            // `connection_answers`, not `connection_still_serves`: the defect
            // here is a node that answers nobody while every connection stays
            // open, which a connection-liveness check reports as healthy.
            robustness::connection_answers(&bystander, PEER, genesis, &trace).await
        };
        let (opened, during) = tokio::join!(flooding, watching);
        let after = robustness::connection_answers(&bystander, PEER, genesis, &trace).await;

        assert_eq!(
            during,
            bystander_should_be_served,
            "with {fault:?} the bystander should{} have been served; {opened} streams opened",
            if bystander_should_be_served {
                ""
            } else {
                " not"
            }
        );

        // The measurement above is only half of it. What the report says is
        // the row's verdict, and a measurement that never reaches one grades
        // nothing -- which is what this test used to assert and all it
        // asserted (`findings.md` §42).
        let ctx = N7Ctx {
            provocations: Vec::new(),
            alive_after: None,
            restart: None,
            flood: Some(n7::FloodFacts {
                target_rate_per_sec: 500,
                duration_ms: duration.as_millis() as u64,
                streams_opened: opened,
                flooder_survived: flooder.end_reason().is_none(),
                served_bystander_during: Some(during),
                served_bystander_after: Some(after),
                authored_during: Vec::new(),
                turns_missed: Vec::new(),
            }),
        };
        let obs = m2_scenario::dsl::ObsLog::new();
        let rows: Vec<(&'static str, Outcome)> = (n7::flood_serves_bystanders(&ctx).run)(&obs)
            .into_iter()
            .map(|row| (row.name, row.outcome))
            .collect();

        let expected = if bystander_should_be_served {
            Outcome::Pass
        } else {
            Outcome::Fail(Severity::Soft)
        };
        assert_eq!(
            outcomes_of(&rows, "n7_flood_serves_bystander_during"),
            [&expected],
            "with {fault:?} the during row must reach that verdict"
        );
        assert_eq!(
            outcomes_of(&rows, "n7_flood_serves_bystander_after"),
            [&expected],
            "with {fault:?} the recovery row must reach that verdict too: this stand-in counts              streams over its whole life, so once past tolerance it never comes back"
        );
        assert!(
            outcomes_of(&rows, "n7_flood_bystander_not_measured").is_empty(),
            "a measured run must not also report itself unmeasured"
        );

        serving.abort();
    }
}

/// A flood nobody watched must report itself unmeasured, not pass.
///
/// The failure this guards is the one §19 records in another lane: a row
/// whose subject never arrived reporting a clean verdict. Here the flood
/// runs and no bystander asks anything, so there is nothing to grade and the
/// row has to say so.
#[tokio::test(start_paused = true)]
async fn a_flood_with_no_bystander_is_not_a_pass() {
    let ctx = N7Ctx {
        provocations: Vec::new(),
        alive_after: None,
        restart: None,
        flood: Some(n7::FloodFacts {
            target_rate_per_sec: 500,
            duration_ms: 500,
            streams_opened: 2400,
            flooder_survived: true,
            served_bystander_during: None,
            served_bystander_after: None,
            authored_during: Vec::new(),
            turns_missed: Vec::new(),
        }),
    };
    let obs = m2_scenario::dsl::ObsLog::new();
    let rows: Vec<(&'static str, Outcome)> = (n7::flood_serves_bystanders(&ctx).run)(&obs)
        .into_iter()
        .map(|row| (row.name, row.outcome))
        .collect();

    assert_eq!(
        outcomes_of(&rows, "n7_flood_bystander_not_measured"),
        [&Outcome::Fail(Severity::Soft)],
        "an unmeasured flood is reported, not passed"
    );
    assert!(
        outcomes_of(&rows, "n7_flood_serves_bystander_during").is_empty(),
        "and it must not also claim the node served anyone"
    );
}
