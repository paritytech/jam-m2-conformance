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
