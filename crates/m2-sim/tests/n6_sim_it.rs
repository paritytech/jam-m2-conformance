//! Can the N6 checks fail?
//!
//! N6 is the newest lane and the first to speak as an ordinary,
//! non-validator peer. Against polkajam every row passes, which says the
//! node is right and says nothing at all about whether the rows can catch a
//! node that is wrong — the bar this project holds every lane to
//! (`findings.md` §18).
//!
//! The exchange is two protocols in opposite directions on one connection:
//! the harness announces over CE 142 and the node asks back over CE 143. So
//! the faults worth posing are about the *follow-up*: a node that reads the
//! announcement and says nothing, and a node that answers it by asking for
//! something else.
//!
//! What this cannot pose is the lane's precondition. The stand-in has no
//! chain, so it cannot decide whether a preimage was requested on chain —
//! it asks for whatever it is told about. That condition is the lane's own
//! gate, and a run that has not met it reports itself unexercised rather
//! than grading anyone; the unit test below covers that half.

use std::net::SocketAddr;
use std::sync::Arc;

use ed25519_consensus::SigningKey;
use jamnp_s::clock::{self, VirtualClock};
use jamnp_s::endpoint::EndpointConfig;
use jamnp_s::transport::mock::MockNetwork;
use jamnp_s::transport::Transport;
use m2_reference::chain::RefChain;
use m2_scenario::dsl::Outcome;
use m2_scenario::scenarios::n6::{self, N6Ctx};
use m2_sim::{SimFault, SimNode};

const NUT_INDEX: usize = 2;

/// Announce a preimage to a simulated node and grade what it did.
async fn grade(fault: SimFault) -> Vec<(&'static str, Outcome)> {
    let transport = Arc::new(MockNetwork::new()) as Arc<dyn Transport>;
    let oracle = m2_reference::oracle::Oracle::for_tests();
    let harness_chain = Arc::new(RefChain::tiny(&oracle, NUT_INDEX).expect("the harness chain"));
    let node_chain = Arc::new(RefChain::tiny_for(&oracle, NUT_INDEX).expect("the node's chain"));
    let genesis = harness_chain.genesis_hash();

    let node = Arc::new(SimNode::at_index(Arc::clone(&node_chain), fault, NUT_INDEX));
    let (nut_addr, serving) = Arc::clone(&node)
        .listen(
            Arc::clone(&transport),
            SigningKey::from([0x96u8; 32]),
            "127.0.0.1:9640".parse::<SocketAddr>().expect("an address"),
        )
        .await
        .expect("the simulated node binds");

    // An ordinary peer: a key outside the validator set and no builder
    // suffix, which is what makes the node read the announcement as a
    // non-validator's.
    let connection = transport
        .connect(
            EndpointConfig {
                genesis_hash: genesis,
                builder: false,
            },
            SigningKey::from([0x6eu8; 32]),
            san_of(NUT_INDEX),
            nut_addr,
        )
        .await
        .expect("the ordinary peer connects");

    let announced = Arc::new(std::sync::Mutex::new(Vec::new()));
    let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let obs = Arc::new(std::sync::Mutex::new(m2_scenario::dsl::ObsLog::new()));
    let blob = m2_reference::reports::n6_preimage();

    m2_emu::preimage_io::announce_and_serve(
        connection.clone(),
        0, // the dev bootstrap service
        blob.clone(),
        Arc::new(std::sync::Mutex::new(jamnp_s::trace::Trace::default())),
        Arc::clone(&obs),
        Arc::clone(&announced),
        Arc::clone(&requests),
        n6::ORDINARY_PEER,
    )
    .await;
    drop(connection);

    let announced = announced.lock().expect("the announcements").clone();
    let requests = requests.lock().expect("the requests").clone();
    // The stand-in authors nothing, so the inclusion row is given its
    // subject directly: whether the node *included* the blob is a different
    // question from whether it asked for it, and this test grades the
    // asking.
    let included = requests
        .iter()
        .filter(|r: &&n6::PreimageRequested| r.answered)
        .map(|r| r.asked)
        .collect();
    let ctx = N6Ctx {
        announced,
        requests,
        solicited_on_chain: true,
        included,
        authored_after_announcement: true,
    };

    let obs = obs.lock().expect("the observation log");
    let rows = n6::all(&ctx)
        .into_iter()
        .flat_map(|check| (check.run)(&obs))
        .map(|row| (row.name, row.outcome))
        .collect();

    serving.abort();
    rows
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

fn passed(rows: &[(&'static str, Outcome)], row: &str) -> bool {
    let seen = outcomes_of(rows, row);
    !seen.is_empty() && seen.iter().all(|o| matches!(o, Outcome::Pass))
}

fn failed(rows: &[(&'static str, Outcome)], row: &str) -> bool {
    outcomes_of(rows, row)
        .iter()
        .any(|o| matches!(o, Outcome::Fail(_)))
}

#[tokio::test(start_paused = true)]
async fn the_preimage_checks_catch_a_node_that_mishandles_an_announcement() {
    clock::install(Arc::new(VirtualClock::starting_at(2_100_000_000_000)))
        .expect("nothing has read the clock yet");

    // The control. A node that asks for what it was told about passes every
    // row, so a failure below is the fault and not the arrangement.
    let honest = grade(SimFault::None).await;
    for row in [
        "n6_ce143_requested_after_announcement",
        "n6_ce143_asked_for_what_was_announced",
        "n6_preimage_included",
    ] {
        assert!(
            passed(&honest, row),
            "a node that follows up an announcement must pass {row}; it reported {:?}",
            outcomes_of(&honest, row)
        );
    }

    // Read the announcement, say nothing.
    let silent = grade(SimFault::IgnoresPreimageAnnouncement).await;
    assert!(
        failed(&silent, "n6_ce143_requested_after_announcement"),
        "a node that never follows up must fail the request row; it reported {:?}",
        outcomes_of(&silent, "n6_ce143_requested_after_announcement")
    );

    // Follow up, but ask for something else. The request row must fail too:
    // opening CE 143 for an unrelated hash is not following up *this*
    // announcement, and a row that counted any CE 143 would pass this node.
    let wrong = grade(SimFault::AsksForAnotherPreimage).await;
    assert!(
        failed(&wrong, "n6_ce143_requested_after_announcement"),
        "a node that asks for a hash it was never told about has not followed up the \
         announcement; it reported {:?}",
        outcomes_of(&wrong, "n6_ce143_requested_after_announcement")
    );
    // And the row that grades *what* it asked for must fail, rather than
    // vanish. This assertion is why that row exists in its current shape:
    // the first draft read the matching request and asserted it matched,
    // which is true by construction, so this fault made the row disappear
    // instead of failing it.
    assert!(
        failed(&wrong, "n6_ce143_asked_for_what_was_announced"),
        "a node that asks for a hash nobody announced must fail the row that grades what \
         it asked for; it reported {:?}",
        outcomes_of(&wrong, "n6_ce143_asked_for_what_was_announced")
    );
    // And the harness must not have served it: a blob nobody announced is
    // not ours to hand over.
    assert!(
        !passed(&wrong, "n6_preimage_included"),
        "the harness must not serve a preimage it did not announce; it reported {:?}",
        outcomes_of(&wrong, "n6_preimage_included")
    );
}

/// A run that never got its preimage solicited grades nobody.
///
/// The lane's precondition is on chain, not on the wire: a node owes a
/// follow-up only if the preimage "has been requested on chain by the given
/// service" (`simple.md:705-707`). Announcing without that and failing the
/// node would report the harness's own timing as a defect — which is the
/// mistake `findings.md` §5 cost two pins.
#[test]
fn a_run_that_did_not_solicit_grades_nobody() {
    let obs = m2_scenario::dsl::ObsLog::new();
    let ctx = N6Ctx {
        announced: vec![n6::AnnouncedPreimage {
            peer: n6::ORDINARY_PEER,
            service_id: 0,
            hash: [0x11; 32],
            length: 26,
            at_wall_ms: 1_000,
        }],
        requests: Vec::new(),
        solicited_on_chain: false,
        included: Vec::new(),
        authored_after_announcement: true,
    };
    let rows: Vec<_> = (n6::requests_announced(&ctx).run)(&obs);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name, "n6_preimage_not_solicited");
    assert!(
        rows[0].outcome != Outcome::Pass,
        "an unmet precondition is not a pass"
    );
}
