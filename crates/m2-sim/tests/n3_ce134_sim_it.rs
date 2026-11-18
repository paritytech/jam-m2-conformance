//! Can the N3 CE 134 receive checks fail?
//!
//! The one place in N3 where the **node** does the refining and the harness
//! grades the result. Everywhere else the lane grades what a node says about
//! work the reference did; here the harness shares a bundle with the node
//! and asks what it made of it (`simple.md:439-456`).
//!
//! Three rows, and not one of them had ever been seen to fail. The
//! simulated node opened CE 134 and had never been asked to answer one, so
//! these were the last rows in N3 in that position and what kept N3 and N4
//! out of the default lane set.
//!
//! **What the stand-in does not do is refine.** The test tells it what the
//! bundle comes to, and it answers with that. The rows are unharmed,
//! because none of them asks whether refining is correct: they ask whether
//! the node answered at all, whether it refused a share it should have, and
//! whether the hash it named is the reference's. Each fault moves exactly
//! one of those.
//!
//! A fourth row sits next door and is **not** provable here.
//! `n3_ce134_shares_the_submitted_package` grades the mappings on a share
//! the node *sends*, and is gated on those mappings being non-empty. They
//! map imported segments to the roots they come from, and no package this
//! harness builds imports any -- so the gate never opens, against a live
//! node or a simulated one. That is the same blocker as `findings.md` §17
//! and is recorded there rather than papered over with a row that cannot
//! run.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ed25519_consensus::{SigningKey, VerificationKey};
use jam_std_common::SecretKeyset;
use jamnp_s::cert::san_for_key;
use jamnp_s::clock::{self, VirtualClock};
use jamnp_s::endpoint::EndpointConfig;
use jamnp_s::transport::mock::MockNetwork;
use jamnp_s::transport::Transport;
use m2_reference::chain::RefChain;
use m2_reference::reports::ShareFault;
use m2_scenario::dsl::Outcome;
use m2_scenario::scenarios::n3::{self, N3Ctx};
use m2_sim::{SimFault, SimNode};

/// The simulated node's validator index.
const NUT_INDEX: usize = 2;
const EMU_INDICES: [usize; 5] = [0, 1, 3, 4, 5];
/// Slots to author before sharing, so the chain reaches the current epoch
/// and leaves a recent lookup anchor behind the head. A bundle is refined
/// through the engine, and the engine refuses both without one.
const WALK_SLOTS: u32 = 12;

fn san_of(index: usize) -> String {
    let secret = SecretKeyset::trivial(index as u32).ed25519;
    san_for_key(&VerificationKey::from(&SigningKey::from(secret.to_bytes())))
}

/// Share a well-formed bundle and an unacceptably-coded one, and return the
/// rows the CE 134 receive check earns.
///
/// Both in one run, because the two rows they feed are each other's
/// control: a node that refuses everything passes the shard-count row and
/// fails the answered row, and one that accepts everything does the
/// reverse. Grading them apart would let either look healthy alone.
async fn grade(fault: SimFault) -> Vec<(&'static str, Outcome)> {
    let transport = Arc::new(MockNetwork::new()) as Arc<dyn Transport>;
    let oracle = m2_reference::oracle::Oracle::for_tests();
    let harness_chain = Arc::new(RefChain::tiny(&oracle, NUT_INDEX).expect("the harness chain"));
    let node_chain = Arc::new(RefChain::tiny_for(&oracle, NUT_INDEX).expect("the node's chain"));
    let genesis = harness_chain.genesis_hash();

    // The chain has to reach the current epoch before it can refine, and
    // leave a recent block behind the head to anchor the lookup against.
    let from = m2_reference::chain::wall_clock_slot();
    let authored = (from..from + WALK_SLOTS)
        .filter(|&slot| matches!(harness_chain.author_block(slot), Ok(Some(_))))
        .count();
    assert!(
        authored > 1,
        "the reference chain must reach the current epoch and leave a recent anchor behind \
         it before it can refine; it authored {authored} block(s)"
    );
    // Past the head the walk left, not at the clock's current slot: the
    // epoch view resolves the cached epoch and the one after it, and a walk
    // long enough to leave an anchor can carry the head past the slot the
    // run started in.
    let slot = from + WALK_SLOTS;

    let node = Arc::new(SimNode::at_index(Arc::clone(&node_chain), fault, NUT_INDEX));

    let (nut_addr, serving) = Arc::clone(&node)
        .listen(
            Arc::clone(&transport),
            SigningKey::from([0x96u8; 32]),
            "127.0.0.1:9903".parse::<SocketAddr>().expect("an address"),
        )
        .await
        .expect("the simulated node binds");

    let emu = m2_emu::emu::Emulator::n0_on(
        Arc::clone(&transport),
        EMU_INDICES.to_vec(),
        genesis,
        41_500,
    )
    .await
    .expect("the emulated validators bind");
    let accepting = emu.accept_loop(Arc::clone(&harness_chain));

    for (i, posed) in [None, Some(ShareFault::WrongShardCount)]
        .into_iter()
        .enumerate()
    {
        let share = harness_chain
            .share_to_nut(NUT_INDEX as u16, slot, posed)
            .expect("a bundle to share")
            .expect("the node holds a core at this slot");
        // Told once, from the honest share: what the bundle refines to is a
        // fact about the bundle, and both shares carry the same one.
        if posed.is_none() {
            node.refines_to(share.expected_report_hash);
        }
        let connection = transport
            .connect(
                EndpointConfig {
                    genesis_hash: genesis,
                    builder: false,
                },
                SigningKey::from([0xd0u8 + i as u8; 32]),
                san_of(NUT_INDEX),
                nut_addr,
            )
            .await
            .expect("the validator connects");
        m2_emu::report_io::spawn_share_sender(
            connection.clone(),
            share,
            emu.trace(),
            emu.obs(),
            emu.shared_to_nut(),
            EMU_INDICES[0] as u16,
        )
        .await;
        drop(connection);
    }
    // The sender reads its own reply, so the exchange is over by here; a
    // beat for the node's side of the stream to close.
    clock::current().sleep(Duration::from_millis(200)).await;

    let shared_to_nut = emu.shared_to_nut();
    let shared_to_nut = shared_to_nut.lock().expect("the shares").clone();

    let ctx = N3Ctx {
        nut_index: NUT_INDEX as u16,
        submissions: Vec::new(),
        shares: Vec::new(),
        reports: Vec::new(),
        answers_sharing: false,
        expected_report_hash: None,
        emulated_peers: EMU_INDICES.iter().map(|&i| i as u16).collect(),
        shared_to_nut,
        distributed: Vec::new(),
        included: Vec::new(),
        authored_slots: Vec::new(),
    };

    let obs = emu.obs();
    let obs = obs.lock().expect("the observation log");
    let rows = (n3::n3_ce134_receive(&ctx).run)(&obs)
        .into_iter()
        .map(|row| (row.name, row.outcome))
        .collect();

    accepting.abort();
    serving.abort();
    rows
}

/// Every outcome reported under `row`, because a check reports one per
/// subject and reading only the first is how a fault that broke one of two
/// looked like a pass.
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

/// Present **and** failing: a row the grading never produced caught nothing.
fn failed(rows: &[(&'static str, Outcome)], row: &str) -> bool {
    outcomes_of(rows, row)
        .iter()
        .any(|o| matches!(o, Outcome::Fail(_)))
}

const ROWS: [&str; 3] = [
    "n3_ce134_answered",
    "n3_ce134_hash_equals_the_reference",
    "n3_ce134_wrong_shard_count_refused",
];

#[tokio::test(start_paused = true)]
async fn the_receive_checks_catch_a_guarantor_that_mishandles_a_share() {
    clock::install(Arc::new(VirtualClock::starting_at(2_000_000_000_000)))
        .expect("nothing has read the clock yet");

    let honest = grade(SimFault::None).await;
    for row in ROWS {
        assert!(
            passed(&honest, row),
            "the honest node must pass {row}; it reported {:?}",
            outcomes_of(&honest, row)
        );
    }

    // Each fault and the row it must cost, with the other two held to
    // passing: a fault that fails everything proves no row in particular.
    for (fault, row) in [
        (SimFault::ShareRefused, "n3_ce134_answered"),
        (
            SimFault::ShareWrongHash,
            "n3_ce134_hash_equals_the_reference",
        ),
        (
            SimFault::ShareAcceptsBadShardCount,
            "n3_ce134_wrong_shard_count_refused",
        ),
    ] {
        let rows = grade(fault).await;
        assert!(
            failed(&rows, row),
            "{fault:?} must fail {row}; it reported {:?}",
            outcomes_of(&rows, row)
        );
        for other in ROWS {
            if other == row {
                continue;
            }
            // `hash_equals_the_reference` is reported only where the node
            // answered, so a node that refuses every share leaves it with
            // no subject rather than a passing one. Absent is not failing,
            // and the row it did cost is asserted above.
            if fault == SimFault::ShareRefused && other == "n3_ce134_hash_equals_the_reference" {
                assert!(
                    outcomes_of(&rows, other).is_empty(),
                    "a refused share has no hash to grade; it reported {:?}",
                    outcomes_of(&rows, other)
                );
                continue;
            }
            assert!(
                passed(&rows, other),
                "{fault:?} must leave {other} passing, so a reader sees one hole rather \
                 than a broken node; it reported {:?}",
                outcomes_of(&rows, other)
            );
        }
    }
}
