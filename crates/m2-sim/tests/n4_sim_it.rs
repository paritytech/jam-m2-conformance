//! Can the N4 availability checks fail?
//!
//! Until this test every N4 row had only ever been graded against a
//! deterministic baseline and against polkajam, which does not make these
//! mistakes. A row nobody has seen fail is a row nobody knows is a row.
//!
//! The simulated node is a *guarantor* here: it holds a bundle coded into
//! shards, with justifications built by the engine through the oracle, and
//! serves CE 137/138/139/140 from them. That is the half of availability
//! that was unreachable until `hazmat::merkle` was exported (findings.md
//! §9) -- `check_bundle_proof` could always verify a justification, and
//! nothing outside `jam-node` could build one.
//!
//! **What this does not cover.** `n4_ce141_inclusion` asks whether the node
//! carries valid assurances in its blocks and leaves invalid ones out. This
//! stand-in authors through the reference chain and cannot put an assurance
//! it received into a block, so that check is not graded here and its rows
//! remain unproven.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ed25519_consensus::{SigningKey, VerificationKey};
use jam_std_common::SecretKeyset;
use jamnp_s::cert::san_for_key;
use jamnp_s::clock::{self, VirtualClock};
use jamnp_s::transport::mock::MockNetwork;
use jamnp_s::transport::Transport;
use m2_reference::chain::RefChain;
use m2_scenario::dsl::Outcome;
use m2_scenario::scenarios::n4::{self, N4Ctx};
use m2_sim::{SimFault, SimNode};

/// The simulated node's validator index.
///
/// Also the shard index the harness asks it for from the peer of that
/// number: a validator fetches the piece it must assure, and the emulated
/// validators each ask for their own.
const NUT_INDEX: usize = 2;
const EMU_INDICES: [usize; 5] = [0, 1, 3, 4, 5];
/// Validators the bundle is coded for, which is the whole set.
const SHARD_COUNT: u16 = 6;
/// Segments the package exports, so CE 139/140 have something to ask for.
const SEGMENTS: usize = 2;
/// The core the harness believes carried the report, so an assurance
/// claiming any other core is claiming one with nothing on it.
const REPORTED_CORE: u16 = 0;

fn san_of(index: usize) -> String {
    let secret = SecretKeyset::trivial(index as u32).ed25519;
    san_for_key(&VerificationKey::from(&SigningKey::from(secret.to_bytes())))
}

/// Run one availability exchange against a simulated node and return the
/// rows it earned.
async fn grade(fault: SimFault) -> Vec<(&'static str, Outcome)> {
    let transport = Arc::new(MockNetwork::new()) as Arc<dyn Transport>;
    let oracle = m2_reference::oracle::Oracle::for_tests();
    let harness_chain = Arc::new(RefChain::tiny(&oracle, NUT_INDEX).expect("the harness chain"));
    let node_chain = Arc::new(RefChain::tiny_for(&oracle, NUT_INDEX).expect("the node's chain"));
    let genesis = harness_chain.genesis_hash();

    let node = Arc::new(SimNode::at_index(Arc::clone(&node_chain), fault, NUT_INDEX));
    // The bundle the node is a guarantor of. Coded and proved by the engine,
    // so the shards it serves are the shards a real guarantor would hold.
    let bundle: Vec<u8> = (0..6_000u32).map(|i| (i % 251) as u8).collect();
    let segments: Vec<Vec<u8>> = (0..SEGMENTS)
        .map(|i| vec![0xa0 + i as u8; jam_types::SEGMENT_LEN])
        .collect();
    let erasure_root = node
        .hold_available(bundle, segments, SHARD_COUNT)
        .expect("the bundle codes into servable shards");

    let (_nut_addr, serving) = Arc::clone(&node)
        .listen(
            Arc::clone(&transport),
            SigningKey::from([0x90u8; 32]),
            "127.0.0.1:9600".parse::<SocketAddr>().expect("an address"),
        )
        .await
        .expect("the simulated node binds");

    let emu = m2_emu::emu::Emulator::n0_on(
        Arc::clone(&transport),
        EMU_INDICES.to_vec(),
        genesis,
        40_700,
    )
    .await
    .expect("the emulated validators bind");
    let accepting = emu.accept_loop(Arc::clone(&harness_chain));

    // The node dials every emulated validator. Each of those connections
    // runs its own availability exchange, because a validator fetches the
    // shard it must assure rather than one of them fetching for the rest.
    let peers: Vec<(u16, SocketAddr, String)> = EMU_INDICES
        .iter()
        .zip(emu.local_addrs())
        .map(|(&index, addr)| (index as u16, addr, san_of(index)))
        .collect();
    node.connect_to(&transport, SigningKey::from([0x91u8; 32]), &peers)
        .await;

    let now = m2_reference::chain::wall_clock_slot();
    emu.avail_planner().set(m2_emu::avail_io::AvailPlan {
        erasure_root,
        shard_count: SHARD_COUNT,
        segment_indices: (0..SEGMENTS as u16).collect(),
        cores: vec![REPORTED_CORE],
        honest_slot: now + 1,
        // Two slots of offers: this test grades what the node *serves* and
        // what it sends, not what it carries, so one honest offer and one
        // spoiled one are all it needs. `n4_inclusion_sim_it` is the test
        // that needs a run of them.
        assurance_slots: 2,
        spoiled_from: now + 2,
    });

    // The node's own assurance, which is what `n4_ce141_send` grades. Sent
    // against a block that exists on the chain both sides share, so an
    // honest node's anchor is one the harness can account for.
    let anchor = harness_chain.genesis_hash();
    let slot_ms = jam_types::slot_period_sec() * 1000;
    clock::current()
        .sleep(Duration::from_millis(slot_ms / 2))
        .await;
    node.send_assurance(anchor, &[REPORTED_CORE]).await;

    // Long enough for both assurance rounds and every fetch to finish.
    clock::current()
        .sleep(Duration::from_millis(slot_ms * 4))
        .await;

    // The same verification a real run does, through the same functions: a
    // test with its own copy of the rule would be grading itself.
    let mut shards_served = emu
        .shards_served()
        .lock()
        .expect("the served shards")
        .clone();
    m2_runner::real::verify_served_shards(&oracle, SHARD_COUNT, &mut shards_served);
    let mut segment_shards_served = emu
        .segment_shards_served()
        .lock()
        .expect("the served segment shards")
        .clone();
    m2_runner::real::verify_segment_shards(&oracle, SHARD_COUNT, &mut segment_shards_served);

    let seen = emu.assurances_seen();
    let assurances_seen = m2_emu::avail_io::assurances_for_lane(
        &seen.lock().expect("the assurances"),
        NUT_INDEX as u16,
        &[anchor],
        &[REPORTED_CORE],
        |at_wall_ms| {
            let slot = m2_reference::chain::slot_of_ms(at_wall_ms);
            m2_reference::chain::slot_start_ms(slot + 1) as i64 - at_wall_ms as i64
        },
    );

    let ctx = N4Ctx {
        nut_index: NUT_INDEX as u16,
        shards_served,
        segment_shards_served,
        assurances_seen,
        // Not graded here: this stand-in cannot carry a received assurance
        // in a block, so the inclusion rows have nothing to say.
        assurances_offered: Vec::new(),
        availability_threshold: jam_types::supermajority_threshold(jam_types::max_val_count()),
        assured_by_core: Vec::new(),
    };

    let obs = emu.obs();
    let obs = obs.lock().expect("the observation log");
    let rows = [
        n4::n4_ce137_serve(&ctx),
        n4::n4_ce138_serve(&ctx),
        n4::n4_ce139_140_serve(&ctx),
        n4::n4_ce141_send(&ctx),
    ]
    .into_iter()
    .flat_map(|check| (check.run)(&obs))
    .map(|row| (row.name, row.outcome))
    .collect();

    accepting.abort();
    serving.abort();
    rows
}

/// Every outcome reported under `row`, because a check reports one per
/// subject and reading only the first is how a fault that broke one of five
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

#[tokio::test(start_paused = true)]
async fn the_n4_availability_checks_catch_a_node_that_serves_wrongly() {
    clock::install(Arc::new(VirtualClock::starting_at(1_800_000_000_000)))
        .expect("nothing has read the clock yet");

    let honest = grade(SimFault::None).await;
    for row in [
        "n4_ce137_answered",
        "n4_ce137_reply_complete",
        "n4_ce137_justification_verifies",
        "n4_ce138_answered",
        "n4_ce138_reply_complete",
        "n4_ce138_justification_verifies",
        "n4_ce139_140_answered",
        "n4_ce139_140_slices_are_whole",
        "n4_ce139_140_one_shard_per_request",
        "n4_ce140_justifications_verify",
        "n4_ce141_well_formed",
        "n4_ce141_bits_have_reports",
        "n4_ce141_sent_before_the_slot",
    ] {
        assert!(
            passed(&honest, row),
            "the honest node must pass {row}; it reported {:?}",
            outcomes_of(&honest, row)
        );
    }

    for (fault, broken) in [
        (SimFault::ShardRefused, "n4_ce137_answered"),
        // A genuine shard of the right length, and not the one the root
        // commits to for this index: only the proof can tell.
        (SimFault::ShardWrongBytes, "n4_ce137_justification_verifies"),
        (
            SimFault::ShardBadJustification,
            "n4_ce137_justification_verifies",
        ),
        (SimFault::ShardReplyShort, "n4_ce137_reply_complete"),
        (
            SimFault::SegmentShardsRagged,
            "n4_ce139_140_slices_are_whole",
        ),
        (
            SimFault::SegmentShardsShort,
            "n4_ce139_140_one_shard_per_request",
        ),
        (
            SimFault::SegmentJustificationBad,
            "n4_ce140_justifications_verify",
        ),
        (SimFault::AssuranceWrongAnchor, "n4_ce141_well_formed"),
        (SimFault::AssuranceBadSignature, "n4_ce141_well_formed"),
        (SimFault::AssuranceEmptyCore, "n4_ce141_bits_have_reports"),
        (SimFault::AssuranceLate, "n4_ce141_sent_before_the_slot"),
    ] {
        let rows = grade(fault).await;
        assert!(
            failed(&rows, broken),
            "{fault:?} must make {broken} fail; it reported {:?}",
            outcomes_of(&rows, broken)
        );
    }

    // Which faults cannot be isolated is part of the result, not a footnote.
    //
    // A refused CE 137 stream is a refused CE 138 stream: the node answers
    // both from the same store and the fault is in the answering, not in
    // either protocol. Both rows fail together, by construction.
    let refused = grade(SimFault::ShardRefused).await;
    assert!(
        failed(&refused, "n4_ce138_answered"),
        "refusing to serve refuses both protocols: {:?}",
        outcomes_of(&refused, "n4_ce138_answered")
    );

    // A reply one message short is isolable: the shard it did send is the
    // right one, so only the count row fails and the justification row is
    // never reached -- the missing message is the justification.
    let short = grade(SimFault::ShardReplyShort).await;
    assert!(
        passed(&short, "n4_ce137_answered"),
        "a short reply is still an answer: {:?}",
        outcomes_of(&short, "n4_ce137_answered")
    );
    assert!(
        passed(&short, "n4_ce138_reply_complete"),
        "and CE 138, which owes two messages, is untouched: {:?}",
        outcomes_of(&short, "n4_ce138_reply_complete")
    );

    // A bad segment justification does not disturb the slices themselves:
    // the right bytes arrive, in the right number, and only the proof over
    // them fails. CE 139, which carries no justification, is untouched.
    let bad_segment = grade(SimFault::SegmentJustificationBad).await;
    assert!(
        passed(&bad_segment, "n4_ce139_140_one_shard_per_request")
            && passed(&bad_segment, "n4_ce139_140_slices_are_whole"),
        "only the proof fails: {:?} / {:?}",
        outcomes_of(&bad_segment, "n4_ce139_140_one_shard_per_request"),
        outcomes_of(&bad_segment, "n4_ce139_140_slices_are_whole"),
    );

    // A late assurance is sound, so only the timing row -- which is Soft,
    // because `simple.md:679-680` says "roughly" -- may fail.
    let late = grade(SimFault::AssuranceLate).await;
    assert!(
        passed(&late, "n4_ce141_well_formed") && passed(&late, "n4_ce141_bits_have_reports"),
        "lateness is not unsoundness: {:?} / {:?}",
        outcomes_of(&late, "n4_ce141_well_formed"),
        outcomes_of(&late, "n4_ce141_bits_have_reports"),
    );
    assert!(
        outcomes_of(&late, "n4_ce141_sent_before_the_slot")
            .iter()
            .any(|o| **o == Outcome::Fail(m2_scenario::dsl::Severity::Soft)),
        "and it is soft: {:?}",
        outcomes_of(&late, "n4_ce141_sent_before_the_slot")
    );
}
