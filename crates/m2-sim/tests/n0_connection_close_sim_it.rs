//! Can the connection-close row fail?
//!
//! The row says a message the node refuses costs its stream and nothing else
//! (`simple.md:115-120`). It exists because polkajam does the other thing:
//! an assurance it will not pool closes the whole QUIC connection, with
//! `Bad assurance: Invalid message (code 257)`, and every other protocol
//! with that validator goes down with it (`findings.md` §30).
//!
//! Against a live node the row only ever *failed*, which says nothing about
//! whether it can pass; and before it existed the close was invisible —
//! §29 read one dropped connection as two unrelated defects in two lanes.
//! So both directions are graded here, with the honest node as the control.
//!
//! The stand-in refuses at the connection for *any* assurance it will not
//! pool, rather than reproducing which refusals polkajam escalates. The row
//! does not grade the reason a node refuses, only where it puts the refusal.

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
use m2_scenario::scenarios::n0;
use m2_sim::{SimFault, SimNode};

const NUT_INDEX: usize = 2;
const EMU_INDICES: [usize; 5] = [0, 1, 3, 4, 5];
const SHARD_COUNT: u16 = 6;
const SEGMENTS: usize = 4;
fn san_of(index: usize) -> String {
    let secret = SecretKeyset::trivial(index as u32).ed25519;
    san_for_key(&VerificationKey::from(&SigningKey::from(secret.to_bytes())))
}

/// One row result: its name, its outcome, and what it said.
type Row = (&'static str, Outcome, Option<String>);

/// Offer a simulated node one honest assurance and one spoiled one, and
/// grade what became of the connections.
async fn grade(fault: SimFault) -> Vec<Row> {
    let transport = Arc::new(MockNetwork::new()) as Arc<dyn Transport>;
    let oracle = m2_reference::oracle::Oracle::for_tests();
    let harness_chain = Arc::new(RefChain::tiny(&oracle, NUT_INDEX).expect("the harness chain"));
    let node_chain = Arc::new(RefChain::tiny_for(&oracle, NUT_INDEX).expect("the node's chain"));
    let genesis = harness_chain.genesis_hash();

    let node = Arc::new(SimNode::at_index(Arc::clone(&node_chain), fault, NUT_INDEX));
    let bundle: Vec<u8> = (0..6_000u32).map(|i| (i % 251) as u8).collect();
    let segments: Vec<Vec<u8>> = (0..SEGMENTS)
        .map(|i| vec![0xa0 + i as u8; jam_types::SEGMENT_LEN])
        .collect();
    let (erasure_root, segments_root) = node
        .hold_available(bundle, segments, SHARD_COUNT)
        .expect("the bundle codes into servable shards");

    let (_nut_addr, serving) = Arc::clone(&node)
        .listen(
            Arc::clone(&transport),
            SigningKey::from([0x90u8; 32]),
            "127.0.0.1:9610".parse::<SocketAddr>().expect("an address"),
        )
        .await
        .expect("the simulated node binds");

    let emu = m2_emu::emu::Emulator::n0_on(
        Arc::clone(&transport),
        EMU_INDICES.to_vec(),
        genesis,
        40_800,
    )
    .await
    .expect("the emulated validators bind");
    let accepting = emu.accept_loop(Arc::clone(&harness_chain));

    // The node dials: these are connections the emulator *accepted*, which
    // is the half that had no log line at all before §30 and so the half a
    // lost connection hid in.
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
        segments_root,
        shard_count: SHARD_COUNT,
        segment_indices: (0..2u16).collect(),
        segment_count: SEGMENTS as u32,
        honest_slot: now + 1,
        // One round, and a spoiled one. A second round would be skipped:
        // nothing authors on this chain, so the head does not move and the
        // assurance loop rightly declines to assure the same anchor twice.
        //
        // Both runs therefore put the *same* bytes on the wire, and the
        // node's answer to them is the only thing that differs.
        assurance_slots: 1,
        spoiled_from: now + 1,
    });

    let slot_ms = jam_types::slot_period_sec() * 1000;
    clock::current()
        .sleep(Duration::from_millis(slot_ms * 4))
        .await;

    // Read as a run reads it: when the window closes, before any teardown.
    let ends = emu.connection_ends();
    let obs = emu.obs();
    let obs = obs.lock().expect("the observation log");
    let rows = (n0::connection_close(ends, true).run)(&obs)
        .into_iter()
        .map(|row| (row.name, row.outcome, row.detail))
        .collect();

    accepting.abort();
    serving.abort();
    rows
}

fn outcomes_of<'a>(rows: &'a [Row], row: &str) -> Vec<&'a Outcome> {
    rows.iter()
        .filter(|(name, _, _)| *name == row)
        .map(|(_, outcome, _)| outcome)
        .collect()
}

fn passed(rows: &[Row], row: &str) -> bool {
    let seen = outcomes_of(rows, row);
    !seen.is_empty() && seen.iter().all(|o| matches!(o, Outcome::Pass))
}

fn failed(rows: &[Row], row: &str) -> bool {
    outcomes_of(rows, row)
        .iter()
        .any(|o| matches!(o, Outcome::Fail(_)))
}

const ROW: &str = "rejection_keeps_the_connection";

#[tokio::test(start_paused = true)]
async fn the_row_catches_a_node_that_answers_a_refusal_by_closing_the_connection() {
    clock::install(Arc::new(VirtualClock::starting_at(1_900_000_000_000)))
        .expect("nothing has read the clock yet");

    // A node that refuses at the stream keeps its connections, and the row
    // says so rather than reporting itself unexercised.
    let honest = grade(SimFault::None).await;
    assert!(
        passed(&honest, ROW),
        "a node that refuses at the stream must pass {ROW}; it reported {:?}",
        honest
    );

    let closing = grade(SimFault::ClosesOnBadAssurance).await;
    assert!(
        failed(&closing, ROW),
        "a node that closes the connection must fail {ROW}; it reported {:?}",
        closing
    );

    // The node's own words, not the harness's reading of them: a report that
    // only said "the connection ended" is what sent §29 after the wrong
    // cause for a day.
    let said = closing
        .iter()
        .filter(|(name, _, _)| *name == ROW)
        .filter_map(|(_, _, detail)| detail.as_deref())
        .find(|detail| detail.contains("Bad assurance: Invalid message"))
        .is_some();
    assert!(
        said,
        "the row must quote the reason the node closed with; it reported {closing:?}"
    );
}

/// Without a connection there is nothing to grade, and the row says that
/// rather than passing: a pass with no connection is a pass nothing could
/// have failed.
#[test]
fn the_row_reports_itself_unexercised_without_a_connection() {
    let obs = m2_scenario::dsl::ObsLog::new();
    let rows = (n0::connection_close(Vec::new(), false).run)(&obs);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name, "rejection_not_exercised");
    assert!(matches!(rows[0].outcome, Outcome::Fail(_)));
}
