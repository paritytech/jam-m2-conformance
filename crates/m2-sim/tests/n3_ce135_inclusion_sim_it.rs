//! Can `n3_ce135_report_included` fail?
//!
//! The other half of CE 135, and a different node from the one
//! `n3_ce135_sim_it` grades. There the node is the guarantor and the rows
//! are about what it sends; here a report the *harness* guaranteed is
//! distributed to the node, on a core the node does not hold, and its only
//! job is to carry it.
//!
//! In its own file because the virtual clock is installed once per process
//! and each of these needs its own timeline.
//!
//! The row had never been seen to fail. It is not the last one in N3 in
//! that position: the four CE 134 *receive* rows still are, because this
//! stand-in opens CE 134 and has never been asked to answer one.

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
use m2_scenario::dsl::Outcome;
use m2_scenario::scenarios::n3::{self, N3Ctx};
use m2_sim::{SimFault, SimNode};

/// The simulated node's validator index.
const NUT_INDEX: usize = 2;
const EMU_INDICES: [usize; 5] = [0, 1, 3, 4, 5];
/// Slots to author before the epoch boundary, so the chains reach the
/// current epoch and leave a recent lookup anchor behind the head.
const WALK_SLOTS: u32 = 12;
/// Slots to drive while waiting for the node to author after a report has
/// been distributed to it.
///
/// Six validators share the slots, so the node authors about one in six and
/// a bound of three epochs makes a run that never reaches one vanishingly
/// unlikely. The loop stops as soon as it has one, so the bound is only
/// what keeps a stuck run from driving forever.
const INCLUSION_SLOT_BUDGET: u32 = 36;

fn san_of(index: usize) -> String {
    let secret = SecretKeyset::trivial(index as u32).ed25519;
    san_for_key(&VerificationKey::from(&SigningKey::from(secret.to_bytes())))
}

fn slot_ms() -> u64 {
    jam_types::slot_period_sec() * 1000
}

async fn at_slot(slot: u32) {
    let target = m2_reference::chain::slot_start_ms(slot);
    if let Some(wait) = target.checked_sub(clock::current().wall_ms()) {
        clock::current().sleep(Duration::from_millis(wait)).await;
    }
}

/// Distribute a report to a simulated node and grade whether it lands on
/// chain.
///
/// The report is guaranteed on a core the node does not hold, which is what
/// `report_to_distribute` composes: on its own core the node would have its
/// own guarantee for the same package and the two would be duplicates, which
/// it is right to drop and which would read as a failure to include.
async fn grade_inclusion(fault: SimFault) -> Vec<(&'static str, Outcome)> {
    let transport = Arc::new(MockNetwork::new()) as Arc<dyn Transport>;
    let oracle = m2_reference::oracle::Oracle::for_tests();
    let harness_chain = Arc::new(RefChain::tiny(&oracle, NUT_INDEX).expect("the harness chain"));
    let node_chain = Arc::new(RefChain::tiny_for(&oracle, NUT_INDEX).expect("the node's chain"));
    let genesis = harness_chain.genesis_hash();

    let node = Arc::new(SimNode::at_index(Arc::clone(&node_chain), fault, NUT_INDEX));

    let (nut_addr, serving) = Arc::clone(&node)
        .listen(
            Arc::clone(&transport),
            SigningKey::from([0x92u8; 32]),
            "127.0.0.1:9701".parse::<SocketAddr>().expect("an address"),
        )
        .await
        .expect("the simulated node binds");

    let emu = m2_emu::emu::Emulator::n0_on(
        Arc::clone(&transport),
        EMU_INDICES.to_vec(),
        genesis,
        41_400,
    )
    .await
    .expect("the emulated validators bind");
    let shared = emu.shared(Arc::clone(&harness_chain));
    let accepting = emu.accept_loop(Arc::clone(&harness_chain));
    // Drives the N1 block fetch: the node announces a block of its own and
    // the harness goes and gets it. Without this `nut_blocks` stays empty,
    // the inclusion row has no block to read, and it reports unexercised
    // however the node behaved.
    let dialing = tokio::spawn(m2_emu::emu::dial_nut(
        EMU_INDICES[0],
        genesis,
        nut_addr,
        san_of(EMU_INDICES[0]),
        shared,
    ));

    let period = jam_types::epoch_period();
    let start = (m2_reference::chain::wall_clock_slot() / period + 1) * period;
    // One slot into the epoch, so the report is composed against an anchor
    // the node already has and declared for a slot inside the epoch's
    // cohort rather than the previous one's.
    let dist_slot = start + 1;

    // Walk both chains up to the boundary before anything is distributed.
    // A reference chain starts at genesis whatever the clock says, and a
    // report composed on one that has not reached the current epoch fails
    // twice over: the epoch view resolves no core for the node -- `the NUT
    // holds no core there in the epoch view` -- and even once it does, a
    // refine needs a lookup anchor that is not genesis.
    //
    // Not inside the driving loop below, because the distributor composes
    // a lead of slots *before* the slot it sends in, which is earlier than
    // the loop's first slot.
    for slot in start - WALK_SLOTS..start {
        if let Ok(Some(block)) = harness_chain.author_block(slot) {
            node_chain
                .import_nut_block(&block)
                .expect("the node's chain imports the walk");
        }
    }

    let connection = transport
        .connect(
            EndpointConfig {
                genesis_hash: genesis,
                builder: false,
            },
            SigningKey::from([0xc0u8; 32]),
            san_of(NUT_INDEX),
            nut_addr,
        )
        .await
        .expect("the validator connects");
    let sending = tokio::spawn(m2_emu::report_io::spawn_report_sender(
        connection.clone(),
        dist_slot,
        NUT_INDEX as u16,
        Arc::clone(&harness_chain),
        emu.trace(),
        emu.obs(),
        emu.distributed(),
        EMU_INDICES[0] as u16,
    ));

    // Drive the chain until the node has authored a block after the report
    // went out, which is the earliest point the row has anything to say.
    // The clock is virtual, so the slots past that point cost oracle calls
    // and nothing else -- and the loop stops at the first one.
    let mut authored_after = false;
    for slot in start..start + INCLUSION_SLOT_BUDGET {
        at_slot(slot).await;
        match harness_chain.author_block(slot) {
            Ok(Some(block)) => {
                let _ = emu.announce_tx().send(
                    m2_emu::emu::announcement_wire(&block, &harness_chain)
                        .expect("an announcement is built"),
                );
                node_chain
                    .import_nut_block(&block)
                    .expect("the node's chain imports the block");
            }
            // The node's own slot: it authors and publishes, and the
            // emulator fetches what it announced. Importing it here would
            // make the block known and the fetch would never happen.
            Ok(None) => {
                if let Ok(Some(authored)) = node_chain.author_block(slot) {
                    node.publish(authored);
                    authored_after |= slot > dist_slot;
                }
            }
            Err(_) => {}
        }
        if authored_after {
            break;
        }
    }
    // Two more slots so the last block authored is fetched.
    clock::current()
        .sleep(Duration::from_millis(2 * slot_ms()))
        .await;

    let nut_blocks = emu.nut_blocks();
    let nut_blocks = nut_blocks.lock().expect("the NUT blocks").clone();
    let distributed = emu.distributed();
    let distributed = distributed.lock().expect("the distributed reports").clone();

    let ctx = N3Ctx {
        nut_index: NUT_INDEX as u16,
        submissions: Vec::new(),
        shares: Vec::new(),
        reports: Vec::new(),
        answers_sharing: false,
        expected_report_hash: None,
        emulated_peers: EMU_INDICES.iter().map(|&i| i as u16).collect(),
        shared_to_nut: Vec::new(),
        distributed,
        included: nut_blocks
            .iter()
            .flat_map(|nut| {
                let slot = nut.block.header.slot;
                nut.block
                    .extrinsic
                    .guarantees
                    .iter()
                    .map(move |g| n3::IncludedReport {
                        report_hash: g.report.hash().0,
                        slot,
                        core: g.report.core_index,
                    })
            })
            .collect(),
        authored_slots: nut_blocks.iter().map(|n| n.block.header.slot).collect(),
    };

    let obs = emu.obs();
    let obs = obs.lock().expect("the observation log");
    let rows = (n3::n3_ce135_inclusion(&ctx).run)(&obs)
        .into_iter()
        .map(|row| (row.name, row.outcome))
        .collect();

    sending.abort();
    dialing.abort();
    accepting.abort();
    serving.abort();
    drop(connection);
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

#[tokio::test(start_paused = true)]
async fn the_inclusion_check_catches_a_node_that_drops_a_distributed_report() {
    clock::install(Arc::new(VirtualClock::starting_at(1_900_000_000_000)))
        .expect("nothing has read the clock yet");

    let honest = grade_inclusion(SimFault::None).await;
    assert!(
        passed(&honest, "n3_ce135_report_included"),
        "a node that pools what it was sent must include it; it reported {:?}",
        outcomes_of(&honest, "n3_ce135_report_included")
    );

    let dropped = grade_inclusion(SimFault::ReportNotIncluded).await;
    assert!(
        failed(&dropped, "n3_ce135_report_included"),
        "a node that pools nothing must fail the inclusion row; it reported {:?}",
        outcomes_of(&dropped, "n3_ce135_report_included")
    );
}
