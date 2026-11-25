//! Can `n4_ce141_invalid_assurance_cost_a_block` fail?
//!
//! The other N4 inclusion faults all leave a block behind to read. This one
//! does not: the node pools an assurance that does not hold, the engine
//! refuses to compose a block past it, and the slot goes empty. "The node
//! authored no block" was the inclusion row's own precondition, so until
//! this row existed the worse failure scored as *not exercised* -- which on
//! a report is indistinguishable from a window that simply missed
//! (`findings.md` §22).
//!
//! A file of its own because the clock is installed once per process and
//! `n4_inclusion_sim_it` already owns it there.

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
const NUT_INDEX: usize = 2;
const EMU_INDICES: [usize; 5] = [0, 1, 3, 4, 5];
/// Epochs the run drives, from a boundary.
///
/// Whole epochs from a boundary rather than a window wherever the clock
/// happens to be, because which slots a validator authors follows from the
/// entropy and rotates every epoch -- and an assurance is carried only by
/// the block authored in the slot it was sent for. The first epoch warms up
/// and the offers go out across the second, where the node has several
/// slots of its own. A window placed at the clock's current position found
/// none of them at all, and reported every row unexercised.
const EPOCHS: u32 = 2;

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

/// Run one availability window against a simulated node and return the rows
/// the inclusion check earned.
async fn grade(fault: SimFault) -> Vec<(&'static str, Outcome)> {
    let transport = Arc::new(MockNetwork::new()) as Arc<dyn Transport>;
    let oracle = m2_reference::oracle::Oracle::for_tests();
    let harness_chain = Arc::new(RefChain::tiny(&oracle, NUT_INDEX).expect("the harness chain"));
    let node_chain = Arc::new(RefChain::tiny_for(&oracle, NUT_INDEX).expect("the node's chain"));
    let genesis = harness_chain.genesis_hash();

    let node = Arc::new(SimNode::at_index(Arc::clone(&node_chain), fault, NUT_INDEX));
    // Nothing has been guaranteed on this chain, so no core carries a
    // report. That is what makes the empty-core fault a fault: an assurance
    // claiming any core at all is claiming one with nothing on it.
    node.reports_on_cores(&[]);

    let (nut_addr, serving) = Arc::clone(&node)
        .listen(
            Arc::clone(&transport),
            SigningKey::from([0x90u8; 32]),
            "127.0.0.1:9800".parse::<SocketAddr>().expect("an address"),
        )
        .await
        .expect("the simulated node binds");

    let emu = m2_emu::emu::Emulator::n0_on(
        Arc::clone(&transport),
        EMU_INDICES.to_vec(),
        genesis,
        40_900,
    )
    .await
    .expect("the emulated validators bind");
    let shared = emu.shared(Arc::clone(&harness_chain));
    let accepting = emu.accept_loop(Arc::clone(&harness_chain));
    // One emulated validator dials the node, which is what drives the N1
    // block fetch: the node announces a block of its own and the harness
    // goes and gets it. Without this nothing ever enters `nut_blocks`, the
    // inclusion rows have no block to read, and every one of them reports
    // unexercised.
    let dialing = tokio::spawn(m2_emu::emu::dial_nut(
        EMU_INDICES[0],
        genesis,
        nut_addr,
        san_of(EMU_INDICES[0]),
        shared,
    ));

    // The node dials, which is also how it learns who is on the other end:
    // this transport carries no peer identity, and CE 141 carries no
    // validator index, so an assurance arriving on a connection the node
    // merely accepted could not be attributed to anyone.
    let peers: Vec<(u16, SocketAddr, String)> = EMU_INDICES
        .iter()
        .zip(emu.local_addrs())
        .map(|(&index, addr)| (index as u16, addr, san_of(index)))
        .collect();
    node.connect_to(&transport, SigningKey::from([0x91u8; 32]), &peers)
        .await;

    let period = jam_types::epoch_period();
    let first_epoch_start = (m2_reference::chain::wall_clock_slot() / period + 1) * period;
    // Offers across the whole of the last epoch, half honest and half
    // spoiled. Either half has to contain a slot the node authors, or its
    // row goes ungraded -- and which slots those are follows from the
    // entropy, not from anything a test can pick.
    let offers_from = first_epoch_start + (EPOCHS - 1) * period;
    emu.avail_planner().set(m2_emu::avail_io::AvailPlan {
        // No bundle is held, so every shard fetch is refused. Those rows are
        // not graded here; `n4_sim_it` is the test that serves shards.
        erasure_root: [0u8; 32],
        segments_root: [0u8; 32],
        shard_count: jam_types::max_val_count(),
        segment_indices: Vec::new(),
        segment_count: 0,
        honest_slot: offers_from,
        assurance_slots: period,
        spoiled_from: offers_from + period / 2,
    });

    // Drive the chain. The harness authors every slot that is not the
    // node's; on the node's own slots it authors and publishes, and the
    // emulator fetches it -- importing it here would make the block known
    // and the fetch would never happen.
    // Slots the node owned and left empty, kept the same way the runner
    // keeps them: the harness could not author, and the node did not.
    let mut lost_slots: Vec<u32> = Vec::new();
    for slot in first_epoch_start..first_epoch_start + EPOCHS * period {
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
            Ok(None) => match node_chain.author_block(slot) {
                Ok(Some(authored)) => node.publish(authored),
                // The node's turn, and no block came out of it. Under
                // `AssuranceCostsTheSlot` that is the engine refusing to
                // compose past a pooled assurance naming an unengaged core
                // -- the same refusal polkajam makes (`findings.md` §22).
                _ => lost_slots.push(slot),
            },
            Err(_) => {}
        }
    }
    // Two more slots so a block authored in the last one is fetched.
    clock::current()
        .sleep(Duration::from_millis(2 * slot_ms()))
        .await;

    let nut_blocks = emu.nut_blocks();
    let nut_blocks = nut_blocks.lock().expect("the NUT blocks").clone();
    let mut assurances_offered = emu
        .assurances_offered()
        .lock()
        .expect("the offered assurances")
        .clone();
    // The runner's own resolution, not a second copy of it: a test that
    // worked out inclusion for itself would be grading its own reading of
    // the rule rather than the one a run applies.
    let lost = m2_runner::real::LostTurns {
        slots: lost_slots,
        chain: harness_chain
            .chain_blocks()
            .unwrap_or_default()
            .iter()
            .map(|block| (block.header.slot, block.header.hash().0))
            .collect(),
    };
    m2_runner::real::resolve_assurance_inclusion(&mut assurances_offered, &nut_blocks, &lost);

    let ctx = N4Ctx {
        nut_index: NUT_INDEX as u16,
        shards_served: Vec::new(),
        segment_shards_served: Vec::new(),
        segments_served: Vec::new(),
        assurances_seen: Vec::new(),
        assurances_offered,
        availability_threshold: jam_types::supermajority_threshold(jam_types::max_val_count()),
        assured_by_core: Vec::new(),
    };

    // N1's import row on the same blocks. A node that carries an assurance
    // it should have refused authors an *invalid* block, so the two fail
    // together -- which is a fact about the protocol worth holding rather
    // than a remark in a comment.
    let deliveries = emu.deliveries();
    let deliveries = deliveries.lock().expect("the deliveries").clone();
    let n1_ctx =
        m2_runner::real::build_n1_ctx(&harness_chain, &nut_blocks, &deliveries, Vec::new())
            .expect("the N1 facts build");
    let n1_rows: Vec<(&'static str, Outcome)> =
        (m2_scenario::scenarios::n1::n1_header_seal(&n1_ctx).run)(&m2_scenario::dsl::ObsLog::new())
            .into_iter()
            .map(|row| (row.name, row.outcome))
            .collect();

    let obs = emu.obs();
    let obs = obs.lock().expect("the observation log");
    let rows = (n4::n4_ce141_inclusion(&ctx).run)(&obs)
        .into_iter()
        .map(|row| (row.name, row.outcome))
        .chain(n1_rows)
        .collect();

    dialing.abort();
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

/// Present **and** failing: a row the grading never produced caught nothing.
fn failed(rows: &[(&'static str, Outcome)], row: &str) -> bool {
    outcomes_of(rows, row)
        .iter()
        .any(|o| matches!(o, Outcome::Fail(_)))
}

/// The failure the lane could not see: the node loses the slot entirely.
///
/// Every other assurance fault leaves a block behind to read. This one does
/// not, and "no block" was the row's own precondition — so until
/// `n4_ce141_invalid_assurance_cost_a_block` existed, a node that answered
/// a peer's false claim by producing nothing scored as *no coverage*, which
/// on a report is indistinguishable from a window that simply missed
/// (`findings.md` §22).
///
/// The stand-in poses it the only way it can be posed: by pooling an
/// assurance that does not hold and letting the engine refuse to compose.
/// That refusal is the engine's own, not something this test simulates —
/// the same refusal polkajam makes, from the same code.
#[tokio::test(start_paused = true)]
async fn an_invalid_assurance_that_costs_the_slot_is_graded_rather_than_skipped() {
    clock::install(Arc::new(VirtualClock::starting_at(1_800_000_000_000)))
        .expect("nothing has read the clock yet");

    let costs = grade(SimFault::AssuranceCostsTheSlot).await;
    assert!(
        failed(&costs, "n4_ce141_invalid_assurance_cost_a_block"),
        "a node that loses its turn to a peer's false claim must fail, not go \
         unexercised; it reported {:?}",
        outcomes_of(&costs, "n4_ce141_invalid_assurance_cost_a_block")
    );

    // The control that makes the row mean something. An honest node authors
    // its slots, so there is no lost turn to attribute and the row must not
    // appear at all -- a row that fired on every run would say nothing.
    let honest = grade(SimFault::None).await;
    assert!(
        outcomes_of(&honest, "n4_ce141_invalid_assurance_cost_a_block").is_empty(),
        "an honest node must not earn the row; it reported {:?}",
        outcomes_of(&honest, "n4_ce141_invalid_assurance_cost_a_block")
    );
}
