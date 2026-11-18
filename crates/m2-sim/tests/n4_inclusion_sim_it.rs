//! Can the N4 inclusion checks fail?
//!
//! `n4_ce141_inclusion` was the last N4 check nobody had seen fail. Its two
//! rows ask whether the node carries the valid assurances its peers send it
//! and leaves the rest out, and until `submit_assurance` was exported from
//! `jam-node` there was no way to find out: the stand-in authors through the
//! reference chain, the chain pools assurances the engine *signs*, and an
//! assurance that arrived from somewhere else had nowhere to go. Both rows
//! passed on every node, conforming or not.
//!
//! Writing it found the rows themselves asking the wrong question
//! (findings.md §14). An assurances extrinsic is refused unless every
//! assurance in it anchors the block's parent, so an assurance can be
//! carried in exactly one block -- the child of the block it names. The rows
//! asked whether *any* later block carried it, and the harness anchored
//! every offer at the last block the NUT had authored, which is almost never
//! the parent of the next one. Together those two would have failed a
//! conforming node on a rule it was keeping.

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
        // An honest assurance claims the cores that carried a report, and
        // none did.
        cores: Vec::new(),
        honest_slot: offers_from,
        assurance_slots: period,
        spoiled_from: offers_from + period / 2,
    });

    // Drive the chain. The harness authors every slot that is not the
    // node's; on the node's own slots it authors and publishes, and the
    // emulator fetches it -- importing it here would make the block known
    // and the fetch would never happen.
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
            Ok(None) => {
                if let Ok(Some(authored)) = node_chain.author_block(slot) {
                    node.publish(authored);
                }
            }
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
    m2_runner::real::resolve_assurance_inclusion(&mut assurances_offered, &nut_blocks);

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
async fn the_inclusion_checks_catch_a_node_that_mishandles_the_assurances_it_is_sent() {
    clock::install(Arc::new(VirtualClock::starting_at(1_800_000_000_000)))
        .expect("nothing has read the clock yet");

    let honest = grade(SimFault::None).await;
    // The run has to reach the rows at all. A window in which the node
    // authored nothing, or authored only blocks nobody had assured the
    // parent of, reports everything unexercised -- which says nothing about
    // the node and would let both rows below pass vacuously.
    assert!(
        !outcomes_of(&honest, "n4_ce141_valid_assurance_included").is_empty(),
        "the window must contain a block the node could have carried an assurance in; \
         it reported {honest:?}"
    );
    assert!(
        passed(&honest, "n4_ce141_valid_assurance_included"),
        "the honest node must carry the assurances it was sent; it reported {:?}",
        outcomes_of(&honest, "n4_ce141_valid_assurance_included")
    );

    // A node that pools nothing. Every honest offer whose child block it
    // authored is one it owed and did not carry.
    let omits = grade(SimFault::AssuranceOmitsValid).await;
    assert!(
        failed(&omits, "n4_ce141_valid_assurance_included"),
        "a node that pools no assurance must fail the inclusion row; it reported {:?}",
        outcomes_of(&omits, "n4_ce141_valid_assurance_included")
    );

    // And one that pools whatever arrives. The spoiled offer -- a wrong
    // anchor, another validator's signature, or a bit for a core carrying
    // nothing, by validator index -- then lands in a block.
    //
    // The wrong-anchor fault cannot reach a block even here: the engine
    // files assurances by anchor and the author reads only the entry for its
    // parent, so a hash nothing was authored on top of is pooled and never
    // carried. That the other two do is what makes the row fail.
    let includes = grade(SimFault::AssuranceIncludesInvalid).await;
    assert!(
        failed(&includes, "n4_ce141_invalid_assurance_excluded"),
        "a node that pools an assurance it should have refused must fail the exclusion \
         row; it reported {:?}",
        outcomes_of(&includes, "n4_ce141_invalid_assurance_excluded")
    );
    // The same node still carries the valid ones, so the two rows are
    // separable: a reader sees a node that checks nothing, not one that is
    // broken in both directions at once.
    assert!(
        passed(&includes, "n4_ce141_valid_assurance_included"),
        "pooling everything must not disturb the inclusion row; it reported {:?}",
        outcomes_of(&includes, "n4_ce141_valid_assurance_included")
    );
    assert!(
        passed(&honest, "n4_ce141_invalid_assurance_excluded"),
        "the honest node must leave the spoiled assurances out; it reported {:?}",
        outcomes_of(&honest, "n4_ce141_invalid_assurance_excluded")
    );

    // The company the exclusion row keeps. An assurances extrinsic carrying
    // a bad signature or a bit for an unengaged core is one the block is
    // invalid for, so the same block fails N1's import row -- and the only
    // way to produce it was to rewrite the authored body, which fails that
    // row by itself as well. Both nodes that author at all keep N1 green
    // unless they are this one.
    assert!(
        failed(&includes, "n1_header_seal_import_ok"),
        "a block carrying an assurance that should have been refused must fail N1's \
         import row; it reported {:?}",
        outcomes_of(&includes, "n1_header_seal_import_ok")
    );
    for rows in [&honest, &omits] {
        assert!(
            passed(rows, "n1_header_seal_import_ok"),
            "a node that only decides what to pool must still author valid blocks; \
             it reported {:?}",
            outcomes_of(rows, "n1_header_seal_import_ok")
        );
    }
}
