//! Can the N3 report-distribution checks fail?
//!
//! CE 135 is the end of guaranteeing and the start of everything after it: a
//! guarantor that has refined a package and collected its co-guarantors'
//! signatures distributes the guaranteed work-report to every validator
//! (`simple.md:460-485`), and some validator puts it on chain. Six rows
//! grade that, and not one of them had ever been seen to fail.
//!
//! The two halves are graded apart because they are two different nodes.
//! This file is `n3_ce135_distribution`, what the node *sends*: the quorum,
//! the order of the signatures, who signed, whether it is the report the
//! reference refined, and whether every validator got it. The other half,
//! what a node does with a report it *receives*, is
//! `n3_ce135_inclusion_sim_it.rs` -- a separate file because the virtual
//! clock is installed once per process and each needs its own timeline.
//!
//! These six are not the last unproven rows in N3. The four CE 134
//! *receive* rows are still in that position: this stand-in opens CE 134
//! and has never been asked to answer one.
//!
//! **What the honest half does and does not prove.** The simulated node does
//! not refine: the test hands it a report the oracle refined, and the node
//! distributes it. So an honest pass on
//! `n3_ce135_report_matches_the_reference` is not evidence that the row
//! would catch a node refining differently -- the fault is. It distributes a
//! second report, well formed and signed by the right cohort, over different
//! items. That is the shape of a node that refined the wrong bundle, and a
//! corrupted report would not be: one of those fails to decode and is caught
//! a step earlier.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use ed25519_consensus::{SigningKey, VerificationKey};
use jam_std_common::{SecretKeyset, WorkReport};
use jamnp_s::cert::san_for_key;
use jamnp_s::clock::{self, VirtualClock};
use jamnp_s::endpoint::EndpointConfig;
use jamnp_s::transport::mock::MockNetwork;
use jamnp_s::transport::Transport;
use m2_reference::chain::RefChain;
use m2_reference::reports::{work_item_with_payload, ScheduledSubmission};
use m2_scenario::dsl::Outcome;
use m2_scenario::scenarios::n3::{self, N3Ctx};
use m2_sim::{GuaranteeOffer, SimFault, SimNode};

/// The simulated node's validator index.
const NUT_INDEX: usize = 2;
const EMU_INDICES: [usize; 5] = [0, 1, 3, 4, 5];
/// The two emulated validators that hold the core with the node, and so the
/// two whose signatures belong on its guarantee.
const CO_GUARANTORS: [u16; 2] = [EMU_INDICES[0] as u16, EMU_INDICES[1] as u16];
/// A validator that does not hold the core, for the stranger fault.
const STRANGER: u16 = EMU_INDICES[2] as u16;
/// The peer index submissions are recorded under: a builder, outside the
/// validator range, so no lane reads this traffic as a validator's.
const BUILDER_PEER: u16 = 64;
const CORE: u16 = 0;
/// Slots to author before refining, to put a recent lookup anchor behind the
/// head. The chain holds every key but the node's, so most of them are its.
const WALK_SLOTS: u32 = 12;
fn san_of(index: usize) -> String {
    let secret = SecretKeyset::trivial(index as u32).ed25519;
    san_for_key(&VerificationKey::from(&SigningKey::from(secret.to_bytes())))
}

/// A submission built by hand rather than refined.
///
/// The node never decodes the package -- it measures the message, takes it,
/// shares it and distributes what the test told it to guarantee. What this
/// has to be is *accepted*, because distribution is what a guarantor does
/// after taking a package and the node does nothing until one arrives.
fn submission(slot: u32) -> ScheduledSubmission {
    ScheduledSubmission {
        slot,
        core: CORE,
        protocol: 133,
        package: vec![0x5a; 1_024],
        package_hash: [0xa5; 32],
        extrinsics: vec![vec![0x01, 0x02], vec![0x03]],
        mappings: Vec::new(),
        segments: Vec::new(),
        import_proofs: Vec::new(),
        fault: None,
        co_guarantors: CO_GUARANTORS.to_vec(),
        exports_root: [0u8; 32],
        exports_count: 0,
        imports_from: None,
    }
}

/// The two reports every distribution run needs, refined once.
///
/// Refining is the most expensive thing the oracle does and a report is a
/// value, so the same two serve every fault. Memoised rather than recomputed
/// per grading run, which would spend six refinements to get two reports.
///
/// The chain is walked to the wall clock first. A reference chain starts at
/// genesis whatever the clock says, and the engine refuses to compose a
/// guarantee for an epoch its state has never reached -- in those words:
/// `invalid epoch N, reference epoch is 0`. One authored block moves it,
/// because authoring may name any slot past the head.
fn reports() -> &'static (WorkReport, WorkReport) {
    static REPORTS: OnceLock<(WorkReport, WorkReport)> = OnceLock::new();
    REPORTS.get_or_init(|| {
        let oracle = m2_reference::oracle::Oracle::for_tests();
        let chain = RefChain::tiny(&oracle, NUT_INDEX).expect("a chain to refine on");
        let from = m2_reference::chain::wall_clock_slot();
        // A run of slots, not one. The first block moves the state into
        // the current epoch; a refine also needs a *lookup anchor* that is
        // not too old, and after a single jump from genesis the only
        // earlier block is genesis itself -- which the engine refuses, in
        // those words: `Failed to build report: lookup anchor too old`.
        let authored = (from..from + WALK_SLOTS)
            .filter(|&slot| matches!(chain.author_block(slot), Ok(Some(_))))
            .count();
        assert!(
            authored > 1,
            "the reference chain must reach the current epoch and leave a recent anchor              behind it before it can refine; it authored {authored} block(s)"
        );
        let honest = chain
            .guarantee_work(vec![work_item_with_payload(b"n3-ce135".to_vec())], CORE)
            .expect("the honest report refines")
            .report;
        let other = chain
            .guarantee_work(
                vec![work_item_with_payload(b"n3-ce135-elsewhere".to_vec())],
                CORE,
            )
            .expect("the second report refines")
            .report;
        assert_ne!(
            honest.hash(),
            other.hash(),
            "the two reports must differ, or the fault poses nothing"
        );
        (honest, other)
    })
}

/// Submit one package to a simulated guarantor and grade what it distributes.
async fn grade_distribution(fault: SimFault) -> Vec<(&'static str, Outcome)> {
    let (honest, other) = reports();
    let expected_report_hash = honest.hash().0;

    let transport = Arc::new(MockNetwork::new()) as Arc<dyn Transport>;
    let oracle = m2_reference::oracle::Oracle::for_tests();
    let harness_chain = Arc::new(RefChain::tiny(&oracle, NUT_INDEX).expect("the harness chain"));
    let node_chain = Arc::new(RefChain::tiny_for(&oracle, NUT_INDEX).expect("the node's chain"));
    let genesis = harness_chain.genesis_hash();

    let node = Arc::new(SimNode::at_index(Arc::clone(&node_chain), fault, NUT_INDEX));
    node.shares_with(&CO_GUARANTORS);
    let slot = m2_reference::chain::wall_clock_slot();
    node.guarantees(GuaranteeOffer {
        report: honest.clone(),
        other: Some(other.clone()),
        // The node and its two co-guarantors, which is who holds the core.
        // Injected rather than derived, for the same reason `shares_with`
        // is: a stand-in that worked the assignment out would be grading
        // the harness against its own arithmetic.
        cohort: {
            let mut cohort = CO_GUARANTORS.to_vec();
            cohort.push(NUT_INDEX as u16);
            cohort
        },
        stranger: STRANGER,
        slot,
    });

    let (nut_addr, serving) = Arc::clone(&node)
        .listen(
            Arc::clone(&transport),
            SigningKey::from([0x90u8; 32]),
            "127.0.0.1:9700".parse::<SocketAddr>().expect("an address"),
        )
        .await
        .expect("the simulated node binds");

    let emu = m2_emu::emu::Emulator::n0_on(
        Arc::clone(&transport),
        EMU_INDICES.to_vec(),
        genesis,
        41_300,
    )
    .await
    .expect("the emulated validators bind");
    let accepting = emu.accept_loop(Arc::clone(&harness_chain));

    // The node dials the validators: CE 134 and CE 135 both go out on the
    // connections it opened. A guarantor with no connection to the set
    // could not distribute whatever it guaranteed.
    let peers: Vec<(u16, SocketAddr, String)> = EMU_INDICES
        .iter()
        .zip(emu.local_addrs())
        .map(|(&index, addr)| (index as u16, addr, san_of(index)))
        .collect();
    node.connect_to(&transport, SigningKey::from([0x91u8; 32]), &peers)
        .await;

    let connection = transport
        .connect(
            EndpointConfig {
                genesis_hash: genesis,
                builder: true,
            },
            SigningKey::from([0xb0u8; 32]),
            san_of(NUT_INDEX),
            nut_addr,
        )
        .await
        .expect("the builder connects");
    m2_emu::report_io::spawn_package_sender(
        connection.clone(),
        submission(slot),
        emu.trace(),
        emu.obs(),
        emu.submissions(),
        BUILDER_PEER,
    )
    .await;
    // The share and the distribution both arrive on streams the node opens,
    // so the sender returning is not the end of the exchange.
    clock::current().sleep(Duration::from_millis(200)).await;
    drop(connection);

    let submissions = emu.submissions();
    let submissions = submissions.lock().expect("the submissions").clone();
    let reports = emu.reports_seen();
    let reports = reports.lock().expect("the reports").clone();

    let ctx = N3Ctx {
        nut_index: NUT_INDEX as u16,
        submissions,
        shares: Vec::new(),
        reports,
        answers_sharing: false,
        expected_report_hash: Some(expected_report_hash),
        emulated_peers: EMU_INDICES.iter().map(|&i| i as u16).collect(),
        shared_to_nut: Vec::new(),
        distributed: Vec::new(),
        included: Vec::new(),
        authored_slots: Vec::new(),
    };

    let obs = emu.obs();
    let obs = obs.lock().expect("the observation log");
    let rows = (n3::n3_ce135_distribution(&ctx).run)(&obs)
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

const DISTRIBUTION_ROWS: [&str; 5] = [
    "n3_ce135_has_enough_signatures",
    "n3_ce135_signatures_sorted",
    "n3_ce135_signers_hold_the_core",
    "n3_ce135_report_matches_the_reference",
    "n3_ce135_reaches_every_validator",
];

#[tokio::test(start_paused = true)]
async fn the_distribution_checks_catch_a_guarantor_that_distributes_wrongly() {
    clock::install(Arc::new(VirtualClock::starting_at(1_800_000_000_000)))
        .expect("nothing has read the clock yet");

    let honest = grade_distribution(SimFault::None).await;
    for row in DISTRIBUTION_ROWS {
        assert!(
            passed(&honest, row),
            "the honest node must pass {row}; it reported {:?}",
            outcomes_of(&honest, row)
        );
    }

    // Each fault, and the row it must cost. Paired rather than asserted one
    // by one so the second half of the loop can say the *other* four rows
    // still passed: a fault that fails everything proves no row in
    // particular.
    for (fault, row) in [
        (
            SimFault::ReportUnderSigned,
            "n3_ce135_has_enough_signatures",
        ),
        (
            SimFault::ReportSignaturesUnsorted,
            "n3_ce135_signatures_sorted",
        ),
        (
            SimFault::ReportStrangerSigns,
            "n3_ce135_signers_hold_the_core",
        ),
        (
            SimFault::ReportIsNotTheReference,
            "n3_ce135_report_matches_the_reference",
        ),
        (
            SimFault::ReportReachesOnePeer,
            "n3_ce135_reaches_every_validator",
        ),
    ] {
        let rows = grade_distribution(fault).await;
        assert!(
            failed(&rows, row),
            "{fault:?} must fail {row}; it reported {:?}",
            outcomes_of(&rows, row)
        );
        for other in DISTRIBUTION_ROWS {
            if other == row {
                continue;
            }
            assert!(
                passed(&rows, other),
                "{fault:?} must leave {other} passing, so a reader sees one hole \
                 rather than a broken node; it reported {:?}",
                outcomes_of(&rows, other)
            );
        }
    }
}
