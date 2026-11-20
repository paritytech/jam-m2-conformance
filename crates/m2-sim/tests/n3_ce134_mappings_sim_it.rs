//! Can the CE 134 mapping row fail, and can it pass?
//!
//! `n3_ce134_maps_the_imported_package` grades the segments-root mappings a
//! guarantor puts on message 1 of a share. A guarantor may share a package
//! only once "all import segments have been retrieved ... this will involve
//! mapping any WP hashes in the import list to segments-roots"
//! (`simple.md:412-415`), and message 1 carries that resolution to the
//! co-guarantors (`simple.md:449`).
//!
//! The row this replaced asked for the opposite: that the mappings name the
//! package being *shared*. No conforming node could have sent that, and
//! nothing caught it for as long as the row existed, because no package the
//! harness built imported anything and the row never ran against a node of
//! any kind (`findings.md` §27).
//!
//! So this file exists to put all four answers to a node:
//!
//! - the pair a conforming node sends, which must pass;
//! - no mappings at all, which is the defect a node most plausibly has;
//! - a mapping for some other package, which leaves this import unresolved;
//! - the right package under the wrong root, which is worse than none --
//!   `simple.md:444-446` lets the receiving guarantor trust it blindly.
//!
//! The stand-in is *told* what to map, the way it is told what a bundle
//! refines to: it has no chain state to resolve a package hash against. The
//! row does not ask how a node arrived at the pair, only whether the pair
//! it shared is the right one.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ed25519_consensus::{SigningKey, VerificationKey};
use jam_std_common::SecretKeyset;
use jam_types::WorkPackageHash;
use jamnp_s::cert::san_for_key;
use jamnp_s::clock::{self, VirtualClock};
use jamnp_s::endpoint::EndpointConfig;
use jamnp_s::transport::mock::MockNetwork;
use jamnp_s::transport::Transport;
use m2_reference::chain::RefChain;
use m2_reference::reports::ScheduledSubmission;
use m2_scenario::dsl::Outcome;
use m2_scenario::scenarios::n3::{self, N3Ctx};
use m2_sim::{SimFault, SimNode};

const NUT_INDEX: usize = 2;
const EMU_INDICES: [usize; 5] = [0, 1, 3, 4, 5];
const CO_GUARANTORS: [u16; 2] = [0, 1];
const CORE: u16 = 0;
const BUILDER_PEER: u16 = 40;

/// The package the submission imports a segment from, and the root its
/// exports sit under.
const EXPORTER: [u8; 32] = [0x7e; 32];
const EXPORTS_ROOT: [u8; 32] = [0x7f; 32];

fn san_of(index: usize) -> String {
    let secret = SecretKeyset::trivial(index as u32).ed25519;
    san_for_key(&VerificationKey::from(&SigningKey::from(secret.to_bytes())))
}

/// A submission that imports, built by hand rather than refined.
///
/// The node never decodes the package here: it takes the submission and
/// shares what it was told to share. What the row grades is the mappings on
/// that share, and the import is a property of the *record* the lane holds,
/// which the harness fills from the plan it built. Refining a real importing
/// package through the oracle is what
/// `a_work_item_that_imports_resolves_the_package_it_imports_from` covers,
/// and it proves a different thing: that such a package can be built at all.
fn importing_submission(slot: u32) -> ScheduledSubmission {
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
        imports_from: Some(m2_reference::reports::ImportSource {
            package_hash: EXPORTER,
            exports_root: EXPORTS_ROOT,
            index: 0,
        }),
    }
}

/// Submit one importing package and return the rows the mapping check earns.
async fn grade(fault: SimFault) -> Vec<(&'static str, Outcome)> {
    let transport = Arc::new(MockNetwork::new()) as Arc<dyn Transport>;
    let oracle = m2_reference::oracle::Oracle::for_tests();
    let harness_chain = Arc::new(RefChain::tiny(&oracle, NUT_INDEX).expect("the harness chain"));
    let node_chain = Arc::new(RefChain::tiny_for(&oracle, NUT_INDEX).expect("the node's chain"));
    let genesis = harness_chain.genesis_hash();

    let node = Arc::new(SimNode::at_index(Arc::clone(&node_chain), fault, NUT_INDEX));
    node.shares_with(&CO_GUARANTORS);
    node.maps(WorkPackageHash::from(EXPORTER), EXPORTS_ROOT);

    let (nut_addr, serving) = Arc::clone(&node)
        .listen(
            Arc::clone(&transport),
            SigningKey::from([0x96u8; 32]),
            "127.0.0.1:9904".parse::<SocketAddr>().expect("an address"),
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
    let accepting = emu.accept_loop(Arc::clone(&harness_chain));

    let peers: Vec<(u16, SocketAddr, String)> = EMU_INDICES
        .iter()
        .zip(emu.local_addrs())
        .map(|(&index, addr)| (index as u16, addr, san_of(index)))
        .collect();
    node.connect_to(&transport, SigningKey::from([0x97u8; 32]), &peers)
        .await;

    let slot = m2_reference::chain::wall_clock_slot();
    let connection = transport
        .connect(
            EndpointConfig {
                genesis_hash: genesis,
                builder: true,
            },
            SigningKey::from([0xb8u8; 32]),
            san_of(NUT_INDEX),
            nut_addr,
        )
        .await
        .expect("the builder connects");
    m2_emu::report_io::spawn_package_sender(
        connection.clone(),
        importing_submission(slot),
        emu.trace(),
        emu.obs(),
        emu.submissions(),
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        BUILDER_PEER,
    )
    .await;
    // The share arrives on a stream of its own, so the sender returning is
    // not the end of the exchange.
    clock::current().sleep(Duration::from_millis(200)).await;
    drop(connection);

    let submissions = emu.submissions();
    let submissions = submissions.lock().expect("the submissions").clone();
    let shares = emu.sharing_seen();
    let shares = shares.lock().expect("the shares").clone();

    let ctx = N3Ctx {
        nut_index: NUT_INDEX as u16,
        submissions,
        shares,
        reports: Vec::new(),
        answers_sharing: false,
        expected_report_hash: None,
        emulated_peers: EMU_INDICES.iter().map(|&i| i as u16).collect(),
        shared_to_nut: Vec::new(),
        distributed: Vec::new(),
        included: Vec::new(),
        authored_slots: Vec::new(),
    };

    let obs = emu.obs();
    let obs = obs.lock().expect("the observation log");
    let rows = (n3::n3_ce134_mappings(&ctx).run)(&obs)
        .into_iter()
        .map(|row| (row.name, row.outcome))
        .collect();

    accepting.abort();
    serving.abort();
    rows
}

fn outcomes<'a>(rows: &'a [(&str, Outcome)], name: &str) -> Vec<&'a Outcome> {
    rows.iter()
        .filter(|(row, _)| *row == name)
        .map(|(_, outcome)| outcome)
        .collect()
}

const ROW: &str = "n3_ce134_maps_the_imported_package";

/// The honest pair passes and each way of getting it wrong fails.
///
/// One test function, because the clock is installed once per process and
/// each case needs a run of its own. One arrangement, because the positive
/// is what gives the three negatives their meaning: a row that is absent is
/// not a row that passed, and a fault that failed a row nobody reached
/// would prove nothing.
#[tokio::test(start_paused = true)]
async fn the_mapping_row_catches_a_guarantor_that_resolves_an_import_wrongly() {
    clock::install(Arc::new(VirtualClock::starting_at(2_000_000_000_000)))
        .expect("nothing has read the clock yet");

    let honest = grade(SimFault::None).await;
    let graded = outcomes(&honest, ROW);
    assert!(
        !graded.is_empty(),
        "the row must be reached at all, or the faults below prove nothing: {honest:?}"
    );
    assert!(
        graded.iter().all(|outcome| **outcome == Outcome::Pass),
        "a node that maps the package it imported from to its exports-root passes: {honest:?}"
    );

    for fault in [
        // No mappings at all: the defect a node most plausibly has, and the
        // one the row this replaced was structurally unable to report.
        SimFault::SharesNoMapping,
        // Some other package's hash: this import left unresolved.
        SimFault::SharesForeignMapping,
        // The right package under the wrong root, which a receiving
        // guarantor is allowed to trust blindly (`simple.md:444-446`).
        SimFault::SharesWrongSegmentsRoot,
    ] {
        let rows = grade(fault).await;
        let graded = outcomes(&rows, ROW);
        assert!(
            !graded.is_empty(),
            "{fault:?} must still reach the row: {rows:?}"
        );
        assert!(
            graded
                .iter()
                .all(|outcome| matches!(outcome, Outcome::Fail(_))),
            "{fault:?} must fail {ROW}: {rows:?}"
        );
    }
}
