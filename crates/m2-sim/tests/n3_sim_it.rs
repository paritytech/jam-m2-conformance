//! Can the N3 submission checks fail?
//!
//! The CE 133 rows had been graded against a deterministic baseline and
//! against polkajam, which takes a package and shares it correctly. Nothing
//! had ever shown them failing, and the CE 146 rows were not written at all
//! until the codec behind them was found to be a shape model (findings.md
//! §15).
//!
//! The simulated node is a *guarantor* here: it reads a submission, applies
//! the one rule a guarantor must apply before reading the rest of it -- the
//! size cap -- and either takes the package and opens CE 134 to its
//! co-guarantors or resets the stream.
//!
//! The two protocols carry the same package under the same rules, which is
//! the point: a node that takes it over CE 133 and refuses it over CE 146 is
//! a node with a framing defect. What differs is where the cap falls. CE 133
//! carries the core index in the same message as the package and caps the
//! pair at `2 + 200 * 1024`; CE 146 gives the package a message of its own
//! and caps it alone at `200 * 1024`. A node reading either submission as a
//! single value gets both wrong, and the oversize rows are what say so.

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
use m2_reference::reports::{ScheduledSubmission, SubmissionFault};
use m2_scenario::dsl::Outcome;
use m2_scenario::scenarios::n3::{self, N3Ctx};
use m2_sim::{SimFault, SimNode};

/// The simulated node's validator index.
const NUT_INDEX: usize = 2;
const EMU_INDICES: [usize; 5] = [0, 1, 3, 4, 5];
/// The two emulated validators that hold the core with the node, and so the
/// two it is expected to open CE 134 to.
const CO_GUARANTORS: [u16; 2] = [EMU_INDICES[0] as u16, EMU_INDICES[1] as u16];
/// The peer index submissions are recorded under.
///
/// A builder, not a validator: CE 133 and CE 146 are builder-to-guarantor
/// and the index sits outside the validator range so no lane reads this
/// traffic as a validator's.
const BUILDER_PEER: u16 = 64;
const CORE: u16 = 0;

fn san_of(index: usize) -> String {
    let secret = SecretKeyset::trivial(index as u32).ed25519;
    san_for_key(&VerificationKey::from(&SigningKey::from(secret.to_bytes())))
}

/// A submission built by hand rather than refined.
///
/// The node never decodes the package here -- it measures the message and
/// shares what it took -- and the lane correlates by the hash the harness
/// gives it. Refining a real one through the oracle would add minutes to
/// this test and prove something `n3_ce133_submission`'s own tests already
/// cover.
fn submission(protocol: u16, slot: u32, package_len: usize) -> ScheduledSubmission {
    ScheduledSubmission {
        slot,
        core: CORE,
        protocol,
        package: vec![0x5a; package_len],
        package_hash: [0xa5; 32],
        extrinsics: vec![vec![0x01, 0x02], vec![0x03]],
        mappings: Vec::new(),
        segments: Vec::new(),
        import_proofs: Vec::new(),
        fault: None,
        co_guarantors: CO_GUARANTORS.to_vec(),
        exports_root: [0u8; 32],
        exports_count: 0,
        // This test grades the submission rows, not the mapping row. A
        // package that imported here would put the stand-in's mappings in
        // front of every row below it.
        imports_from: None,
    }
}

/// The package size that clears each protocol's cap by one byte.
fn over_cap(protocol: u16) -> usize {
    if protocol == 146 {
        jamnp_s::codec::ce137_148::WORK_PACKAGE_MAX + 1
    } else {
        // CE 133's cap counts the two-byte core index with the package.
        jamnp_s::codec::ce131_136::WORK_PACKAGE_INITIAL_MAX as usize - 1
    }
}

/// Submit an honest package and an oversized one over each protocol, and
/// return the rows the two submission checks earn.
async fn grade(fault: SimFault) -> Vec<(&'static str, Outcome)> {
    let transport = Arc::new(MockNetwork::new()) as Arc<dyn Transport>;
    let oracle = m2_reference::oracle::Oracle::for_tests();
    let harness_chain = Arc::new(RefChain::tiny(&oracle, NUT_INDEX).expect("the harness chain"));
    let node_chain = Arc::new(RefChain::tiny_for(&oracle, NUT_INDEX).expect("the node's chain"));
    let genesis = harness_chain.genesis_hash();

    let node = Arc::new(SimNode::at_index(Arc::clone(&node_chain), fault, NUT_INDEX));
    node.shares_with(&CO_GUARANTORS);

    let (nut_addr, serving) = Arc::clone(&node)
        .listen(
            Arc::clone(&transport),
            SigningKey::from([0x90u8; 32]),
            "127.0.0.1:9900".parse::<SocketAddr>().expect("an address"),
        )
        .await
        .expect("the simulated node binds");

    let emu = m2_emu::emu::Emulator::n0_on(
        Arc::clone(&transport),
        EMU_INDICES.to_vec(),
        genesis,
        41_100,
    )
    .await
    .expect("the emulated validators bind");
    let accepting = emu.accept_loop(Arc::clone(&harness_chain));

    // The node dials the validators, which is the path its CE 134 shares go
    // out on. A guarantor that had no connection to its co-guarantors could
    // not share whatever it decided.
    let peers: Vec<(u16, SocketAddr, String)> = EMU_INDICES
        .iter()
        .zip(emu.local_addrs())
        .map(|(&index, addr)| (index as u16, addr, san_of(index)))
        .collect();
    node.connect_to(&transport, SigningKey::from([0x91u8; 32]), &peers)
        .await;

    let slot = m2_reference::chain::wall_clock_slot();
    for (i, (protocol, package_len)) in [
        (133u16, 1_024usize),
        (133, over_cap(133)),
        (146, 1_024),
        (146, over_cap(146)),
    ]
    .into_iter()
    .enumerate()
    {
        let mut plan = submission(protocol, slot, package_len);
        if package_len > 1_024 {
            plan.fault = Some(SubmissionFault::Oversized);
        }
        // A connection per submission, as a real builder uses: they are a
        // rotation apart in a run, and one held open across that gap would
        // be relying on QUIC keeping an idle connection alive.
        let connection = transport
            .connect(
                EndpointConfig {
                    genesis_hash: genesis,
                    builder: true,
                },
                SigningKey::from([0xb0u8 + i as u8; 32]),
                san_of(NUT_INDEX),
                nut_addr,
            )
            .await
            .expect("the builder connects");
        m2_emu::report_io::spawn_package_sender(
            connection.clone(),
            plan,
            emu.trace(),
            emu.obs(),
            emu.submissions(),
            BUILDER_PEER,
        )
        .await;
        // The share the node opens in reply arrives on its own stream, so
        // the sender returning is not the end of the exchange.
        clock::current().sleep(Duration::from_millis(200)).await;
        drop(connection);
    }

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
    let rows = [n3::n3_ce133_submission(&ctx), n3::n3_ce146_submission(&ctx)]
        .into_iter()
        .flat_map(|check| (check.run)(&obs))
        .map(|row| (row.name, row.outcome))
        .collect();

    accepting.abort();
    serving.abort();
    rows
}

/// Submit a package for a core the node does not hold, then an honest one,
/// and grade whether the node is credited with ignoring the first.
///
/// The arrangement is the point. `n3_ce133_not_a_guarantor_ignored` asks
/// what the node did *not* do, and a run where nothing else is shared
/// cannot tell a node that ignored the package from one the harness never
/// looked past. An honest submission behind it supplies shares the node was
/// right to make, and a lane that attributes them to the misaddressed
/// submission fails a node that did everything right -- which is how both
/// silence rows came to be unpassable (`findings.md` §18).
async fn grade_misaddressed(fault: SimFault) -> Vec<(&'static str, Outcome)> {
    let transport = Arc::new(MockNetwork::new()) as Arc<dyn Transport>;
    let oracle = m2_reference::oracle::Oracle::for_tests();
    let harness_chain = Arc::new(RefChain::tiny(&oracle, NUT_INDEX).expect("the harness chain"));
    let node_chain = Arc::new(RefChain::tiny_for(&oracle, NUT_INDEX).expect("the node's chain"));
    let genesis = harness_chain.genesis_hash();

    let node = Arc::new(SimNode::at_index(Arc::clone(&node_chain), fault, NUT_INDEX));
    node.shares_with(&CO_GUARANTORS);
    // The one test that tells the node which core is its own, because it is
    // the one that submits to another.
    node.guards_core(CORE);

    let (nut_addr, serving) = Arc::clone(&node)
        .listen(
            Arc::clone(&transport),
            SigningKey::from([0x94u8; 32]),
            "127.0.0.1:9902".parse::<SocketAddr>().expect("an address"),
        )
        .await
        .expect("the simulated node binds");

    let emu = m2_emu::emu::Emulator::n0_on(
        Arc::clone(&transport),
        EMU_INDICES.to_vec(),
        genesis,
        41_200,
    )
    .await
    .expect("the emulated validators bind");
    let accepting = emu.accept_loop(Arc::clone(&harness_chain));

    let peers: Vec<(u16, SocketAddr, String)> = EMU_INDICES
        .iter()
        .zip(emu.local_addrs())
        .map(|(&index, addr)| (index as u16, addr, san_of(index)))
        .collect();
    node.connect_to(&transport, SigningKey::from([0x95u8; 32]), &peers)
        .await;

    let slot = m2_reference::chain::wall_clock_slot();
    // The misaddressed one first, the honest one after it: the order a run
    // uses, and the order in which the bug shows.
    for (i, posed) in [Some(SubmissionFault::NotAGuarantor), None]
        .into_iter()
        .enumerate()
    {
        let mut plan = submission(133, slot, 1_024);
        if posed.is_some() {
            // The core the node does not hold. Two cores under `tiny`, so
            // there is exactly one other.
            plan.core = (CORE + 1) % jam_types::core_count();
        }
        plan.fault = posed;
        let connection = transport
            .connect(
                EndpointConfig {
                    genesis_hash: genesis,
                    builder: true,
                },
                SigningKey::from([0xc0u8 + i as u8; 32]),
                san_of(NUT_INDEX),
                nut_addr,
            )
            .await
            .expect("the builder connects");
        m2_emu::report_io::spawn_package_sender(
            connection.clone(),
            plan,
            emu.trace(),
            emu.obs(),
            emu.submissions(),
            BUILDER_PEER,
        )
        .await;
        // Long enough for the share the node opens in reply to arrive, and
        // for the two submissions to carry different wall-clock stamps.
        clock::current().sleep(Duration::from_millis(200)).await;
        drop(connection);
    }

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
    let rows = (n3::n3_ce133_submission(&ctx).run)(&obs)
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

#[tokio::test(start_paused = true)]
async fn the_submission_checks_catch_a_guarantor_that_mishandles_a_package() {
    clock::install(Arc::new(VirtualClock::starting_at(1_800_000_000_000)))
        .expect("nothing has read the clock yet");

    let honest = grade(SimFault::None).await;
    for protocol in [133, 146] {
        for row in [
            format!("n3_ce{protocol}_accepted"),
            format!("n3_ce{protocol}_shares_with_both_co_guarantors"),
            format!("n3_ce{protocol}_shares_within_the_window"),
            format!("n3_ce{protocol}_oversized_reset"),
        ] {
            assert!(
                passed(&honest, &row),
                "the honest node must pass {row}; it reported {:?}",
                outcomes_of(&honest, &row)
            );
        }
    }

    // A node that takes no work at all.
    let refuses = grade(SimFault::RefusesPackages).await;
    for protocol in [133, 146] {
        assert!(
            failed(&refuses, &format!("n3_ce{protocol}_accepted")),
            "a node that resets every submission must fail CE {protocol}'s acceptance row; \
             it reported {:?}",
            outcomes_of(&refuses, &format!("n3_ce{protocol}_accepted"))
        );
    }

    // The cap, which is the one rule a guarantor must apply before reading
    // the rest of the submission.
    let oversized = grade(SimFault::AcceptsOversizedPackage).await;
    for protocol in [133, 146] {
        assert!(
            failed(&oversized, &format!("n3_ce{protocol}_oversized_reset")),
            "a node that takes an over-cap package must fail CE {protocol}'s oversize row; \
             it reported {:?}",
            outcomes_of(&oversized, &format!("n3_ce{protocol}_oversized_reset"))
        );
        // And it is only that row: the honest package is still taken and
        // still shared, so a reader sees a node with one hole rather than a
        // node that is broken.
        assert!(
            passed(&oversized, &format!("n3_ce{protocol}_accepted")),
            "taking the oversized package must not disturb CE {protocol}'s acceptance row; \
             it reported {:?}",
            outcomes_of(&oversized, &format!("n3_ce{protocol}_accepted"))
        );
    }

    // Sharing with one co-guarantor instead of both.
    let half = grade(SimFault::SharesWithOneCoGuarantor).await;
    for protocol in [133, 146] {
        assert!(
            failed(
                &half,
                &format!("n3_ce{protocol}_shares_with_both_co_guarantors")
            ),
            "a node that opens CE 134 to one co-guarantor must fail CE {protocol}'s \
             sharing row; it reported {:?}",
            outcomes_of(
                &half,
                &format!("n3_ce{protocol}_shares_with_both_co_guarantors")
            )
        );
    }

    // A package for a core the node does not hold, with an honest
    // submission behind it. Both halves matter: the honest node must be
    // credited with ignoring it even though it shared the next one, and
    // the node that shares it anyway must be caught.
    let ignored = grade_misaddressed(SimFault::None).await;
    assert!(
        passed(&ignored, "n3_ce133_not_a_guarantor_ignored"),
        "a node that ignores a package for a core it does not hold must pass the silence \
         row, whatever it shared for the submission after it; it reported {:?}",
        outcomes_of(&ignored, "n3_ce133_not_a_guarantor_ignored")
    );
    assert!(
        passed(&ignored, "n3_ce133_shares_with_both_co_guarantors"),
        "and the honest submission behind it must still be graded; it reported {:?}",
        outcomes_of(&ignored, "n3_ce133_shares_with_both_co_guarantors")
    );

    let shared = grade_misaddressed(SimFault::SharesForeignCore).await;
    assert!(
        failed(&shared, "n3_ce133_not_a_guarantor_ignored"),
        "a node that shares a package for a core it does not hold must fail the silence \
         row; it reported {:?}",
        outcomes_of(&shared, "n3_ce133_not_a_guarantor_ignored")
    );
}
