//! The §4 run lifecycle, orchestrated by [`crate::cli::run`].

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

use jamnp_s::cert::san_for_key;
use m2_emu::emu::Emulator;
use m2_reference::chain::RefChain;
use m2_reference::tickets::{
    first_delivery_slot, window_can_exercise_forwarding, ScheduledTicket, TicketCtx, TicketDelivery,
};
use m2_scenario::dsl::ObsKind;
use m2_scenario::scenarios::n0;

use crate::cli::{Cli, Preset};
use crate::connectivity::{self, ConnectivityPlan, ProbeOutcome};
use crate::keygen;
use crate::launch::{self, LaunchConfig, NutProcess};
use crate::real::{
    build_real_run_ctx, generate_tickets, plans_by_peer, schedule_tickets, EpochContexts,
    RealRunData,
};
use crate::report::{self, Finding};
use crate::scenario::{evaluate, fabricated_obs_log, fabricated_run_ctx, Evaluation, ObsSource};
use crate::spec;

/// How often the runner re-reads the node's advertised finalized slot while
/// waiting for it to be able to accept tickets.
const NODE_READINESS_POLL_MS: u64 = 250;

/// How many emulated slots the dry-run baseline pretends were authored.
const DRY_RUN_BLOCK_COUNT: usize = 3;

/// Errors from a run, mapped to exit codes (startup = 1, internal = 2).
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// The NUT failed to start or never came up (§4 step 2).
    #[error("NUT startup failure: {0}")]
    Startup(String),
    /// Any other internal failure (keygen/spec/emulator/report).
    #[error("internal error: {0}")]
    Internal(String),
}

/// Run a full §4 lifecycle, returning the scenario evaluation or an error.
pub(crate) async fn run_once(cli: Cli) -> Result<Evaluation, RunError> {
    let session_dir = &cli.session_dir;
    report::ensure_layout(session_dir).map_err(internal)?;

    // Before anything reads a protocol parameter. `current_epoch_start_slot`
    // divides by `epoch_period`, and under the process-wide default that is
    // 600 rather than the tiny set's 12 -- which anchored genesis 336 slots in
    // the past instead of at most 11. The node then had to import and finalize
    // a month of chain before it would accept a ticket, and the whole ticket
    // plan was delivered into that window and rejected with "finality
    // lagging". Everything downstream applies these too; this call is the one
    // that happens first.
    jam_types::ProtocolParameters::tiny()
        .apply()
        .map_err(|e| internal(format!("failed to apply tiny protocol parameters: {e}")))?;

    // §4.1 keys + spec.
    let nut_index = cli.validator_index;
    let keys = keygen::generate(cli.seed, nut_index, VALIDATOR_COUNT);
    keygen::write_seed_files(session_dir, &keys).map_err(internal)?;

    let ips = loopback_ips();
    let ports: Vec<u16> = (0..VALIDATOR_COUNT)
        .map(|i| cli.base_port + i as u16)
        .collect();
    // Genesis is anchored to the start of the current epoch (A9). polkajam
    // gates its ticket lottery on the finalized block being in the current
    // epoch, which a genesis at slot 0 can never satisfy, so the node would
    // never submit a ticket and never author.
    //
    // The oracle is started first because the dev genesis both specs are
    // patched from comes out of it: the bootstrap-service blob it is built
    // around lives inside polkajam's node crate, which this workspace does
    // not depend on. It runs for the length of the run and dies with this
    // handle.
    let oracle = m2_reference::oracle::Oracle::spawn(session_dir).map_err(internal)?;
    let anchor_slot = m2_reference::chain::current_epoch_start_slot();
    let chain_spec = spec::tiny_spec(&oracle, &ips, &ports, anchor_slot).map_err(internal)?;
    let genesis_hash = chain_spec.genesis_hash();
    let spec_id = format!("m2-{}", cli.seed);
    let m2_spec = spec::m2_spec(&spec_id, &chain_spec).map_err(internal)?;
    let m2_spec_path = spec::write_m2_spec(session_dir, &spec_id, &m2_spec).map_err(internal)?;
    let spec_path = spec::write_polkajam_spec(session_dir, &chain_spec).map_err(internal)?;

    let nut_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, cli.base_port + nut_index as u16));
    let nut_san = san_for_key(&keys.keysets[nut_index].ed25519.0.verification_key());

    // §4.2 launch + startup probe, §4.3 connectivity (both skipped in dry-run).
    let emu_indices = emulated_indices(nut_index);
    let emu_keys: Vec<[u8; 32]> = emu_indices
        .iter()
        .map(|&i| keys.keysets[i].ed25519.0.verification_key().to_bytes())
        .collect();
    let nut_key = keys.keysets[nut_index]
        .ed25519
        .0
        .verification_key()
        .to_bytes();
    let plan = connectivity::plan_connectivity(&emu_keys, &nut_key);

    // The reference chain is built here so the connectivity phase can serve
    // from it, but ticket generation deliberately is *not* started alongside
    // it. A ring-VRF ticket is sealed against the tickets entropy read from
    // the chain head, and at this point the chain is still at its anchored
    // genesis: tickets proved now carry genesis entropy, while the node
    // validates them against the entropy of the epoch the run is actually in.
    // They never match, and the node rejects every one with "invalid ticket
    // signature" -- which is what it did, silently, for as long as the ticket
    // plan existed. Generation happens after seeding instead; with the
    // dependencies optimized it costs about three seconds, so there is nothing
    // left to overlap with the node's startup.
    //
    // Opened on the very file the node under test is started from, rather
    // than on a second build from the same inputs. The two builds were
    // deterministic and did agree, but agreeing by construction is better
    // than agreeing by argument: the anchor slot is in the genesis header
    // preimage, so any drift between them would move the genesis hash and
    // break every UP 0 handshake in the run.
    let reference = if cli.dry_run {
        None
    } else {
        Some(Arc::new(
            RefChain::with_spec(&oracle, nut_index, &spec_path).map_err(internal)?,
        ))
    };

    let mut nut: Option<NutProcess> = None;
    let mut conn_findings: Vec<Finding> = Vec::new();
    // N0 facts the connectivity phase establishes. A dry run leaves them at
    // the conforming values, since it fabricates a conforming node.
    let mut handshake_completed = true;
    let mut wrong_alpn_rejected = true;
    let mut builder: Option<n0::BuilderProbeFacts> = Some(n0::BuilderProbeFacts {
        attempted: connectivity::BUILDER_CONNECTIONS,
        accepted: connectivity::BUILDER_CONNECTIONS,
        ce133_accepted: true,
        ce133_detail: None,
    });
    if !cli.dry_run {
        let cfg = launch_config(&keys, &cli, spec_path, m2_spec_path);
        // The peer-id is the 53-char text form ("e" + base32 of the Ed25519
        // key) — the same string as the certificate SAN.
        let peer_id = nut_san.clone();
        let image = std::env::var("JAM_M2_IMAGE").unwrap_or_else(|_| "polkajam".to_string());
        let cmd = match cli.preset {
            Preset::Polkajam => launch::preset_polkajam(&cfg).replace("{peer-id}", &peer_id),
            Preset::Docker => launch::preset_docker(&cfg).replace("{image}", &image),
            Preset::Mock => "sleep 30".to_string(),
        };
        nut = Some(launch::spawn(&cmd, session_dir).await.map_err(startup)?);
        if !wait_for_nut(nut_addr, &nut_san, genesis_hash, cli.startup_timeout).await {
            if let Some(nut) = nut.take() {
                let _ = launch::kill(nut).await;
            }
            return Err(RunError::Startup(format!(
                "NUT did not come up on {nut_addr} within {}s",
                cli.startup_timeout
            )));
        }

        let emu_addrs: Vec<SocketAddr> = emu_indices
            .iter()
            .map(|&i| SocketAddr::from((Ipv4Addr::LOCALHOST, cli.base_port + i as u16)))
            .collect();
        let outcomes =
            connectivity::run_connectivity(&plan, nut_addr, &emu_addrs, genesis_hash, &nut_san)
                .await;
        conn_findings = connectivity_findings(&plan, &outcomes);
        handshake_completed = outcomes.iter().any(|o| o.connected);
        // Both before the emulator starts: the builder probe opens twenty-one
        // connections and the mismatch probe deliberately fails one, and
        // neither should be in flight while the preferred-initiator split is
        // being observed.
        wrong_alpn_rejected = connectivity::probe_wrong_alpn(
            nut_addr,
            &nut_san,
            genesis_hash,
            connectivity::INITIATOR_GRACE,
        )
        .await;
        let probe = connectivity::probe_builder_slots(
            nut_addr,
            &nut_san,
            genesis_hash,
            connectivity::INITIATOR_GRACE,
        )
        .await;
        builder = Some(n0::BuilderProbeFacts {
            attempted: probe.attempted,
            accepted: probe.accepted,
            ce133_accepted: probe.ce133_accepted,
            ce133_detail: probe.ce133_detail,
        });
    }

    // §4.4 scenario: reference chain + emulator, or the fabricated dry-run log.
    let (source, reference_block_count, dial_tasks, real_run) = if cli.dry_run {
        (
            ObsSource::Fabricated {
                log: fabricated_obs_log(DRY_RUN_BLOCK_COUNT),
                trace: jamnp_s::trace::Trace::default(),
            },
            DRY_RUN_BLOCK_COUNT,
            Vec::new(),
            None,
        )
    } else {
        let ref_chain = reference.expect("a live run builds the reference chain");
        // Seeded before the node is given anything to sync from: every slot
        // between genesis and now has to be filled for the chain to be
        // current, and the entropy the tickets are later proved against is
        // read from its head.
        let t = std::time::Instant::now();
        seed_past_slots(&ref_chain).map_err(internal)?;
        phase("seed_past_slots", t);
        let epoch_contexts: EpochContexts = Arc::new(Mutex::new(Vec::new()));
        let emu = Emulator::n0(emu_indices.clone(), genesis_hash, cli.base_port)
            .await
            .map_err(internal)?;
        let obs = emu.obs();
        let trace = emu.trace();
        let nut_blocks = emu.nut_blocks();
        let deliveries = emu.deliveries();
        let shared = emu.shared(Arc::clone(&ref_chain));
        let _accept = emu.accept_loop(ref_chain.clone());
        // Drive the preferred-initiator connectivity: emulated validators that
        // are the preferred initiator dial the NUT now; the rest wait the 5 s
        // grace then dial anyway (a soft finding).
        //
        // Keep authoring for the whole observation window, announcing each
        // block as its slot arrives (A10). Aborted with the dial tasks when the
        // window closes.
        let mut dial_tasks = vec![tokio::spawn(drive_slots(
            Arc::clone(&ref_chain),
            emu.announce_tx(),
            Arc::clone(&epoch_contexts),
        ))];
        for &i in &plan.initiate_now {
            let shared = shared.clone();
            let nut_san = nut_san.clone();
            let index = emu_indices[i];
            dial_tasks.push(tokio::spawn(async move {
                hold_connection(index, genesis_hash, nut_addr, nut_san, shared).await;
            }));
        }
        for &i in &plan.wait_then_connect {
            let shared = shared.clone();
            let nut_san = nut_san.clone();
            let index = emu_indices[i];
            dial_tasks.push(tokio::spawn(async move {
                jamnp_s::clock::current()
                    .sleep(connectivity::INITIATOR_GRACE)
                    .await;
                // The NUT is the preferred initiator for this peer. The grace
                // is there so the pair still connects if it never dials, not
                // so we open a second connection alongside its first.
                let peer = index as u16;
                if !connectivity::should_fallback_dial(&lock(&shared.obs), peer) {
                    return;
                }
                m2_emu::emu::record(&shared.obs, peer, ObsKind::Other(n0::FALLBACK_DIAL));
                hold_connection(index, genesis_hash, nut_addr, nut_san, shared).await;
            }));
        }
        // Only now is the plan laid out. Until the node has imported and
        // finalized the chain it was just handed it refuses every ticket, so
        // the sender holds them back (`ticket_io::node_can_accept_tickets`)
        // -- and a schedule written before that hold is a schedule of
        // intentions. `sessions/fwd-1` planned its one proxied ticket for
        // phase 2 and the gate released it in phase 7, past any forwarding
        // window, with the plan none the wiser. Planning against a node that
        // can already accept makes the slots the schedule names the slots the
        // tickets arrive in.
        // The same readiness gate serves the package lane. A node still
        // importing the chain it was handed is not guaranteeing anything
        // either, and a submission aimed at a slot it spends catching up in
        // would grade it for work it was never in a position to do.
        if cli.lanes.needs_package() && !cli.lanes.needs_tickets() {
            let t = std::time::Instant::now();
            wait_until_the_node_can_accept_tickets(&shared, cli.observe_secs).await;
            phase("readiness_gate", t);
        }
        let t_tickets = std::time::Instant::now();
        let (ticket_ctx, ticket_plan, target_epoch) = if cli.lanes.needs_tickets() {
            wait_until_the_node_can_accept_tickets(&shared, cli.observe_secs).await;
            plan_tickets_for_this_run(&ref_chain, nut_index)
                .await
                .map_err(internal)?
        } else {
            // Neither ticket lane was asked for. Proving a plan nothing will
            // grade costs the most expensive seconds in the run, and waiting
            // for the node to be able to accept tickets costs more still.
            (ref_chain.ticket_ctx().map_err(internal)?, Vec::new(), 0)
        };
        phase("ticket_plan", t_tickets);
        // Counted from the chain rather than from the seeding: by now
        // `drive_slots` has added blocks of its own, and the N0 lane compares
        // this against the reference chain the contexts are built from, which
        // has to be the same chain.
        let count = ref_chain
            .chain_blocks()
            .map_err(internal)?
            .len()
            .saturating_sub(1);
        if cli.lanes.needs_tickets() && ticket_plan.is_empty() {
            conn_findings.push(empty_ticket_plan_finding(&ref_chain, target_epoch));
        }
        // Each emulated validator's tickets go out on the connection to it,
        // whichever side opened it; the senders pick the plan up from here.
        emu.set_ticket_plans(plans_by_peer(&ticket_plan));
        if cli.lanes.needs_package() {
            let t = std::time::Instant::now();
            // The lane aims one epoch ahead, and the epoch view can only
            // answer for the cached epoch and the one after it. While the
            // cache trails the head by more than an epoch the target
            // resolves to nothing and the run exercises nothing at all --
            // which is what a third of runs did.
            //
            // The cache advances on finalization, so this waits for it to
            // catch up rather than planning against a view that cannot see
            // where the submission is going.
            wait_for_the_epoch_view_to_catch_up(&ref_chain, cli.observe_secs).await;
            // Aiming into the next epoch can mean waiting most of one, so a
            // window that closes first leaves the lane unexercised with
            // nothing to say why.
            let wait_secs = u64::from(
                (ref_chain.next_slot() / jam_types::epoch_period() + 1) * jam_types::epoch_period()
                    - ref_chain.next_slot(),
            ) * m2_scenario::ctx::SLOT_PERIOD_MS
                / 1000;
            if wait_secs + MIN_SECS_AFTER_SUBMISSION > cli.observe_secs {
                conn_findings.push(short_window_finding(wait_secs, cli.observe_secs));
            }
            match plan_package_for_this_run(&ref_chain, nut_index) {
                Ok(plan) => {
                    // The honest submission leads the plan; the report is
                    // distributed in its slot.
                    let honest_slot = plan.first().map(|p| p.slot).unwrap_or_default();
                    // The report to be included rides the same slot plan: it
                    // is guaranteed on a core the NUT does not hold, so the
                    // two never collide.
                    let t_dist = std::time::Instant::now();
                    match ref_chain.report_to_distribute(
                        // A different payload from the submission's, or the
                        // two are the same package and the node refuses the
                        // second as a duplicate.
                        vec![m2_reference::reports::work_item_with_payload(
                            b"n3-distributed".to_vec(),
                        )],
                        nut_index as u16,
                        honest_slot,
                    ) {
                        Ok(Some(report)) => {
                            eprintln!(
                                "[assignment] distributing report on core {} in slot {}",
                                report.core, report.slot
                            );
                            emu.set_report_plan(report)
                        }
                        // One core, or no assignment: the inclusion row says
                        // it was not exercised rather than failing the node.
                        Ok(None) => eprintln!(
                            "[assignment] no report to distribute: the NUT holds no core at \
                             slot {} in the epoch view, or there is only one core",
                            honest_slot
                        ),
                        Err(e) => conn_findings.push(no_package_plan_finding(&e)),
                    }
                    phase("plan_package.report_to_distribute", t_dist);
                    // The harness also shares a bundle *to* the node, so
                    // the node does the refining for once. A rotation after
                    // the last submission, so the two never contend.
                    let share_base =
                        honest_slot + SUBMISSION_SPACING_SLOTS * (plan.len() as u32 + 1);
                    let mut shares = Vec::new();
                    for (i, fault) in [
                        None,
                        Some(m2_reference::reports::ShareFault::WrongShardCount),
                    ]
                    .into_iter()
                    .enumerate()
                    {
                        let slot = share_base + SUBMISSION_SPACING_SLOTS * i as u32;
                        match ref_chain.share_to_nut(nut_index as u16, slot, fault) {
                            Ok(Some(share)) => shares.push(share),
                            // Said rather than dropped, the same as the
                            // sibling above. A run where no share could be
                            // planned grades the CE 134 receive rules as
                            // unexercised, and a reader looking at a report
                            // with nothing in those rows needs to know the
                            // harness never asked -- not be left to guess
                            // whether the node stayed silent.
                            Ok(None) => eprintln!(
                                "[assignment] no bundle to share at slot {slot}: the NUT holds \
                                 no core there in the epoch view"
                            ),
                            Err(e) => conn_findings.push(no_package_plan_finding(&e)),
                        }
                    }
                    emu.set_share_plan(shares);
                    emu.set_submission_plan(plan);
                    // CE 133 is builder -> guarantor, so it goes out over a
                    // builder connection of its own rather than riding an
                    // emulated validator's. polkajam hands out direct
                    // submission slots by peer role, and a validator gets
                    // none: the first real run was refused with `TooMany`,
                    // the per-peer concurrency limit, having never been
                    // offered a slot at all.
                    let shared_for_builder = shared.clone();
                    let san = nut_san.clone();
                    dial_tasks.push(tokio::spawn(async move {
                        submit_as_builder(nut_addr, san, genesis_hash, shared_for_builder).await;
                    }));
                }
                // A run that cannot plan a submission still grades every
                // other lane; N3 reports the rule as unexercised rather than
                // failing the node for the harness's inability to ask.
                Err(e) => conn_findings.push(no_package_plan_finding(&e)),
            }
            phase("plan_package", t);
        }
        let submissions = emu.submissions();
        let sharing_answer = emu.sharing_answer();
        let distributed = emu.distributed();
        let shared_to_nut = emu.shared_to_nut();
        let sharing_seen = emu.sharing_seen();
        let reports_seen = emu.reports_seen();
        let ce128_probes = emu.ce128_probes();
        let ce129_probes = emu.ce129_probes();
        let shards_served = emu.shards_served();
        let segment_shards_served = emu.segment_shards_served();
        let segments_served = emu.segments_served();
        let assurances_seen = emu.assurances_seen();
        let assurances_offered = emu.assurances_offered();
        let avail_shard_count = Arc::new(Mutex::new(None));
        if cli.lanes.needs_availability() {
            // The one plan that cannot be written before the run. Its
            // erasure root is the one the NUT published in a report it
            // guaranteed, so it exists only once the node has guaranteed
            // something -- and a root the harness guaranteed instead would
            // be one the node is right to answer `NoData` for.
            let reports = Arc::clone(&reports_seen);
            let shard_count = Arc::clone(&avail_shard_count);
            let planner = emu.avail_planner();
            let budget = cli.observe_secs;
            dial_tasks.push(tokio::spawn(async move {
                plan_availability(reports, shard_count, planner, budget).await;
            }));
        }
        let real_run = RealRunData {
            ref_chain,
            nut_blocks,
            deliveries,
            ticket_ctx,
            plan: ticket_plan,
            target_epoch,
            nut_index,
            emu_indices: emu_indices.clone(),
            epoch_contexts,
            submissions,
            sharing_seen,
            reports_seen,
            sharing_answer,
            distributed,
            shared_to_nut,
            shards_served,
            segment_shards_served,
            segments_served,
            assurances_seen,
            assurances_offered,
            avail_shard_count,
        };
        (
            ObsSource::Emulator {
                obs,
                trace,
                ce128_probes,
                ce129_probes,
                emu: Box::new(emu),
            },
            count,
            dial_tasks,
            Some(real_run),
        )
    };

    if !dial_tasks.is_empty() {
        let t = std::time::Instant::now();
        jamnp_s::clock::current()
            .sleep(Duration::from_secs(cli.observe_secs))
            .await;
        phase("observation_window", t);
    }
    // Abort rather than drop: dropping a `JoinHandle` detaches the task, so the
    // slot driver would keep authoring into the reference chain while the
    // checks read it, and two runs of the same log could disagree.
    for task in &dial_tasks {
        task.abort();
    }
    drop(dial_tasks);

    // Read before the teardown, not at report time: what follows ends every
    // remaining connection, and an end recorded then is the harness closing
    // up shop rather than anything the node decided (`findings.md` §29).
    let connection_ends = match &source {
        ObsSource::Emulator { emu, .. } => emu.connection_ends(),
        ObsSource::Fabricated { .. } => Vec::new(),
    };

    // A report nobody claimed never went out, and `n3_ce135_inclusion`
    // reports that the same way it reports a node that ignored one it was
    // sent. Only one validator in the cohort may distribute it, so a plan
    // still sitting here means the run never had a connection to that
    // validator -- a fact about the run's topology, not about the node.
    if let ObsSource::Emulator { emu, .. } = &source {
        if let Some(plan) = emu.unclaimed_report_plan() {
            eprintln!(
                "[distributor] the report for slot {} was never distributed: no connection to \
                 validator {}, the only member of core {}'s cohort that may send it",
                plan.slot, plan.sender, plan.core
            );
        }
    }

    let t_ctx = std::time::Instant::now();
    let run_ctx = match &source {
        ObsSource::Emulator {
            trace,
            ce128_probes,
            ce129_probes,
            ..
        } => {
            let data = real_run.as_ref().ok_or_else(|| {
                RunError::Internal("emulator run missing reference run data".into())
            })?;
            // Everything after genesis, in slot order: what an ascending
            // CE 128 walk from genesis is supposed to return.
            let reference_chain: Vec<[u8; 32]> = data
                .ref_chain
                .chain_blocks()
                .map_err(internal)?
                .iter()
                .skip(1)
                .map(|block| block.header.hash().0)
                .collect();
            build_real_run_ctx(
                data,
                &lock(trace),
                n0::N0Ctx {
                    reference_block_count,
                    reference_chain,
                    ce128_probes: lock(ce128_probes).clone(),
                    ce129_probes: lock(ce129_probes).clone(),
                    first_emu_peer: emu_indices[0] as u16,
                    handshake_completed,
                    wrong_alpn_rejected,
                    builder,
                    nut_preferred_peers: peers_of(&plan.wait_then_connect, &emu_indices),
                    emu_preferred_peers: peers_of(&plan.initiate_now, &emu_indices),
                    connection_ends,
                },
            )
            .map_err(internal)?
        }
        ObsSource::Fabricated { .. } => {
            fabricated_run_ctx(&oracle, reference_block_count).map_err(internal)?
        }
    };

    phase("build_run_ctx", t_ctx);
    let t_eval = std::time::Instant::now();
    let evaluation = match &source {
        ObsSource::Emulator { obs, .. } => evaluate(&lock(obs), &run_ctx, cli.lanes),
        ObsSource::Fabricated { log, .. } => evaluate(log, &run_ctx, cli.lanes),
    };

    phase("evaluate", t_eval);
    // What the out-of-process engine cost. The question this answers is
    // whether a round trip per request still leaves tickets inside the
    // submission window, so the mean matters more than the total.
    let (requests, spent) = oracle.traffic();
    eprintln!(
        "[oracle] {requests} requests, {spent:?} total, {:?} mean, polkajam {}",
        spent
            .checked_div(requests.max(1) as u32)
            .unwrap_or_default(),
        oracle.revision()
    );
    // §4.6 teardown: kill the NUT (stdout/stderr already collected by `spawn`).
    if let Some(nut) = nut.take() {
        launch::kill(nut).await.map_err(internal)?;
    }

    // §4.6 report + trace.
    let Evaluation {
        outcomes,
        findings: scenario_findings,
        all_hard_passed,
    } = evaluation;
    let mut findings = conn_findings;
    findings.extend(scenario_findings);
    report::write_report(session_dir, &outcomes, &findings).map_err(internal)?;
    let trace_result = match &source {
        ObsSource::Emulator { trace, .. } => report::write_trace(session_dir, &lock(trace)),
        ObsSource::Fabricated { trace, .. } => report::write_trace(session_dir, trace),
    };
    trace_result.map_err(internal)?;

    Ok(Evaluation {
        outcomes,
        findings,
        all_hard_passed,
    })
}

/// The tiny validator set: six validators, one of which is the NUT.
const VALIDATOR_COUNT: usize = 6;

/// Validator indices the harness emulates: every index except the NUT's.
///
/// The result is positional — position `i` of the returned list is the
/// validator that position `i` of the [`ConnectivityPlan`], `emu_keys` and
/// `emu_addrs` refers to. It is deliberately not a range: a NUT anywhere but
/// the ends of the keyset splits the emulated set in two, and treating it as
/// the range `0..nut_index` both dropped the validators above the NUT and left
/// the NUT's own keyset loaded in the reference chain (defect 2).
fn emulated_indices(nut_index: usize) -> Vec<usize> {
    (0..VALIDATOR_COUNT).filter(|&i| i != nut_index).collect()
}

/// Seed the reference chain over the slots between its head and now.
///
/// Every slot authored here is in the past, which is the point. The old
/// pre-window burst started at the *current* slot and ran forward, so all but
/// the first block carried a slot the wall clock had not reached yet, and a
/// node is entitled to refuse a header from the future. Genesis is anchored to
/// the start of the current epoch (A9), so there are real past slots to fill
/// instead.
///
/// Seeding resumes from the head rather than from genesis, so calling it
/// again after the clock has moved tops the chain up instead of failing:
/// authoring a slot the chain already holds is an error, which made a second
/// call abort the whole run.
///
/// Returns how many blocks were produced; the harness skips the NUT's own
/// slots by itself.
fn seed_past_slots(chain: &RefChain) -> Result<usize, m2_reference::chain::ChainError> {
    let now = chain.next_slot();
    let mut count = 0;
    for slot in (chain.best_slot()? + 1)..=now {
        if chain.author_block(slot)?.is_some() {
            count += 1;
        }
    }
    Ok(count)
}

/// Prove the emulated validators' tickets and schedule them, regenerating once
/// if proving was overtaken by an epoch boundary.
///
/// The caller seeds the chain first. That ordering is not an optimization: a
/// ticket is sealed against the tickets entropy of the chain head, so proving
/// against an unseeded head produces tickets the node rejects outright.
///
/// Even seeded, proving can still straddle a boundary — it reads the entropy,
/// proves, and by the time the plan is laid the submission window for the
/// epoch it generated for may have closed, which leaves *both* ticket lanes
/// measuring nothing. The second attempt reads the entropy of the epoch the
/// run is now in and has that epoch's whole window ahead of it.
///
/// Neither attempt seeds the chain itself. By the time this runs `drive_slots`
/// owns authoring, and a second writer racing it for the same slot fails the
/// whole run with "cannot author slot N: reference chain head is at slot N".
async fn plan_tickets_for_this_run(
    ref_chain: &RefChain,
    nut_index: usize,
) -> Result<(TicketCtx, Vec<ScheduledTicket>, u32), m2_reference::chain::ChainError> {
    let (ticket_ctx, tickets, target_epoch) = generate_tickets(ref_chain)?;
    let plan = schedule_tickets(ref_chain, &tickets, nut_index, target_epoch);
    if !this_epoch_is_a_waste(ref_chain.next_slot(), &plan, target_epoch) {
        return Ok((ticket_ctx, plan, target_epoch));
    }
    // The window for this epoch's lottery cannot carry the run, and nothing
    // within this epoch can change that: tickets are submitted before the
    // tail, and forwards are owed only early in the lottery. Waiting it out
    // costs slots before the observation window opens and buys the whole of
    // the next epoch's window; not waiting costs the lanes that would have
    // measured something.
    wait_for_next_epoch(ref_chain).await;
    let (ticket_ctx, tickets, target_epoch) = generate_tickets(ref_chain)?;
    let plan = schedule_tickets(ref_chain, &tickets, nut_index, target_epoch);
    Ok((ticket_ctx, plan, target_epoch))
}

/// Whether this epoch's remaining window is poor enough to be worth trading
/// for the next one's.
///
/// Two cases. An empty plan is the obvious one: the window has closed
/// outright, so both ticket lanes measure nothing. The second is a window
/// that is open but opens late — a CE 131 delivery goes out at its first
/// slot, and once that slot is past the forwardable phases the node owes no
/// forward for it, so `n2_proxy_duty` reports "not exercised" however well
/// the node behaves (`sessions/gate-7`, which planned every CE 131 at phase
/// 8). Deferring is only worth it when the plan actually proxies something to
/// the NUT; with no CE 131 entry there is no duty to exercise and the wait
/// buys nothing.
fn this_epoch_is_a_waste(now_slot: u32, plan: &[ScheduledTicket], target_epoch: u32) -> bool {
    if plan.is_empty() {
        return true;
    }
    let proxies_to_the_nut = plan.iter().any(|s| s.delivery == TicketDelivery::Ce131);
    proxies_to_the_nut
        && !window_can_exercise_forwarding(first_delivery_slot(now_slot), target_epoch)
}

/// Block until the NUT is in a state to accept tickets, or until waiting
/// stops being worth it.
///
/// The node refuses every ticket offered to it while its finalized head is
/// behind the current epoch, which it is for as long as it takes to import
/// and finalize the chain the harness seeded. The emulator's sender already
/// holds tickets back for exactly this (`node_can_accept_tickets`), but a
/// plan written while the node is still catching up names slots the tickets
/// will not arrive in, and the proxy-forwarding duty is owed only on arrival.
///
/// Giving up is deliberate rather than an error: a node that never finalizes
/// has a defect of its own, and the run should go on to report it from the
/// lanes rather than hang here. The sender's own gate still withholds, so
/// nothing is graded against a ticket the node could not have taken.
async fn wait_until_the_node_can_accept_tickets(shared: &m2_emu::emu::EmuShared, budget_secs: u64) {
    // Half the observation window, capped at an epoch: past an epoch the
    // lottery has moved on and the wait has bought nothing.
    let cap = u64::from(jam_types::epoch_period()) * m2_scenario::ctx::SLOT_PERIOD_MS / 1000;
    // Protocol time, not orchestration time: the budget is counted in slots
    // and the loop reads the slot clock, so the deadline has to be on the same
    // clock as the thing it is waiting for. Measured against a machine clock
    // while the slots came from a virtual one, this would never expire.
    let clock = jamnp_s::clock::current();
    let deadline = clock
        .mono_ms()
        .saturating_add((budget_secs / 2).min(cap).saturating_mul(1000));
    while clock.mono_ms() < deadline {
        let now_slot = m2_reference::chain::wall_clock_slot();
        if m2_emu::ticket_io::node_can_accept_tickets(shared.nut_final_slot(), now_slot) {
            return;
        }
        clock
            .sleep(Duration::from_millis(NODE_READINESS_POLL_MS))
            .await;
    }
}

/// Sleep until the start of the next epoch.
async fn wait_for_next_epoch(ref_chain: &RefChain) {
    let period = jam_types::epoch_period();
    let now = ref_chain.next_slot();
    let slots = period - now % period;
    jamnp_s::clock::current()
        .sleep(Duration::from_millis(
            u64::from(slots) * m2_scenario::ctx::SLOT_PERIOD_MS,
        ))
        .await;
}

/// Author each slot as the wall clock reaches it and announce every block, for
/// as long as the task lives.
///
/// This is what keeps the chain moving: before, it was authored once up front
/// and then stood still for the rest of the observation window.
async fn drive_slots(
    chain: Arc<RefChain>,
    announce: broadcast::Sender<Vec<u8>>,
    contexts: EpochContexts,
) {
    let mut next = chain.next_slot() + 1;
    let mut captured_epoch = None;
    loop {
        // Wait for the slot to actually begin. Sleeping to the boundary rather
        // than for one slot period keeps the pacing from drifting over a run.
        let start = m2_reference::chain::slot_start_ms(next);
        let clock = jamnp_s::clock::current();
        if let Some(delay) = start.checked_sub(clock.wall_ms()) {
            clock.sleep(Duration::from_millis(delay)).await;
        }
        // The head no longer moves only when this task authors: a NUT block
        // adopted into the chain can already occupy this slot or a later one,
        // and authoring at or behind the head is an error that would end the
        // driver for the rest of the run.
        // An unreachable oracle ends the driver, the same as an authoring
        // error below: there is no chain left to drive.
        let Ok(head) = chain.best_slot() else { break };
        if next <= head {
            next += 1;
            continue;
        }
        match chain.author_block(next) {
            Ok(Some(block)) => {
                // Fails only when nothing is subscribed, which is not an error:
                // the announcement simply has nowhere to go yet.
                if let Ok(wire) = m2_emu::emu::announcement_wire(&block, &chain) {
                    let _ = announce.send(wire);
                }
            }
            // The NUT's own slot, or nothing to author.
            Ok(None) => {}
            Err(_) => break,
        }
        // A ticket proof is bound to the tickets-entropy of the epoch it
        // targets, so the only moment the harness can read the context for
        // epoch `e + 1` is while the chain is *in* epoch `e`. Capturing it on
        // each boundary is the difference between judging the node's tickets
        // and reporting them unjudged: a run spans several epochs, and the
        // node generates afresh in each one.
        //
        // Read after authoring, not before: the entropy rotates with the first
        // block of the new epoch, so a read taken before it still holds the
        // previous epoch's and the context would be filed one epoch late.
        let epoch = next / jam_types::epoch_period();
        if captured_epoch != Some(epoch) {
            // Once per epoch is the trigger; the epoch it is *filed* under
            // comes from the context, which read it from the same storage as
            // the entropy. The two agree here almost always -- the read
            // follows the authoring immediately -- but "almost always" is how
            // the other two sites looked too, and a NUT block adopted between
            // the two lines is enough to part them.
            if let Ok(ctx) = chain.ticket_ctx() {
                lock(&contexts).push((ctx.epoch, ctx));
            }
            captured_epoch = Some(epoch);
        }
        next += 1;
    }
}

/// A soft finding for a run whose ticket plan came out empty: the epoch's
/// submission window closed before the harness was ready to use it.
///
/// Reported rather than swallowed, because the N1 and N2 ticket checks are
/// then measuring nothing — the honest reading is "not exercised", not "no
/// defect found".
fn empty_ticket_plan_finding(ref_chain: &RefChain, target_epoch: u32) -> Finding {
    let now = ref_chain.next_slot();
    Finding {
        severity: "soft".into(),
        spec_citation: "simple.md :305-349".into(),
        slot: Some(now),
        evidence: "ticket plan".into(),
        message: format!(
            "no tickets scheduled: at slot {now} (epoch offset {}) the submission window for \
             epoch {target_epoch} has closed, so the ticket lanes are not exercised",
            now % jam_types::epoch_period()
        ),
    }
}

/// How much of its rotation the node is left to work in.
///
/// Sharing is given ~3 s by DESIGN §11 N3, and distributing the report
/// follows it; two slots is twelve seconds, which clears both without
/// pushing the submission so far into the rotation that a slow node runs out
/// of room through no fault of its own.
const SUBMISSION_MARGIN_SLOTS: u32 = 2;

/// Build this run's CE 133 submission: one trivial work item, aimed at a slot
/// the NUT guarantees a core in with room left to act.
fn plan_package_for_this_run(
    ref_chain: &RefChain,
    nut_index: usize,
) -> Result<Vec<m2_reference::reports::SubmissionSchedule>, m2_reference::chain::ChainError> {
    // Into the *next* epoch, not the next slot.
    //
    // The two core assignments read different entries of the entropy buffer.
    // `core_assignments_for` takes entry 2 for a slot in the head's own epoch
    // and entry 1 for one in the next; the cached epoch view a guarantor
    // shares by carries entry 1 either way. So they disagree for a slot in
    // the head's epoch and agree for a slot in the next one -- which is the
    // whole of why this lane passed every row in one run and failed the
    // sharing row in the next, with the run's start time as the only
    // variable.
    //
    // Aiming into the next epoch puts the submission where the node's
    // sharing cohort and the on-chain rule provably read the same entropy,
    // so the lane grades an assignment both sides agree on instead of
    // picking a side. Which of the two is authoritative for a same-epoch
    // slot is a separate question, recorded in findings.md.
    //
    // A few slots *into* that epoch, not its first slot. The node's cached
    // epoch view rotates on finalization, which trails the head, so at the
    // boundary itself it is still shuffling by the old epoch's entropy and
    // shares with the old cohort -- a run that aimed at the first slot of an
    // epoch saw the node open CE 134 to one co-guarantor instead of two even
    // though both views agreed on paper.
    //
    // Aimed from the *cached* epoch, not from the head. The epoch view
    // resolves the cached epoch and the one after it, so aiming at
    // `cached + 1` is resolvable by construction. Aiming from the head is
    // not: the run waits for the cache to catch up and then reads the head
    // again, and a head that crosses an epoch in between puts the target two
    // epochs past the cache, which resolves to nothing and leaves the whole
    // lane unexercised. Three runs in five did exactly that, all of them
    // near a boundary.
    let epoch = jam_types::epoch_period();
    let (cached_epoch_index, state_epoch_index) = ref_chain.epoch_views()?;
    let base = cached_epoch_index.max(state_epoch_index);
    let from = (base + 1) * epoch + EPOCH_SETTLE_SLOTS;
    let plan = ref_chain
        .submission_slot_for(nut_index as u16, from, SUBMISSION_MARGIN_SLOTS)?
        .ok_or_else(|| {
            m2_reference::chain::ChainError::Chain(format!(
                "no slot at or after {from} leaves {SUBMISSION_MARGIN_SLOTS} slots of its \
                 rotation for the node to act in"
            ))
        })?;
    eprintln!(
        "[assignment] aiming at slot {} (epoch {}), head is slot {} (epoch {})",
        plan.slot,
        plan.slot / epoch,
        ref_chain.next_slot(),
        ref_chain.next_slot() / epoch
    );
    let (cached_epoch, state_epoch) = ref_chain.epoch_views()?;
    let (cached_entropy, entropy1, entropy2) = ref_chain.assignment_entropy()?;
    eprintln!(
        "[assignment] entropy: cached {cached_entropy}  best-block[1] {entropy1}  \
         best-block[2] {entropy2}  -> cached matches {}",
        if cached_entropy == entropy2 {
            "entry 2 (the on-chain rule)"
        } else if cached_entropy == entropy1 {
            "entry 1 (one epoch ahead)"
        } else {
            "neither"
        }
    );
    eprintln!(
        "[assignment] cached epoch view {cached_epoch}, best-block state epoch {state_epoch}{}",
        if cached_epoch == state_epoch {
            ""
        } else {
            "  <-- CACHE LAGS THE STATE"
        }
    );
    eprintln!(
        "[assignment] reference head slot {} (epoch {}), submission slot {} (epoch {})",
        ref_chain.best_slot()?,
        ref_chain.best_slot()? / jam_types::epoch_period(),
        plan.slot,
        plan.slot / jam_types::epoch_period()
    );
    // The whole assignment at the submission slot, so a disagreement with the
    // node over who holds a core is visible in the run rather than inferred
    // from which peers it talked to.
    for core in 0..jam_types::core_count() {
        eprintln!(
            "[assignment] slot {} core {core}: storage {:?} epoch {:?}",
            plan.slot,
            ref_chain.guarantors_for(core, plan.slot),
            ref_chain.guarantors_for_in_epoch(core, plan.slot),
        );
    }
    // The honest submission first, then one per fault, a slot apart. A fault
    // sharing a slot with the honest submission would be graded against a
    // node already busy with it; a slot is six seconds, which is far more
    // than the node needs, since it opens CE 134 within milliseconds.
    use m2_reference::reports::SubmissionFault::*;
    let mut plans = vec![m2_reference::reports::SubmissionSchedule {
        slot: plan.slot,
        core: plan.core,
        protocol: u16::from(jamnp_s::framing::CE133),
        co_guarantors: plan.co_guarantors.clone(),
        fault: None,
        imports: false,
    }];
    // The CE 133 faults, then CE 146: the same package over the whole-bundle
    // protocol, honest and then over its own size cap.
    //
    // CE 146 gets the honest submission that CE 133 already has because
    // DESIGN §11 N3 grades it "as 133" -- the node should accept it and
    // share it with both co-guarantors just the same. What is not the same
    // is the framing: five messages instead of two, and a cap on the
    // work-package message alone rather than on it plus the core index. A
    // node that reads the bundle as one value gets neither right.
    //
    // The importing submission comes last, and that is timing rather than
    // taste. It names the run's first package by hash, and a guarantor can
    // only resolve that hash once the guarantee for it is in a block it
    // holds -- `available_data` reads the packages the chain has seen, not
    // the ones a peer mentioned. Six slots behind the package it imports
    // from is room for the node to guarantee it, distribute it and see it
    // included.
    for (i, (protocol, fault, imports)) in [
        (jamnp_s::framing::CE133, Some(Oversized), false),
        (jamnp_s::framing::CE133, Some(Unauthorized), false),
        (jamnp_s::framing::CE133, Some(ExtrinsicSizeMismatch), false),
        (jamnp_s::framing::CE133, Some(NotAGuarantor), false),
        (jamnp_s::framing::CE146, None, false),
        (jamnp_s::framing::CE146, Some(Oversized), false),
        (jamnp_s::framing::CE133, None, true),
    ]
    .into_iter()
    .enumerate()
    {
        let slot = plan.slot + SUBMISSION_SPACING_SLOTS * (i as u32 + 1);
        // Each fault needs the assignment at *its own* slot: the rotation
        // can turn between two of them, and a package aimed at the core the
        // NUT held before is the not-a-guarantor fault by accident.
        let Some(core) = ref_chain.core_for_in_epoch(nut_index as u16, slot)? else {
            // Past the epoch the view can resolve. Said out loud: this used
            // to drop submissions silently, and the rows then reported
            // themselves unexercised with no way to tell that from a node
            // that was never asked.
            eprintln!(
                "[assignment] dropping the CE {protocol} {fault:?} submission: slot {slot} \
                 is past the epoch the view resolves"
            );
            continue;
        };
        let addressed = if fault == Some(NotAGuarantor) {
            // Deliberately the core it does *not* hold.
            (core + 1) % jam_types::core_count()
        } else {
            core
        };
        plans.push(m2_reference::reports::SubmissionSchedule {
            slot,
            core: addressed,
            protocol: u16::from(protocol),
            co_guarantors: ref_chain
                .guarantors_for_in_epoch(addressed, slot)?
                .unwrap_or_default()
                .into_iter()
                .filter(|v| *v != nut_index as u16)
                .collect(),
            fault,
            imports,
        });
    }
    Ok(plans)
}

/// Wait until the chain's cached epoch view names the epoch its own head is
/// in.
///
/// `EpochInfo` is refreshed when a block is finalized, so it trails the head
/// by however far finality is behind. The lane plans one epoch ahead of the
/// head and the view resolves only the cached epoch and the next, so a cache
/// two or more epochs behind cannot answer for the slot the submission is
/// aimed at and no plan is made.
///
/// Bounded, and silent on expiry: a cache that never catches up leaves the
/// plan to fail on its own and report the rule unexercised, which is the
/// truth. Budgeted in protocol time against the same clock the slots come
/// from, so a virtual clock does not wait forever.
async fn wait_for_the_epoch_view_to_catch_up(ref_chain: &RefChain, budget_secs: u64) {
    let clock = jamnp_s::clock::current();
    let deadline = clock
        .mono_ms()
        .saturating_add((budget_secs / 2).saturating_mul(1000));
    while clock.mono_ms() < deadline {
        // An unreachable oracle is not something waiting will fix, and the
        // lane behind this will report its own failure in a moment.
        let Ok((cached, state)) = ref_chain.epoch_views() else {
            return;
        };
        if cached >= state {
            return;
        }
        clock
            .sleep(Duration::from_millis(NODE_READINESS_POLL_MS))
            .await;
    }
}

/// Stderr phase marker, so a run that stalls says which phase it stalled in.
///
/// A conformance run is minutes of mostly-silent waiting, and when one hangs
/// the node's own log is the only clock -- it shows the symptom and never the
/// phase. These lines are the harness's own clock.
pub(crate) fn phase(label: &str, started: std::time::Instant) {
    eprintln!("[phase] {label}: {:?}", started.elapsed());
}

/// Peer index the CE 133 builder is recorded under, defined beside the lane
/// that prints it so that both sides read the same number.
pub(crate) use m2_scenario::scenarios::n0::BUILDER_PEER;

/// Slots before the submission at which its package is built.
///
/// Two opposing bounds, both measured against a live node. Build against the
/// very head and the node refuses the submission: it has not imported that
/// block yet, so the anchor is unknown. Build far enough back and the anchor
/// ages out of recent history -- about eleven slots ahead is accepted and
/// about fourteen is not. A couple of slots sits inside both.
const PACKAGE_BUILD_LEAD_SLOTS: u32 = 2;

/// Open a builder connection to the NUT and submit this run's work package.
///
/// The package is built `PACKAGE_BUILD_LEAD_SLOTS` before the slot and the
/// connection dialled at it. Both are timing, not ceremony: the anchor has a
/// window, and a connection opened early and held idle is one QUIC closes
/// under us.
async fn submit_as_builder(
    addr: SocketAddr,
    expected_san: String,
    genesis_hash: [u8; 32],
    shared: m2_emu::emu::EmuShared,
) {
    let plan = shared.take_submission_plan();
    if plan.is_empty() {
        eprintln!("[builder] no submission plan to claim");
        return;
    }
    // What the run's first exporting package turned out to be, for the
    // submission that imports from it.
    //
    // The *first*, not the most recent. A later exporting package would be
    // fewer slots ahead of the import, and the import needs the guarantee
    // for what it names to have reached a block before it is sent.
    let mut exported: Option<m2_reference::reports::ImportSource> = None;
    for schedule in plan {
        if let Some(source) = submit_one(
            addr,
            &expected_san,
            genesis_hash,
            &shared,
            schedule,
            &exported,
        )
        .await
        {
            exported.get_or_insert(source);
        }
    }
}

/// Submit one scheduled package, honest or faulty.
///
/// A connection of its own per submission. They are a rotation apart, which
/// is far longer than QUIC holds an idle one open, and a builder that
/// submits twice on one connection would be relying on it surviving the gap.
///
/// Returns what this package exported, where it exported anything, so a
/// later submission can import from it.
async fn submit_one(
    addr: SocketAddr,
    expected_san: &str,
    genesis_hash: [u8; 32],
    shared: &m2_emu::emu::EmuShared,
    schedule: m2_reference::reports::SubmissionSchedule,
    exported: &Option<m2_reference::reports::ImportSource>,
) -> Option<m2_reference::reports::ImportSource> {
    sleep_until_slot(schedule.slot.saturating_sub(PACKAGE_BUILD_LEAD_SLOTS)).await;
    // A package that imports by work-package hash is only submittable once
    // the guarantee for the package it names is in a block. Before that the
    // node takes the submission, fails to resolve the import, and never
    // shares -- which on the report reads as a node refusing to share a
    // package it was given, a failure the harness caused.
    //
    // So the run checks, and skips the submission rather than posing a
    // question the node cannot be expected to answer. The mapping row then
    // reports itself unexercised, which is what it is.
    let importing = exported.as_ref().filter(|_| schedule.imports);
    if let Some(from) = importing {
        match shared.ref_chain.carries_package(&from.package_hash) {
            Ok(true) => {}
            Ok(false) => {
                eprintln!(
                    "[builder] skipping the importing submission for slot {}: no block yet \
                     carries a guarantee for package {}, so the node could not resolve the \
                     import",
                    schedule.slot,
                    hex8(&from.package_hash)
                );
                return None;
            }
            Err(e) => {
                eprintln!("[builder] could not check the chain for the exporting package: {e}");
                return None;
            }
        }
    }
    let (plan, answer) = match shared.ref_chain.submission_now(&schedule, importing) {
        Ok(built) => built,
        Err(e) => {
            eprintln!("[builder] could not build the package: {e}");
            return None;
        }
    };
    if let Some(from) = plan.imports_from {
        eprintln!(
            "[builder] slot {} imports segment {} of package {}",
            schedule.slot,
            from.index,
            hex8(&from.package_hash)
        );
    }
    // Read before the plan is handed to the sender, which consumes it.
    let produced = (plan.exports_count > 0).then_some(m2_reference::reports::ImportSource {
        package_hash: plan.package_hash,
        exports_root: plan.exports_root,
        index: 0,
    });
    // Only the honest submission's answer. Set for every submission, each
    // overwrote the last, so the hash the lane compared the node's report
    // against was whichever fault happened to be built last -- and the
    // harness was offering a co-guarantor signature for packages it had
    // deliberately broken.
    if schedule.fault.is_none() {
        *shared
            .sharing_answer
            .lock()
            .expect("the sharing answer lock is never poisoned") = Some(answer);
    }
    eprintln!(
        "[builder] built for slot {} against head {}",
        schedule.slot,
        shared.ref_chain.next_slot()
    );

    sleep_until_slot(schedule.slot).await;
    let mut seed = [0u8; 32];
    seed[0] = 0xB0;
    seed[1] = 0xD1;
    use jamnp_s::transport::Transport as _;
    let connected = jamnp_s::transport::quic::QuicTransport
        .connect(
            jamnp_s::endpoint::EndpointConfig {
                genesis_hash,
                builder: true,
            },
            ed25519_consensus::SigningKey::from(seed),
            expected_san.to_string(),
            addr,
        )
        .await;
    let connection = match connected {
        Ok(connection) => connection,
        Err(e) => {
            eprintln!("[builder] could not connect as a builder: {e}");
            return None;
        }
    };
    m2_emu::report_io::spawn_package_sender(
        connection.clone(),
        plan,
        Arc::clone(&shared.trace),
        Arc::clone(&shared.obs),
        Arc::clone(&shared.submissions),
        Arc::clone(&shared.connection_ends),
        BUILDER_PEER,
    )
    .await;
    drop(connection);
    produced
}

/// Watch for a report the NUT guaranteed, and plan this run's availability
/// around it.
///
/// Every other plan is written before the observation window. This one
/// cannot be: it is built around an erasure root, and the only root the node
/// is obliged to serve shards for is one it published itself. A root the
/// harness guaranteed would be a root the node never held, and `NoData` on
/// it would read as a node that refuses to serve.
///
/// Gives up when the window runs out, in which case the N4 lane reports its
/// rules as unexercised -- which is the truth, and not a node that failed.
async fn plan_availability(
    reports: Arc<Mutex<Vec<m2_scenario::scenarios::n3::ReportSeen>>>,
    shard_count: Arc<Mutex<Option<u16>>>,
    planner: m2_emu::emu::AvailPlanner,
    budget_secs: u64,
) {
    let deadline = jamnp_s::clock::current().wall_ms() + budget_secs * 1000;
    let spec = loop {
        if let Some(spec) = first_package_spec(&reports) {
            break spec;
        }
        if jamnp_s::clock::current().wall_ms() >= deadline {
            eprintln!(
                "[availability] the NUT published no report of its own inside the window; \
                 N4 has nothing to ask it for"
            );
            return;
        }
        jamnp_s::clock::current()
            .sleep(Duration::from_millis(m2_scenario::ctx::SLOT_PERIOD_MS))
            .await;
    };

    // Segment indices only where the package exported something. Asking for
    // segment 0 of a package that exports none is asking for a slice that
    // does not exist, and a node is right to refuse it.
    let segment_indices: Vec<u16> = (0..spec.exports_count.min(MAX_SEGMENTS_ASKED)).collect();
    let now = m2_reference::chain::wall_clock_slot();
    // Assure for the rest of the window, not a fixed stretch of it. The
    // node authors about one slot in six and a run cannot choose which, so
    // the only thing that reliably puts one of its slots among the offers
    // is offering in all of them.
    //
    // A fixed epoch's worth was not enough, and the way it failed is worth
    // keeping: a live run offered across slots 9880681..=9880692 while the
    // node authored 9880662, 9880670, 9880675 and then 9880693 -- one slot
    // past the last offer. Every inclusion row reported itself unexercised,
    // which reads exactly like a node that carried nothing.
    let left = deadline.saturating_sub(jamnp_s::clock::current().wall_ms());
    let assurance_slots = (left / m2_scenario::ctx::SLOT_PERIOD_MS)
        .saturating_sub(u64::from(ASSURANCE_TAIL_SLOTS))
        .max(u64::from(MIN_ASSURANCE_SLOTS)) as u32;
    let plan = m2_emu::avail_io::AvailPlan {
        erasure_root: spec.erasure_root,
        segments_root: spec.exports_root,
        shard_count: spec.erasure_shards,
        segment_indices,
        // The whole coded segment set, which is the tree a justification
        // proves against. Three different numbers meet here and only one is
        // right (`findings.md` §26):
        //
        // - what a run asks for, capped by `MAX_SEGMENTS_ASKED`;
        // - what the package exported, `exports_count`;
        // - what was actually coded, which is the exports **plus their
        //   import-proof pages**. `import_proof_pages` appends one page per
        //   `PROVEN_PER_SEGMENT` segments before the set is shard-coded, and
        //   `jam_types::max_export_segments` is this same formula at the
        //   maximum.
        segment_count: segment_tree_len(spec.exports_count),
        // A slot ahead, so the fetches have somewhere to finish before the
        // assurance that follows them.
        honest_slot: now + 1,
        assurance_slots,
        // Half honest, half spoiled. Either half has to contain a slot the
        // node authors the child of, or its row goes ungraded.
        spoiled_from: now + 1 + assurance_slots / 2,
    };
    eprintln!(
        "[availability] planning against root {} coded into {} shards, {} segment(s)",
        hex8(&plan.erasure_root),
        plan.shard_count,
        plan.segment_indices.len()
    );
    *lock(&shard_count) = Some(plan.shard_count);
    planner.set(plan);
}

/// Slots left unassured at the end of the window.
///
/// An assurance offered in the last slot of a run has no child block to be
/// carried in, because the run ends before one is authored and fetched. Two
/// slots of headroom keeps the final offers gradeable rather than reporting
/// themselves unexercised.
const ASSURANCE_TAIL_SLOTS: u32 = 2;

/// Fewest slots a run assures for, however little window is left.
///
/// A validator assures the head every slot, and an assurance is carried in
/// exactly one block: the child of the block it anchors. The node authors
/// about one slot in six, so a short stretch of offers leaves the inclusion
/// rows unexercised -- not failing, but saying nothing.
const MIN_ASSURANCE_SLOTS: u32 = 12;

/// Segments a package of `exports` exports is coded into.
///
/// The exports themselves plus one import-proof page per
/// `PROVEN_PER_SEGMENT` of them: `import_proof_pages` appends the pages to
/// the segment vector and the whole thing is erasure-coded together, so the
/// tree a CE 140 justification proves against is this size and not
/// `exports`.
///
/// The engine states the same formula at its maximum, in
/// `jam_types::max_export_segments`.
fn segment_tree_len(exports: u16) -> u32 {
    let exports = u32::from(exports);
    exports + exports.div_ceil(jam_types::PROVEN_PER_SEGMENT as u32)
}

/// Most segment indices a run asks for over CE 139/140.
///
/// A handful is enough to exercise the protocol; the point of the rows is
/// that the slices verify, not that every one of them is fetched.
const MAX_SEGMENTS_ASKED: u16 = 4;

/// What a report the NUT distributed says about its package's availability.
struct AvailSpec {
    erasure_root: [u8; 32],
    erasure_shards: u16,
    /// The root the package's exported segments sit under, which is what a
    /// CE 148 request names. A different root from `erasure_root`, and a
    /// different question.
    exports_root: [u8; 32],
    exports_count: u16,
}

/// Read the package spec out of the first report the NUT distributed.
///
/// Decoded from the bytes that came off the wire rather than from anything
/// the harness computed: the erasure root the node must serve shards for is
/// the one it published, whatever this harness would have derived.
fn first_package_spec(
    reports: &Arc<Mutex<Vec<m2_scenario::scenarios::n3::ReportSeen>>>,
) -> Option<AvailSpec> {
    let seen = lock(reports);
    let report = seen.first()?;
    let mut input: &[u8] = &report.encoded_report;
    let decoded = <jam_std_common::WorkReport as jam_types::Decode>::decode(&mut input).ok()?;
    Some(AvailSpec {
        erasure_root: decoded.package_spec.erasure_root.0,
        erasure_shards: decoded.package_spec.erasure_shards,
        exports_root: decoded.package_spec.exports_root.0,
        exports_count: decoded.package_spec.exports_count,
    })
}

/// Dial the NUT as an emulated validator and keep that connection up for as
/// long as the run lasts.
///
/// [`dial_nut`] returns when the connection ends, and the two call sites used
/// to discard that with `let _ =`. Where the emulated validator is the
/// preferred initiator the node is *right* to sit and wait for it
/// (`simple.md:70-80`), so a connection that died stayed dead: the node had
/// four peers for the rest of the run and the rows that needed the fifth
/// failed, in two different lanes, reading as two unrelated node defects
/// (`findings.md` §29).
///
/// So it re-dials, and says so. The delay is what keeps a node that is
/// refusing connections from being hammered; the run ends by aborting this
/// task, so there is no need to count attempts.
async fn hold_connection(
    index: usize,
    genesis_hash: [u8; 32],
    nut_addr: SocketAddr,
    nut_san: String,
    shared: m2_emu::emu::EmuShared,
) {
    loop {
        match m2_emu::emu::dial_nut(
            index,
            genesis_hash,
            nut_addr,
            nut_san.clone(),
            shared.clone(),
        )
        .await
        {
            Ok(reason) => eprintln!(
                "[connectivity] validator {index}: the connection to the NUT ended ({reason}); re-dialling"
            ),
            Err(e) => eprintln!("[connectivity] validator {index}: connection to the NUT: {e}"),
        }
        jamnp_s::clock::current().sleep(REDIAL_DELAY).await;
    }
}

/// How long to wait before dialling the NUT again after a connection ends.
///
/// Short enough that a run of 300 s loses little, long enough that a node
/// refusing connections is not dialled in a tight loop.
const REDIAL_DELAY: std::time::Duration = std::time::Duration::from_secs(2);

fn hex8(bytes: &[u8; 32]) -> String {
    bytes[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// Wait until `slot` begins.
async fn sleep_until_slot(slot: u32) {
    let target_ms = m2_emu::emu::slot_start_ms(slot);
    loop {
        let now = jamnp_s::trace::wall_ts();
        if now >= target_ms {
            return;
        }
        jamnp_s::clock::current()
            .sleep(Duration::from_millis(target_ms - now))
            .await;
    }
}

/// Slots between one scheduled CE 133 submission or CE 134 share and the
/// next.
///
/// Everything the lane schedules has to fit inside one epoch: it aims at the
/// start of `cached + 1`, and the epoch view resolves only that epoch, so a
/// slot past its end has no assignment to plan against and is dropped
/// silently. A rotation apart put the fourth submission at +12 of a
/// twelve-slot epoch, and two faults and both shares fell off the end --
/// they never went out and their rows reported themselves unexercised with
/// nothing to say why.
const SUBMISSION_SPACING_SLOTS: u32 = 1;

/// Slots to let an epoch settle before submitting into it.
///
/// Zero, measured. Three was tried and made the lane strictly worse: five
/// consecutive runs scored no passes at all. Aiming that far out puts the
/// slot beyond the cached epoch view, which knows only the current epoch and
/// the next, and the submitted package's anchor ages out of recent history
/// over the longer wait. See findings.md 2.
const EPOCH_SETTLE_SLOTS: u32 = 0;

/// Seconds the node needs after a submission to share, be answered, build a
/// guarantee and distribute it. Measured at a few seconds in practice; this
/// leaves room for a slow one.
const MIN_SECS_AFTER_SUBMISSION: u64 = 30;

/// Reported when the observation window closes before the submission slot.
fn short_window_finding(wait_secs: u64, observe_secs: u64) -> Finding {
    Finding {
        severity: "soft".into(),
        spec_citation: "simple.md :351-376".into(),
        slot: None,
        evidence: "work-package plan".into(),
        message: format!(
            "the submission slot is {wait_secs} s away and the window is {observe_secs} s, so \
             N3 will not be exercised; the lane aims into the next epoch, so it needs at least \
             {} s",
            wait_secs + MIN_SECS_AFTER_SUBMISSION
        ),
    }
}

/// Reported when the harness could not pose the CE 133 row at all.
fn no_package_plan_finding(error: &m2_reference::chain::ChainError) -> Finding {
    Finding {
        severity: "soft".into(),
        spec_citation: "simple.md :351-376".into(),
        slot: None,
        evidence: "work-package plan".into(),
        message: format!("no work package submitted, so N3's CE 133 row is not exercised: {error}"),
    }
}

/// Probe the NUT port until a handshake succeeds or `timeout_secs` elapses.
async fn wait_for_nut(
    addr: SocketAddr,
    san: &str,
    genesis_hash: [u8; 32],
    timeout_secs: u64,
) -> bool {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let attempt = connectivity::probe_nut(
            addr,
            san,
            genesis_hash,
            remaining.min(Duration::from_secs(1)),
        )
        .await;
        if attempt.connected {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    false
}

/// Map `run_connectivity`'s outcomes back onto emulator indices (outcomes are
/// ordered `initiate_now` then `wait_then_connect`) and report soft findings
/// for probes that never established a connection.
fn connectivity_findings(plan: &ConnectivityPlan, outcomes: &[ProbeOutcome]) -> Vec<Finding> {
    let n_now = plan.initiate_now.len();
    let mut findings = Vec::new();
    for (k, &i) in plan.initiate_now.iter().enumerate() {
        push_connectivity_finding(&mut findings, i, &outcomes[k]);
    }
    for (k, &i) in plan.wait_then_connect.iter().enumerate() {
        push_connectivity_finding(&mut findings, i, &outcomes[n_now + k]);
    }
    findings
}

fn push_connectivity_finding(findings: &mut Vec<Finding>, emu_index: usize, o: &ProbeOutcome) {
    if o.connected {
        return;
    }
    findings.push(Finding {
        severity: "soft".into(),
        spec_citation: "simple.md :5-99".into(),
        slot: None,
        evidence: "connectivity probe".into(),
        message: format!("emulated validator {emu_index} could not handshake with the NUT"),
    });
}

/// §7 `LaunchConfig` for a run: NUT on `base_port + validator_index`, IPv4-mapped loopback
/// public address, session dir as data path.
fn launch_config(
    keys: &keygen::GeneratedKeys,
    cli: &Cli,
    spec_path: std::path::PathBuf,
    m2_spec_path: std::path::PathBuf,
) -> LaunchConfig {
    LaunchConfig {
        spec_path,
        m2_spec_path,
        ed25519_secret_hex: keys.nut_ed25519_secret_hex.clone(),
        bandersnatch_secret_hex: keys.nut_bandersnatch_secret_hex.clone(),
        listen: format!("[::]:{}", cli.base_port + cli.validator_index as u16),
        public_addr: format!(
            "::ffff:127.0.0.1:{}",
            cli.base_port + cli.validator_index as u16
        ),
        data_path: cli.session_dir.clone(),
        log_level: "info".to_string(),
    }
}

/// The six validators' IPv4-mapped loopback addresses (`::ffff:127.0.0.1`).
fn loopback_ips() -> [[u8; 16]; 6] {
    let mut ips = [[0u8; 16]; 6];
    for ip in ips.iter_mut() {
        ip[10] = 0xff;
        ip[11] = 0xff;
        ip[12] = 127;
        ip[15] = 1;
    }
    ips
}

/// Map plan positions onto validator indices.
///
/// `ConnectivityPlan` holds positions into `emu_indices`, not validator
/// indices; the observation log is keyed by validator index.
fn peers_of(positions: &[usize], emu_indices: &[usize]) -> Vec<u16> {
    let mut peers: Vec<u16> = positions.iter().map(|&i| emu_indices[i] as u16).collect();
    peers.sort_unstable();
    peers
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn internal(e: impl std::fmt::Display) -> RunError {
    RunError::Internal(e.to_string())
}

fn startup(e: impl std::fmt::Display) -> RunError {
    RunError::Startup(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `current_epoch_start_slot` divides the wall-clock slot by
    /// `epoch_period`, which is process-wide state. Read before the tiny
    /// parameters are applied it uses 600 instead of 12, and genesis lands up
    /// to 599 slots back rather than 11 -- a chain the node must import and
    /// finalize before it will accept a single ticket.
    #[test]
    fn the_genesis_anchor_uses_the_tiny_epoch_period() {
        jam_types::ProtocolParameters::tiny()
            .apply()
            .expect("tiny parameters apply");
        let period = jam_types::epoch_period();
        let anchor = m2_reference::chain::current_epoch_start_slot();
        let now = m2_reference::chain::wall_clock_slot();
        assert_eq!(anchor % period, 0, "the anchor is an epoch boundary");
        assert!(
            now - anchor < period,
            "genesis is anchored inside the current epoch: {now} - {anchor} >= {period}"
        );
    }

    /// The planner and the lane have to mean the same thing by "early enough
    /// to forward". They are in different crates and neither can see the
    /// other's constant, so the phases they admit are compared directly here:
    /// a planner that ran ahead of the rule would schedule deliveries the
    /// lane then declines to judge, and one that lagged would wait out epochs
    /// it had no need to.
    #[test]
    fn forwardable_phases_match_the_judged_rule() {
        jam_types::ProtocolParameters::tiny()
            .apply()
            .expect("tiny parameters apply");
        let period = jam_types::epoch_period();
        let tail = jam_types::epoch_tail_start();
        let last =
            m2_reference::tickets::last_forwardable_phase().expect("tiny leaves room to forward");
        for phase in 0..period {
            assert_eq!(
                phase <= last,
                m2_scenario::ctx::leaves_room_to_forward(41 * period + phase, period, tail),
                "phase {phase} is judged one way and planned the other"
            );
        }
    }

    /// The lane grades which validator the node proxied a ticket to, and the
    /// reference assigns which validator the emulator proxies to. They are in
    /// different crates -- `m2-scenario` holds `m2-reference` only as a
    /// dev-dependency, so the lane carries its own copy of the rule -- and a
    /// drift between them would have the harness send a ticket to one
    /// validator while faulting the node for not choosing another.
    #[test]
    fn proxy_rule_matches_the_reference() {
        jam_types::ProtocolParameters::tiny()
            .apply()
            .expect("tiny parameters apply");
        let val_count = usize::from(jam_types::max_val_count());
        // Ids that exercise the whole modulus, the boundaries of the four
        // bytes the rule reads, and bytes outside them that it must ignore.
        let mut ids: Vec<[u8; 32]> = (0u8..=32).map(|b| [b; 32]).collect();
        for tail in [
            [0u8, 0, 0, 0],
            [0xff, 0xff, 0xff, 0xff],
            [1, 0, 0, 7],
            [0, 0, 0, 5],
        ] {
            let mut id = [0xa5u8; 32];
            id[28..32].copy_from_slice(&tail);
            ids.push(id);
        }
        for id in ids {
            assert_eq!(
                usize::from(m2_scenario::ctx::proxy_index(&id, val_count)),
                m2_reference::tickets::proxy_index(&id, val_count),
                "the lane and the reference disagree about the proxy for {:02x?}",
                &id[28..32],
            );
        }
    }

    /// A plan that proxies nothing to the NUT has no forwarding duty to
    /// exercise, so a late window is as good as an early one and waiting an
    /// epoch for it buys nothing. A plan that does proxy to the NUT is worth
    /// the wait, because every CE 131 in it goes out at the window's first
    /// slot and a late first slot owes no forward at all.
    #[test]
    fn a_late_window_is_traded_only_when_a_ticket_is_proxied_to_the_nut() {
        jam_types::ProtocolParameters::tiny()
            .apply()
            .expect("tiny parameters apply");
        let period = jam_types::epoch_period();
        let target_epoch = 42;
        let scheduled = |delivery| ScheduledTicket {
            ticket: m2_reference::tickets::EmulatedTicket {
                id: [0u8; 32],
                author: 0,
                attempt: 0,
                proof: [0u8; 784],
                proxy: 0,
            },
            delivery,
            fault: None,
            plan_index: 0,
            slot: 0,
            target_epoch,
        };
        let proxied = [scheduled(TicketDelivery::Ce131)];
        let broadcast_only = [scheduled(TicketDelivery::Ce132)];

        assert!(
            this_epoch_is_a_waste(41 * period, &[], target_epoch),
            "an empty plan measures nothing whatever the phase"
        );
        // Phase 0: the whole lottery is ahead, so nothing is traded.
        assert!(!this_epoch_is_a_waste(41 * period, &proxied, target_epoch));
        // Phase 8: still inside the submission window, but a CE 131 landing
        // there is one no proxy owes a forward for.
        assert!(this_epoch_is_a_waste(
            41 * period + 8,
            &proxied,
            target_epoch
        ));
        assert!(
            !this_epoch_is_a_waste(41 * period + 8, &broadcast_only, target_epoch),
            "no CE 131 in the plan means no duty to wait for"
        );
    }

    /// Seeding has to be callable again once the clock has moved: ticket
    /// generation that overran its epoch tops the chain up before proving
    /// afresh. Seeding from genesis each time re-authors a slot the chain
    /// already holds, which is an error — and that error aborted the whole
    /// run before any report was written.
    ///
    /// Anchored to the current epoch, exactly as a live run anchors it: on the
    /// slot-0 dev spec the gap between genesis and now is nine million slots,
    /// and seeding it would author every one of them.
    #[test]
    fn seed_past_slots_can_be_called_again() -> Result<(), m2_reference::chain::ChainError> {
        // Before the anchor is read, exactly as `run` does it. The parameters
        // are process-wide, so a test that reads the anchor first gets
        // whichever set some other test happened to install: with the default
        // 600-slot epoch genesis lands up to 599 slots back, `tiny_spec` then
        // installs the tiny set anyway, and seeding authors every one of those
        // slots until the test is killed. That is a flake in the suite, not in
        // the harness -- `run` applies these first -- but it has aborted a
        // whole test run twice.
        jam_types::ProtocolParameters::tiny()
            .apply()
            .expect("tiny parameters apply");
        let chain = anchored_chain_for(40000, 5)?;
        let head = chain.best_slot()?;

        // The second call is the regression: seeding from genesis would try to
        // re-author a slot the chain already holds, which `author_block`
        // rejects. It may legitimately fill a slot or two -- seeding takes
        // seconds and a slot is six of them -- but never one at or behind the
        // head, and it must not fail.
        let second = seed_past_slots(&chain).expect("seeding resumes instead of re-authoring");
        assert!(
            chain.best_slot()? >= head,
            "the head only ever moves forward"
        );
        assert_eq!(
            chain.best_slot()? - head,
            second as u32,
            "the second call authored exactly the slots the clock had moved on by"
        );
        Ok(())
    }

    /// The whole guaranteeing path on one trivial work item: a package, the
    /// report it refines to, the bundle, and a guarantee signed by the
    /// validators holding the core.
    ///
    /// Here rather than in `m2-reference` because it needs a chain whose
    /// genesis is anchored to the current epoch. An unanchored one refuses
    /// twice over -- the guarantee's slot names an epoch the state has never
    /// heard of, and once past that, genesis is far too old to be a lookup
    /// anchor -- and anchoring is `spec::tiny_spec`'s job, which lives here.
    ///
    /// It also measures what refining costs on the interpreter backend, which
    /// `RefChain` forces because the compiler backend needs a userfaultfd
    /// sandbox. N3 schedules work packages into slots, so the figure decides
    /// whether that calendar is realistic.
    /// The NUT's validator index in the anchored test chain.
    const TEST_NUT_INDEX: u16 = 5;

    /// A reference chain anchored to the current epoch, seeded to the present.
    ///
    /// Everything about guaranteeing needs one: assignments come from the
    /// storage for a slot, and an unanchored chain's state is at epoch 0 while
    /// its clock is eight hundred thousand epochs later, so it has no
    /// assignment for any slot the harness would ask about.
    /// An anchored chain on a spec file of its own, seeded to the present.
    ///
    /// Written out and reopened rather than handed over in memory, because
    /// that is the only way the oracle can be given one: it is another
    /// process, and a file is what both ends can read.
    fn anchored_chain(base_port: u16) -> Result<RefChain, m2_reference::chain::ChainError> {
        anchored_chain_for(base_port, TEST_NUT_INDEX as usize)
    }

    fn anchored_chain_for(
        base_port: u16,
        nut_index: usize,
    ) -> Result<RefChain, m2_reference::chain::ChainError> {
        jam_types::ProtocolParameters::tiny()
            .apply()
            .expect("tiny parameters apply");
        let oracle = m2_reference::oracle::Oracle::for_tests();
        let ports: Vec<u16> = (0..VALIDATOR_COUNT).map(|i| base_port + i as u16).collect();
        let anchor = m2_reference::chain::current_epoch_start_slot();
        let spec = spec::tiny_spec(&oracle, &loopback_ips(), &ports, anchor)
            .map_err(|e| m2_reference::chain::ChainError::Chain(e.to_string()))?;
        let dir =
            std::env::temp_dir().join(format!("m2-run-spec-{}-{base_port}", std::process::id()));
        let path = spec::write_polkajam_spec(&dir, &spec)
            .map_err(|e| m2_reference::chain::ChainError::Chain(e.to_string()))?;
        let chain = RefChain::with_spec(&oracle, nut_index, &path)?;
        seed_past_slots(&chain)?;
        Ok(chain)
    }

    /// Every validator holds exactly one core, and the two directions of the
    /// assignment agree. A harness that read them apart would grade a node
    /// against a split the engine never made.
    #[test]
    fn the_assignment_is_a_partition_and_both_directions_agree(
    ) -> Result<(), m2_reference::chain::ChainError> {
        let chain = anchored_chain(42000)?;
        let slot = chain.best_slot()?;
        let mut seen = Vec::new();
        for core in 0..jam_types::core_count() {
            let holders = chain
                .guarantors_for(core, slot)?
                .expect("an active core has holders");
            for val in &holders {
                assert_eq!(
                    chain.core_for(*val, slot)?,
                    Some(core),
                    "validator {val} is listed under core {core} but does not name it"
                );
            }
            seen.extend(holders);
        }
        seen.sort_unstable();
        assert_eq!(
            seen,
            (0..jam_types::max_val_count()).collect::<Vec<_>>(),
            "every validator holds exactly one core"
        );
        assert!(
            chain
                .guarantors_for(jam_types::core_count(), slot)?
                .is_none(),
            "a core outside the active set has no holders"
        );
        Ok(())
    }

    /// The assignment rotates within an epoch, which is the half of the rule a
    /// harness caching one lookup would silently lose.
    #[test]
    fn the_assignment_rotates_within_an_epoch() -> Result<(), m2_reference::chain::ChainError> {
        let chain = anchored_chain(43000)?;
        let slot = chain.best_slot()?;
        assert_ne!(
            chain.core_for(0, slot)?,
            chain.core_for(0, slot + jam_types::rotation_period())?,
            "the core a validator holds must change across a rotation boundary"
        );
        Ok(())
    }

    #[test]
    fn a_work_item_refines_into_a_signed_guarantee() -> Result<(), m2_reference::chain::ChainError>
    {
        let chain = anchored_chain(41000)?;

        let item = m2_reference::reports::trivial_work_item();
        let core = 0;
        let started = std::time::Instant::now();
        let work = chain.guarantee_work(vec![item], core)?;
        eprintln!("refine took {:?}", started.elapsed());

        assert!(!work.bundle.is_empty(), "the bundle carries the package");
        assert!(
            !work.guarantee.signatures.is_empty(),
            "the guarantee is signed"
        );
        // Every signer must hold the core -- at the guarantee's *own* slot, not
        // the chain head's. The assignment rotates every `rotation_period`, so
        // the two disagree whenever a run straddles a boundary, and asserting
        // against the head made this test fail about half the time.
        let holders = chain
            .guarantors_for(core, work.guarantee.slot)?
            .expect("an active core has holders");
        for signature in work.guarantee.signatures.iter() {
            assert!(
                holders.contains(&signature.val_index),
                "validator {} signed for a core it does not hold ({holders:?})",
                signature.val_index
            );
        }
        Ok(())
    }

    /// The submission slot keeps the NUT on one core for the whole window.
    ///
    /// That is the only thing the margin is for. A package submitted in the
    /// last slot of a rotation names a core the node stops holding before it
    /// can share and distribute, and the lane would record a node that did
    /// nothing wrong as having failed to share.
    #[test]
    fn a_submission_slot_holds_its_core_for_the_whole_margin(
    ) -> Result<(), m2_reference::chain::ChainError> {
        let chain = anchored_chain(47000)?;
        let margin = 2u32;
        let rotation = jam_types::rotation_period();

        // Every starting point in a rotation, so the one that has to skip
        // ahead is covered rather than whichever the clock happens to land on.
        for offset in 0..rotation {
            let from = chain.best_slot()? + offset;
            let plan = chain
                .submission_slot_for(TEST_NUT_INDEX, from, margin)?
                .expect("a slot within one rotation always qualifies");
            assert!(plan.slot >= from, "the plan never aims into the past");
            assert!(
                plan.slot < from + rotation,
                "and never further than one rotation out"
            );
            assert_eq!(
                chain.core_for(TEST_NUT_INDEX, plan.slot)?,
                Some(plan.core),
                "the plan names the core the NUT actually holds"
            );
            for slot in plan.slot..plan.slot + margin {
                assert_eq!(
                    chain.core_for(TEST_NUT_INDEX, slot)?,
                    Some(plan.core),
                    "the core must not move under the node during the window \
                     (start {}, slot {slot})",
                    plan.slot
                );
            }
        }
        Ok(())
    }

    /// A margin no rotation can satisfy has no answer, rather than a slot
    /// that silently fails to hold.
    #[test]
    fn a_margin_longer_than_a_rotation_has_no_submission_slot(
    ) -> Result<(), m2_reference::chain::ChainError> {
        let chain = anchored_chain(48000)?;
        assert!(
            chain
                .submission_slot_for(
                    TEST_NUT_INDEX,
                    chain.best_slot()?,
                    jam_types::rotation_period() + 1
                )?
                .is_none(),
            "no slot has more than a rotation left in its rotation"
        );
        Ok(())
    }

    /// CE 133's extrinsic message is the bodies concatenated, and the only
    /// thing that says where one ends is the package's own declared lengths.
    ///
    /// Against a real package, not a hand-made one: `extrinsic_lens` reads a
    /// nested field of the engine's `WorkPackage`, and a hand-made package
    /// would only prove that my own two sides agree.
    #[test]
    fn the_extrinsic_message_is_split_by_the_packages_declared_lengths(
    ) -> Result<(), m2_reference::chain::ChainError> {
        use jamnp_s::codec::ce131_136::{extrinsic_lens, WorkPackageSubmission};

        let chain = anchored_chain(46000)?;
        let bodies = vec![vec![1u8, 2, 3], vec![4u8, 5]];
        let item = m2_oracle_proto::WireItem {
            xts: bodies.clone(),
            ..m2_reference::reports::trivial_work_item()
        };
        let built = chain.build_work_package(vec![item])?;

        assert_eq!(
            built.extrinsics, bodies,
            "the builder hands back the bodies it was given"
        );
        let lens = extrinsic_lens(&built.package);
        assert_eq!(
            lens,
            vec![3u32, 2],
            "the package declares each body's length, in wire order"
        );
        assert_eq!(
            lens.iter().sum::<u32>(),
            built.package.saturated_extrinsic_size(),
            "and they sum to the size the message must have"
        );

        let submission =
            WorkPackageSubmission::from_package(0, &built.package, built.extrinsics.clone());
        let wire = submission.encode_extrinsics();
        assert_eq!(
            wire,
            vec![1u8, 2, 3, 4, 5],
            "the message is the bodies and nothing else"
        );
        assert_eq!(
            WorkPackageSubmission::decode_extrinsics(&wire, &lens).unwrap(),
            bodies,
            "and the declared lengths cut it back apart"
        );
        Ok(())
    }

    /// The builder-side package is submittable: it fits under the CE 133 cap,
    /// and the unauthorized variant differs from it *only* in the authorizer.
    ///
    /// That last part is the whole value of the fault. If the two packages
    /// differed anywhere else, a node refusing the unauthorized one would
    /// prove nothing about authorization -- it could be rejecting the
    /// difference instead.
    #[test]
    fn the_unauthorized_package_differs_only_in_its_authorizer(
    ) -> Result<(), m2_reference::chain::ChainError> {
        use jamnp_s::codec::ce131_136::WorkPackageSubmission;

        let chain = anchored_chain(45000)?;
        let item = || m2_reference::reports::trivial_work_item();
        let good = chain.build_work_package(vec![item()])?;
        let bad = chain.build_unauthorized_package(vec![item()])?;

        let submission = WorkPackageSubmission::from_package(0, &good.package, Vec::new());
        assert!(
            submission.validate_initial_size(),
            "a one-item package must fit the CE 133 initial message"
        );
        assert_eq!(
            good.extrinsics, bad.extrinsics,
            "the two packages carry the same extrinsic bodies"
        );

        assert_ne!(
            good.package.authorizer.code_hash, bad.package.authorizer.code_hash,
            "the unauthorized package must name an authorizer the core does not have"
        );
        assert_eq!(
            codec::Encode::encode(&good.package.items),
            codec::Encode::encode(&bad.package.items),
            "the work items must be identical, or the fault proves nothing"
        );
        assert_eq!(
            codec::Encode::encode(&good.package.context),
            codec::Encode::encode(&bad.package.context),
            "the refine context must be identical too"
        );

        // CE 133 addresses a core, so the lane needs the NUT to hold one at
        // the slot it submits in. Without this the submission has nowhere to
        // go and the lane's first row is unreachable.
        let slot = chain.best_slot()?;
        assert!(
            chain.core_for(TEST_NUT_INDEX, slot)?.is_some(),
            "the NUT must guarantee some core at the slot a package is submitted in"
        );
        Ok(())
    }

    /// A CE 133 submission carries the real package, and `package()` is the
    /// exact inverse of `from_package`.
    ///
    /// The typed view is only worth having if it survives a package the
    /// engine actually built: a hand-made one would agree with a codec that
    /// got the field order wrong, because both sides would be mine.
    #[test]
    fn a_submission_round_trips_the_real_work_package(
    ) -> Result<(), m2_reference::chain::ChainError> {
        use jamnp_s::codec::ce131_136::WorkPackageSubmission;

        let chain = anchored_chain(44000)?;
        let item = m2_reference::reports::trivial_work_item();
        let work = chain.guarantee_work(vec![item], 0)?;

        let mut sub = WorkPackageSubmission::from_package(0, &work.package, Vec::new());
        let decoded = sub.package().expect("the package decodes");
        assert_eq!(
            codec::Encode::encode(&decoded),
            codec::Encode::encode(&work.package),
            "decoding and re-encoding must return the same bytes"
        );
        assert!(
            sub.validate_initial_size(),
            "a one-item package is far below the CE 133 cap"
        );

        // The initial message is the core index and then the package, with no
        // length prefix on the package: it runs to the end of the message.
        let wire = sub.encode_initial();
        let (core_index, work_package) =
            WorkPackageSubmission::decode_initial(&mut &wire[..]).expect("message 1 decodes");
        assert_eq!(core_index, 0);
        assert_eq!(work_package, sub.work_package);

        // Because the package is not length-prefixed, a node could append junk
        // and a plain `Decode` would stop short and never notice.
        sub.work_package.push(0xff);
        assert!(
            codec::Decode::decode(&mut &sub.work_package[..])
                .map(|p: jam_types::WorkPackage| codec::Encode::encode(&p))
                .is_ok(),
            "a plain decode accepts the junk, which is what `package` has to catch"
        );
        assert!(
            sub.package().is_err(),
            "trailing bytes after the package must be rejected"
        );
        Ok(())
    }

    /// Defect 2: at every NUT position the harness emulates the other five
    /// validators and never the NUT itself. The old contiguous range gave
    /// `0..nut_index`, which both lost the validators above the NUT and
    /// included the NUT at index 0.
    #[test]
    fn emulated_indices_cover_every_validator_but_the_nut() {
        for nut_index in 0..VALIDATOR_COUNT {
            let emu = emulated_indices(nut_index);
            assert_eq!(
                emu.len(),
                VALIDATOR_COUNT - 1,
                "NUT index {nut_index}: every other validator must be emulated"
            );
            assert!(
                !emu.contains(&nut_index),
                "NUT index {nut_index}: the harness must not emulate the NUT"
            );
            let expected: Vec<usize> = (0..VALIDATOR_COUNT).filter(|&i| i != nut_index).collect();
            assert_eq!(emu, expected, "NUT index {nut_index}: indices stay ordered");
        }
    }
}
