//! Scenario evaluation for a run: the N0 checks against an observation log
//! and the deterministic dry-run baseline log.

use std::sync::{Arc, Mutex};

use jam_types::JAM_COMMON_ERA;
use jamnp_s::codec::ce131_136::Ticket as Ce131Ticket;
use jamnp_s::trace::Trace;
use m2_emu::emu::Emulator;
use m2_reference::chain::RefChain;
use m2_scenario::ctx::{
    DeliveredTicket, EmuTicket, ImportFact, N1Ctx, N2Ctx, NutBlock, NutBlockTickets, NutFinal,
    NutTicketFacts, TicketDelivery, SLOT_PERIOD_MS, TICKET_ARRIVAL_LEAD_MS,
};
use m2_scenario::dsl::{Check, Obs, ObsKind, ObsLog, Outcome, Scheduler, Severity};
use m2_scenario::scenarios::n0::{Ce128Probe, Ce129Probe};
use m2_scenario::scenarios::n3::N3Ctx;
use m2_scenario::scenarios::n4::N4Ctx;
use m2_scenario::scenarios::n6::N6Ctx;
use m2_scenario::scenarios::obs::{
    EMU_SENT_131, EMU_SENT_132, RECV_CE131, RECV_CE132, TICKET_REFUSED,
};
use m2_scenario::scenarios::{n0, n1, n2, n3, n4, n6, n7};

use crate::cli::LaneSet;
use crate::report::{CheckOutcome, Finding};

/// Per-lane facts a run's scenario evaluation reads.
pub(crate) struct RunCtx {
    pub n0: n0::N0Ctx,
    pub n1: Option<N1Ctx>,
    pub n2: Option<N2Ctx>,
    pub n3: Option<N3Ctx>,
    pub n4: Option<N4Ctx>,
    pub n6: Option<N6Ctx>,
    pub n7: Option<n7::N7Ctx>,
}

/// The outcome of a run's scenario evaluation.
pub(crate) struct Evaluation {
    pub outcomes: Vec<CheckOutcome>,
    pub findings: Vec<Finding>,
    pub all_hard_passed: bool,
}

/// Where a run's checks read observations from.
pub(crate) enum ObsSource {
    /// Live emulator log (real run); `emu` keeps its runtime alive, and the
    /// run reads it once the window closes to ask what went unclaimed.
    ///
    /// Boxed only for its size: the emulator is much larger than the
    /// fabricated variant and grows with every record the lanes collect, so
    /// an unboxed one makes every `ObsSource` that size, dry runs included.
    Emulator {
        obs: Arc<Mutex<ObsLog>>,
        trace: Arc<Mutex<Trace>>,
        ce128_probes: Arc<Mutex<Vec<Ce128Probe>>>,
        ce129_probes: Arc<Mutex<Vec<Ce129Probe>>>,
        emu: Box<Emulator>,
    },
    /// Deterministic fabricated log + empty trace (dry-run).
    Fabricated { log: ObsLog, trace: Trace },
}

/// Run the selected lanes' checks against `obs` and reduce to report outcomes
/// and findings. A lane fires only when it was asked for *and* its context is
/// present.
pub(crate) fn evaluate(obs: &ObsLog, run_ctx: &RunCtx, selected: LaneSet) -> Evaluation {
    let mut outcomes = Vec::new();
    let mut findings = Vec::new();
    let mut all_hard_passed = true;
    // Two conditions, and they mean different things. `selected` is what the
    // operator asked to grade; the context being present is whether the run
    // produced anything to grade it on. A lane nobody asked for is absent
    // from the report rather than passed.
    let mut lanes: Vec<(&str, Vec<Check>)> = Vec::new();
    if selected.n0 {
        lanes.push(("N0", n0::all(&run_ctx.n0)));
    }
    if let (true, Some(ctx)) = (selected.n1, &run_ctx.n1) {
        lanes.push(("N1", n1::all(ctx)));
    }
    if let (true, Some(ctx)) = (selected.n2, &run_ctx.n2) {
        lanes.push(("N2", n2::all(ctx)));
    }
    if let (true, Some(ctx)) = (selected.n3, &run_ctx.n3) {
        lanes.push(("N3", n3::all(ctx)));
    }
    if let (true, Some(ctx)) = (selected.n4, &run_ctx.n4) {
        lanes.push(("N4", n4::all(ctx)));
    }
    if let (true, Some(ctx)) = (selected.n6, &run_ctx.n6) {
        lanes.push(("N6", n6::all(ctx)));
    }
    if let (true, Some(ctx)) = (selected.n7, &run_ctx.n7) {
        lanes.push(("N7", n7::all(ctx)));
    }
    for (lane, checks) in lanes {
        let (out, finds, hard) = run_lane(lane, &checks, obs);
        outcomes.extend(out);
        findings.extend(finds);
        all_hard_passed &= hard;
    }
    Evaluation {
        outcomes,
        findings,
        all_hard_passed,
    }
}

fn run_lane(lane: &str, checks: &[Check], obs: &ObsLog) -> (Vec<CheckOutcome>, Vec<Finding>, bool) {
    let mut scheduler = Scheduler::new();
    let mut outcomes = Vec::new();
    let mut findings = Vec::new();
    let mut all_hard_passed = true;
    for check in checks {
        for result in scheduler.fire(check, obs) {
            let passed = result.outcome == Outcome::Pass;
            // The row's own severity, not the parent check's. A passing row
            // used to inherit the parent's, so a soft row under a hard check
            // printed `hard` on exactly the runs where it passed.
            let soft = result.severity == Severity::Soft;
            if !passed && !soft {
                all_hard_passed = false;
            }
            if !passed {
                findings.push(Finding {
                    severity: if soft { "soft" } else { "hard" }.into(),
                    spec_citation: format!("{lane} {}", check.id),
                    slot: None,
                    evidence: "traces/jamnp.bin".into(),
                    message: match &result.detail {
                        Some(detail) => format!("{}: {}: {detail}", check.id, result.name),
                        None => format!("{}: {}", check.id, result.name),
                    },
                });
            }
            outcomes.push(CheckOutcome {
                id: format!("{}.{}", check.id, result.name),
                lane: lane.into(),
                severity: if soft { "soft" } else { "hard" }.into(),
                passed,
                soft,
                details: match (passed, &result.detail) {
                    (true, _) => "ok".into(),
                    (false, Some(detail)) => detail.clone(),
                    (false, None) => format!("{:?}", result.outcome),
                },
            });
        }
    }
    (outcomes, findings, all_hard_passed)
}

/// The deterministic conforming observation log the dry-run baseline reports
/// on: peer 1 exhibits every N0 contract event (codes 20..=40 plus the named
/// kinds) in an order that satisfies all nine checks.
pub(crate) fn fabricated_obs_log(reference_block_count: usize) -> ObsLog {
    use n0::{
        ALPN_ACCEPTED, ALPN_BUILDER_OK, ALPN_OFFERED, BUILDERS_ACCEPTED, CE128_FIN_BOTH,
        CE128_MAX_RESPECTED, CE129_BOUNDARY_ORDER, CE129_LEN_PREFIXED, CE129_SIZE_CAP,
        CE129_SORTED, CE133_ON_BUILDER, CERT_ED25519, CERT_KEY_MATCH, CERT_SAN_OK, ENDPOINT_DIALED,
        NUT_INITIATED, REANNOUNCED, UP0_FINAL_GENESIS, UP0_KIND0,
    };
    let mut log = ObsLog::new();
    let mut at = 0u64;
    let mut push = |peer: u16, kind: ObsKind| {
        log.push(
            at,
            Obs {
                peer,
                kind,
                at_ms: at,
            },
        );
        at += 10;
    };
    push(n0::PEER_1, ObsKind::Accept);
    push(n0::PEER_1, ObsKind::Other(CERT_ED25519));
    push(n0::PEER_1, ObsKind::Other(CERT_KEY_MATCH));
    push(n0::PEER_1, ObsKind::Other(CERT_SAN_OK));
    push(n0::PEER_1, ObsKind::OpenUp0);
    push(n0::PEER_1, ObsKind::Other(ALPN_ACCEPTED));
    push(n0::PEER_1, ObsKind::Other(ALPN_OFFERED));
    push(n0::PEER_1, ObsKind::Other(ALPN_BUILDER_OK));
    push(n0::PEER_1, ObsKind::Other(NUT_INITIATED));
    push(n0::PEER_1, ObsKind::Other(ENDPOINT_DIALED));
    push(n0::PEER_1, ObsKind::Other(BUILDERS_ACCEPTED));
    push(n0::PEER_1, ObsKind::Other(CE133_ON_BUILDER));
    push(n0::PEER_1, ObsKind::Other(UP0_KIND0));
    push(n0::PEER_1, ObsKind::Other(UP0_FINAL_GENESIS));
    push(n0::PEER_1, ObsKind::Up0Announce);
    push(n0::PEER_1, ObsKind::Other(REANNOUNCED));
    for _ in 0..reference_block_count {
        push(n0::PEER_1, ObsKind::ServesCe128);
    }
    push(n0::PEER_1, ObsKind::Other(CE128_FIN_BOTH));
    push(n0::PEER_1, ObsKind::Other(CE128_MAX_RESPECTED));
    push(n0::PEER_1, ObsKind::Other(CE129_SORTED));
    push(n0::PEER_1, ObsKind::Other(CE129_BOUNDARY_ORDER));
    push(n0::PEER_1, ObsKind::Other(CE129_SIZE_CAP));
    push(n0::PEER_1, ObsKind::Other(CE129_LEN_PREFIXED));
    // N1: the NUT announced an authored block.
    push(n0::PEER_1, ObsKind::AuthorsBlock);
    // N2: the NUT received its CE 131/132 ticket distributions and the
    // emulator's sends; the CE 132 broadcast reaches all five emulated peers.
    push(n0::PEER_1, ObsKind::Other(RECV_CE131));
    for peer in 1..=5u16 {
        push(peer, ObsKind::Other(RECV_CE132));
    }
    push(n0::PEER_1, ObsKind::Other(EMU_SENT_131));
    push(n0::PEER_1, ObsKind::Other(EMU_SENT_132));
    // N2: the NUT reset the stream carrying the unknown-epoch probe.
    // Which ticket it refused is carried by that ticket's plan entry, below;
    // this records only that a refusal happened, for the report.
    push(n0::PEER_1, ObsKind::Other(TICKET_REFUSED));
    log
}

/// The deterministic conforming [`RunCtx`] for the dry-run baseline: the N1
/// lane is built around one real reference-authored NUT block (genuine header
/// and extrinsic types), with its import fact and delivered tickets matching
/// that block; the N2 lane carries a conforming emulator plan and verified NUT
/// ticket facts.
pub(crate) fn fabricated_run_ctx(
    oracle: &std::sync::Arc<m2_reference::oracle::Oracle>,
    reference_block_count: usize,
) -> Result<RunCtx, m2_reference::chain::ChainError> {
    let chain = RefChain::tiny(oracle, 0)?;
    let start = chain.next_slot();
    // Two blocks, the second built on the first: one NUT block on its own can
    // never witness its own posterior state root, which only the header of a
    // block built on top of it commits to.
    let mut authored: Vec<jam_std_common::Block> = Vec::new();
    for slot in start..start + 24 {
        if let Some(block) = chain.author_block(slot)? {
            authored.push(block);
            if authored.len() == 2 {
                break;
            }
        }
    }
    let [first, second] = <[_; 2]>::try_from(authored).map_err(|_| {
        m2_reference::chain::ChainError::Chain("no two emulated slots in 24 slots".into())
    })?;

    // Everything up to and including `first` is reference history; `second` is
    // the block under test, so its parent is the reference best at its slot.
    let blocks = chain.chain_blocks()?;
    let history: Vec<(u32, [u8; 32])> = blocks
        .iter()
        .take_while(|block| block.header.slot <= first.header.slot)
        .map(|block| (block.header.slot, block.header.hash().0))
        .collect();
    let first_root = first.header.hash().0;
    let second_root = second.header.hash().0;
    let slot = first.header.slot;
    let second_slot = second.header.slot;
    // The N0 sync probes: what a conforming node would answer. The reference
    // the CE 128 reply is compared against stops at `first`, since that is all
    // the harness treats as history here; the node is allowed to be ahead.
    let genesis = chain.genesis_hash();
    let reference_chain: Vec<[u8; 32]> = history.iter().skip(1).map(|(_, hash)| *hash).collect();
    let probed_blocks: Vec<n0::ProbedBlock> = blocks
        .iter()
        .skip(1)
        .map(|block| n0::ProbedBlock {
            slot: block.header.slot,
            hash: block.header.hash().0,
            parent: block.header.parent.0,
        })
        .collect();
    let included_ids: Vec<[u8; 32]> = first.extrinsic.tickets.iter().map(|t| t.id().0).collect();
    let slot_start = |slot: u32| JAM_COMMON_ERA * 1000 + slot as u64 * SLOT_PERIOD_MS;
    let import = |block: &jam_std_common::Block, root: Option<[u8; 32]>| ImportFact {
        header_root: block.header.hash().0,
        parent: block.header.parent.0,
        declared_parent_root: block.header.parent_state_root.0,
        reference_parent_root: Some(block.header.parent_state_root.0),
        ok: true,
        root,
        error: None,
    };
    let n1 = N1Ctx {
        // The fabricated node's blocks carry only tickets the emulator
        // delivered, so there are none of its own to account for. The
        // own-ticket allowance is exercised by the N1 lane's own tests.
        own_ticket_ids: Vec::new(),
        reference_best: first_root,
        reference_block_hashes: history.iter().map(|(_, hash)| *hash).collect(),
        reference_chain: history,
        imports: vec![
            // `second` declares `first`'s posterior root, so the witnessed
            // path is the one this baseline exercises. `second` itself has no
            // block built on it, which is a soft "not witnessed" — inherent to
            // the last block of any chain, and reported as such.
            import(&first, Some(second.header.parent_state_root.0)),
            import(&second, Some(second_root)),
        ],
        nut_blocks: vec![
            // Each block is announced at the start of *its own* slot. The two
            // are not necessarily adjacent -- the reference only authors the
            // slots it wins, so the NUT may own the one in between -- and
            // timing the second as `first + one slot period` put its
            // announcement before its slot had begun whenever that happened,
            // failing `n1_timing_within_slot` for one wall-clock slot in
            // several. A fabricated baseline must not depend on the clock.
            NutBlock {
                block: first,
                announced_wall_ms: slot_start(slot),
            },
            NutBlock {
                block: second,
                announced_wall_ms: slot_start(second_slot),
            },
        ],
        delivered_tickets: included_ids
            .into_iter()
            .enumerate()
            .map(|(plan_index, id)| DeliveredTicket {
                plan_index,
                id,
                delivered_at_ms: slot_start(slot) - TICKET_ARRIVAL_LEAD_MS,
                target_epoch: slot / jam_types::epoch_period() + 1,
                probe: false,
                // A conforming node accepts every ticket owed to it.
                refused: false,
            })
            .collect(),
        slot_period_ms: SLOT_PERIOD_MS,
        epoch_period: jam_types::epoch_period(),
        epoch_tail_start: jam_types::epoch_tail_start(),
        max_tickets_per_block: jam_types::max_tickets_per_block(),
    };

    // The fabricated NUT sits at validator index 0, so the emulated peers —
    // the index space the observation log and the ticket facts share — are
    // the other five validators.
    const FAB_NUT_INDEX: u16 = 0;
    const FAB_TARGET_EPOCH: u32 = 3;
    let emu_peers: Vec<u16> = (1..=5).collect();
    // Emulator-sent tickets carry proofs in the low range; the node's own
    // carry the high range, so a forward is never mistaken for a ticket the
    // node generated, and vice versa.
    let emu = |id: u8, proxy: u16, delivery: TicketDelivery, target_epoch: u32| EmuTicket {
        id: [id; 32],
        author: 1,
        attempt: 0,
        proof: [id; 784],
        proxy,
        valid: true,
        delivery,
        slot: 1,
        target_epoch,
        // Set per entry below: the baseline's node refuses the unknown-epoch
        // probe, as it must, and nothing else.
        refused: false,
        fault: None,
        // The baseline is a conforming run, so every planned ticket reached
        // the node on the slot it was planned for: the dry run has nothing to
        // withhold or delay them for.
        delivered_at_ms: Some(JAM_COMMON_ERA * 1000 + SLOT_PERIOD_MS),
    };
    // A ticket the node generates during epoch 2 is for epoch 3, so the facts
    // are stamped inside epoch 2 rather than at an arbitrary instant: the
    // lane derives the epoch it expects from the moment the frame went out.
    // Phase 1, not 0 -- generation starts at `epoch_start + 1` (DESIGN §11
    // N2), and a baseline that sits on the boundary would assert the node may
    // do what the catalogue says it may not.
    let sent_in_epoch_2 =
        JAM_COMMON_ERA * 1000 + u64::from(2 * jam_types::epoch_period() + 1) * SLOT_PERIOD_MS;
    let sent =
        |attempt: u8, proof: [u8; 784], id: [u8; 32], peer: u16, delivery: TicketDelivery| {
            NutTicketFacts {
                epoch: FAB_TARGET_EPOCH,
                ticket: Ce131Ticket { attempt, proof },
                id,
                peer,
                delivery,
                verified: Some(true),
                received_at_ms: sent_in_epoch_2,
            }
        };
    // A ticket's proxy follows from its id, so a baseline that sends one to
    // an arbitrary peer claims a conforming node may ignore the rule. For a
    // uniform id byte `k` the rule reduces to `k mod validators`, because
    // `0x01010101 ≡ 1 (mod 6)`; the bytes below are chosen to designate the
    // peer each ticket is actually sent to, and stay in the high range that
    // separates the node's own tickets from the emulator's.
    let own = |attempt: u8, id_byte: u8, peer: u16, delivery: TicketDelivery| {
        sent(
            attempt,
            [0x80 + attempt; 784],
            [id_byte; 32],
            peer,
            delivery,
        )
    };
    // The block the fabricated node authors in the epoch its tickets are
    // submitted in, a slot after the last of its forwards.
    let fab_block_slot = 2 * jam_types::epoch_period() + 3;
    let proxied_to_the_nut = emu(1, FAB_NUT_INDEX, TicketDelivery::Ce131, FAB_TARGET_EPOCH);
    // Two tickets of its own proxied to one validator each, one it proxies
    // for itself and so broadcasts, and the forward of the ticket another
    // validator proxied to it.
    let mut nut_tickets = vec![
        // 0x85 mod 6 == 1 and 0x86 mod 6 == 2: each goes to the validator the
        // proxy rule names for it.
        own(0, 0x85, 1, TicketDelivery::Ce131),
        own(1, 0x86, 2, TicketDelivery::Ce131),
    ];
    for &peer in &emu_peers {
        // 0x84 mod 6 == 0, the fabricated NUT's own index: this is the one
        // ticket it proxies for itself, and so the one CE 132 broadcast that
        // `n2_self_proxy` judges.
        nut_tickets.push(own(2, 0x84, peer, TicketDelivery::Ce132));
        // The forward of the ticket another validator proxied to it, which is
        // `n2_proxy_duty`'s to judge and not the self-proxy row's.
        nut_tickets.push(sent(
            proxied_to_the_nut.attempt,
            proxied_to_the_nut.proof,
            proxied_to_the_nut.id,
            peer,
            TicketDelivery::Ce132,
        ));
    }
    // A second forward of that ticket to one peer, a slot later. The baseline
    // has to carry one for the same reason it has to carry a fault: a node
    // that never repeats a forward satisfies "it stopped forwarding once the
    // ticket was final" without having stopped anything, so without this the
    // baseline reports `n2_forward_stops_at_finality` unexercised. It is a
    // conforming repeat -- before the node declared the block carrying the
    // ticket final, which is where the rule bites.
    nut_tickets.push(NutTicketFacts {
        received_at_ms: sent_in_epoch_2 + SLOT_PERIOD_MS,
        ..sent(
            proxied_to_the_nut.attempt,
            proxied_to_the_nut.proof,
            proxied_to_the_nut.id,
            emu_peers[0],
            TicketDelivery::Ce132,
        )
    });
    let n2 = N2Ctx {
        target_epoch: FAB_TARGET_EPOCH,
        epoch_start_slot: 0,
        emu_plan: vec![
            proxied_to_the_nut,
            emu(2, 1, TicketDelivery::Ce132, FAB_TARGET_EPOCH),
            // The unknown-epoch probe (`simple.md:335-337`): an epoch the
            // node cannot know yet, which it must reset the stream on -- and
            // in the baseline, does.
            EmuTicket {
                refused: true,
                fault: Some(m2_scenario::ctx::TicketFault::UnknownEpoch),
                ..emu(3, 1, TicketDelivery::Ce132, FAB_TARGET_EPOCH + 2)
            },
            // A ticket proxied to the node over CE 131 that is not its to
            // proxy. A conforming node refuses it, and the baseline has to
            // carry one: `n2_fault_not_forwarded` is a negative rule, and
            // without a CE 131 fault beside the honest forward above there is
            // nothing for it to judge and the run reports it unexercised.
            EmuTicket {
                refused: true,
                fault: Some(m2_scenario::ctx::TicketFault::WrongProxy),
                ..emu(4, 1, TicketDelivery::Ce131, FAB_TARGET_EPOCH)
            },
        ],
        nut_tickets,
        // Two delivered tickets plus one of the node's own: a validator's own
        // ticket belongs in its own block, and the baseline says so.
        //
        // The slot is inside the epoch those tickets are submitted in -- the
        // one before `FAB_TARGET_EPOCH` -- and after the slot the node
        // forwarded them in, so the baseline tells one coherent story:
        // received, forwarded, included, declared final.
        nut_blocks: vec![NutBlockTickets {
            slot: fab_block_slot,
            ticket_ids: vec![[1u8; 32], [2u8; 32], [9u8; 32]],
        }],
        // The node calls its own block final two slots after authoring it,
        // and is still advertising a slot after that. Both halves matter:
        // without the first there is no moment for the stopping rule to be
        // judged against, and without the second a pass would only say the
        // run ended.
        nut_finals: vec![
            NutFinal {
                at_ms: slot_start(fab_block_slot + 2),
                slot: fab_block_slot,
            },
            NutFinal {
                at_ms: slot_start(fab_block_slot + 3),
                slot: fab_block_slot + 1,
            },
        ],
        own_ticket_ids: vec![[9u8; 32]],
        nut_index: FAB_NUT_INDEX,
        emulated_peers: emu_peers,
        slot_period_ms: SLOT_PERIOD_MS,
        epoch_period: jam_types::epoch_period(),
        epoch_tail_start: jam_types::epoch_tail_start(),
        tickets_per_validator: jam_types::tickets_per_validator(jam_types::max_val_count()),
        max_tickets_per_block: jam_types::max_tickets_per_block(),
    };

    // A conforming N3: the package was accepted and shared with both
    // co-guarantors well inside the window. Fabricated like the rest, so a
    // dry run renders the lane instead of dropping it -- a lane that was
    // asked for and has no context is absent from the report, which reads the
    // same as a lane nobody asked for.
    let submitted_at = slot_start(fab_block_slot);
    let fab_co_guarantors = vec![n0::PEER_1, n0::PEER_1 + 1];
    const FAB_REPORT_HASH: [u8; 32] = [0x77; 32];
    const FAB_INCLUDED_HASH: [u8; 32] = [0x88; 32];
    const FAB_SHARED_HASH: [u8; 32] = [0x6b; 32];
    // A package the fabricated submission imports a segment from, and the
    // root its exports sit under. The baseline has to carry one: without an
    // importing submission the mapping row reports itself unexercised, and
    // the point of the baseline is that every row it has is graded.
    const FAB_EXPORTER: [u8; 32] = [0x7e; 32];
    const FAB_EXPORTS_ROOT: [u8; 32] = [0x7f; 32];
    let n3 = N3Ctx {
        nut_index: FAB_NUT_INDEX,
        // One over each submission protocol. CE 146 is graded by the same
        // rules as CE 133 but under its own row names, so a baseline with
        // only one of them reports the other's rows unexercised -- and the
        // test below holds the baseline to grading every row it has.
        submissions: [133u16, 146]
            .into_iter()
            .map(|protocol| m2_scenario::scenarios::n3::SubmittedPackage {
                peer: n0::PEER_1,
                protocol,
                core: 0,
                slot: fab_block_slot,
                package_hash: [0x5a; 32],
                sent_at_wall_ms: submitted_at,
                refused: false,
                reset_code: None,
                connection_end: None,
                fault: None,
                co_guarantors: fab_co_guarantors.clone(),
                imports_from: Some(m2_scenario::scenarios::n3::ImportedFrom {
                    package_hash: FAB_EXPORTER,
                    exports_root: FAB_EXPORTS_ROOT,
                }),
            })
            .collect(),
        shares: fab_co_guarantors
            .iter()
            .enumerate()
            .map(|(i, peer)| m2_scenario::scenarios::n3::SharingSeen {
                peer: *peer,
                core_index: 0,
                shard_count: 6,
                // The resolution the imported package needed: its hash to
                // the root its exports sit under (`simple.md:449`). This is
                // what a conforming node sends, so the baseline passes the
                // mapping row rather than leaving it unexercised.
                mappings: vec![(
                    jam_types::WorkPackageHash::from(FAB_EXPORTER),
                    FAB_EXPORTS_ROOT,
                )],
                bundle: Some(vec![0xab; 32]),
                at_wall_ms: submitted_at + 200 * (i as u64 + 1),
            })
            .collect(),
        // A guaranteed report distributed to both emulated validators, with
        // two signatures from holders of the core, matching the reference.
        reports: fab_co_guarantors
            .iter()
            .map(|peer| m2_scenario::scenarios::n3::ReportSeen {
                peer: *peer,
                report_hash: FAB_REPORT_HASH,
                slot: fab_block_slot,
                signatures: vec![(FAB_NUT_INDEX, [0u8; 64]), (n0::PEER_1, [0u8; 64])],
                encoded_report: vec![0xaa; 32],
                at_wall_ms: submitted_at + 2_000,
            })
            .collect(),
        answers_sharing: true,
        expected_report_hash: Some(FAB_REPORT_HASH),
        emulated_peers: fab_co_guarantors.clone(),
        // A reference-guaranteed report distributed before the node's block,
        // and carried in it.
        // A bundle shared to the node, answered with the reference's hash.
        shared_to_nut: vec![m2_scenario::scenarios::n3::SharedToNut {
            peer: n0::PEER_1,
            core: 0,
            slot: fab_block_slot,
            shard_count: 6,
            expected_report_hash: FAB_SHARED_HASH,
            reply: Some((FAB_SHARED_HASH, [0u8; 64])),
            refused: false,
            reset_code: None,
            fault: None,
            sent_at_wall_ms: submitted_at,
        }],
        distributed: vec![m2_scenario::scenarios::n3::DistributedReport {
            peer: n0::PEER_1,
            core: 1,
            report_hash: FAB_INCLUDED_HASH,
            sent_in_slot: fab_block_slot - 1,
            sent_at_wall_ms: submitted_at,
        }],
        included: vec![(FAB_INCLUDED_HASH, fab_block_slot)],
        authored_slots: vec![fab_block_slot],
    };

    // A conforming node's availability, as the deterministic baseline: both
    // bundle protocols answered in full with justifications that verify,
    // both segment protocols answered one slice per index asked for, an
    // assurance sent in time for a core that carried a report, and the
    // offered assurances included or excluded exactly as their soundness
    // says they should be.
    const FAB_ERASURE_ROOT: [u8; 32] = [0x5c; 32];
    const FAB_ANCHOR: [u8; 32] = [0x4d; 32];
    /// The exports root of the same fabricated package: what a CE 148
    /// request names, and not the erasure root.
    const FAB_SEGMENTS_ROOT: [u8; 32] = [0x6e; 32];
    let served = |protocol: u16| n4::ShardServed {
        protocol,
        erasure_root: FAB_ERASURE_ROOT,
        shard_index: FAB_NUT_INDEX,
        bundle_shard: vec![0x11; 64],
        // The harness did not build this bundle, so it has nothing to
        // compare against; the lane leaves the comparison unmade.
        expected_bundle_shard: None,
        segment_shards: if protocol == 137 {
            vec![0x22; 8]
        } else {
            Vec::new()
        },
        messages: n4::ShardServed::messages_owed(protocol),
        justification: vec![0x33; 33],
        justification_verified: Some(true),
        justification_detail: None,
        refused: false,
    };
    let segments_served = |protocol: u16| n4::SegmentShardsServed {
        segment_count: 2,
        protocol,
        erasure_root: FAB_ERASURE_ROOT,
        shard_index: FAB_NUT_INDEX,
        requested: vec![0, 1],
        shards: vec![vec![0x44; 4], vec![0x55; 4]],
        justifications: if protocol == 140 {
            vec![vec![0x66; 33], vec![0x66; 33]]
        } else {
            Vec::new()
        },
        justifications_verified: if protocol == 140 {
            vec![Some(true), Some(true)]
        } else {
            Vec::new()
        },
        justification_details: Vec::new(),
        ragged: false,
        refused: false,
    };
    // A conforming CE 148 reply: both segments asked for came back whole,
    // each with a proof the engine would walk to the root.
    let whole_segments = n4::SegmentsServed {
        segments_root: FAB_SEGMENTS_ROOT,
        requested: vec![0, 1],
        segments: vec![
            vec![0x77; jam_types::SEGMENT_LEN],
            vec![0x88; jam_types::SEGMENT_LEN],
        ],
        proofs: vec![vec![[0x99; 32]], vec![[0xaa; 32]]],
        proofs_verified: vec![Some(true), Some(true)],
        proof_details: Vec::new(),
        ragged: false,
        proofs_unreadable: false,
        messages: 2,
        refused: false,
    };
    let n4 = n4::N4Ctx {
        nut_index: FAB_NUT_INDEX,
        shards_served: vec![served(137), served(138)],
        segment_shards_served: vec![segments_served(139), segments_served(140)],
        segments_served: vec![whole_segments],
        assurances_seen: vec![n4::AssuranceSeen {
            from: FAB_NUT_INDEX,
            anchor: FAB_ANCHOR,
            cores: vec![0],
            fault: None,
            lead_ms: 2_000,
            reported_cores: vec![0],
        }],
        assurances_offered: vec![
            n4::AssuranceOffered {
                validator: n0::PEER_1,
                anchor: FAB_ANCHOR,
                cores: vec![0],
                sent_in_slot: fab_block_slot - 1,
                included: true,
                had_opportunity: true,
                fault: None,
            },
            n4::AssuranceOffered {
                validator: n0::PEER_1,
                anchor: FAB_ANCHOR,
                cores: vec![0],
                sent_in_slot: fab_block_slot - 1,
                included: false,
                had_opportunity: true,
                fault: Some(n4::AssuranceFaultKind::BadSignature),
            },
        ],
        availability_threshold: jam_types::supermajority_threshold(jam_types::max_val_count()),
        assured_by_core: vec![(0, (0..jam_types::max_val_count()).collect())],
    };

    // N6's fabricated context: a preimage solicited, announced, asked for
    // and included. Every row gets a subject, because a baseline that left
    // one unexercised would ship a lane nothing had ever graded.
    let n6_blob = m2_reference::reports::n6_preimage();
    let n6_hash = jam_std_common::hash_raw(&n6_blob);
    let n6_unsolicited =
        jam_std_common::hash_raw(&m2_reference::reports::n6_unsolicited_preimage());
    let n6 = n6::N6Ctx {
        announced: vec![
            n6::AnnouncedPreimage {
                solicited: n6::Solicited::OnChain,
                peer: n6::ORDINARY_PEER,
                service_id: m2_oracle_proto::DEV_BOOTSTRAP_SERVICE_ID,
                hash: n6_hash,
                length: n6_blob.len() as u32,
                at_wall_ms: submitted_at,
            },
            // The one nobody solicited, which a conforming node leaves
            // alone. Without it the baseline would never grade the row
            // that says so.
            n6::AnnouncedPreimage {
                solicited: n6::Solicited::Never,
                peer: n6::ORDINARY_PEER,
                service_id: m2_oracle_proto::DEV_BOOTSTRAP_SERVICE_ID,
                hash: n6_unsolicited,
                length: 33,
                at_wall_ms: submitted_at + 1,
            },
        ],
        requests: vec![n6::PreimageRequested {
            peer: n6::ORDINARY_PEER,
            asked: n6_hash,
            matched_announcement: true,
            after_announcement_ms: 400,
            answered: true,
            served_matches_hash: true,
        }],
        solicited_on_chain: true,
        included: vec![n6_hash],
        // Validator 0's grid neighbours in the tiny set are 1, 2 and 4;
        // the fabricated node announces to all of them, as a conforming
        // one does.
        nut_announced_to: vec![(1, n6_hash), (2, n6_hash), (4, n6_hash)],
        nut_index: 0,
        emulated_peers: vec![1, 2, 3, 4, 5],
        authored_after_announcement: true,
    };

    // A dry run provokes nobody, so N7 has no context. The lane reports
    // itself unexercised rather than fabricating a node that survived: a
    // dry run's job is to prove the report pipeline works, and a fabricated
    // pass on a robustness lane would be the one row nobody should trust.
    Ok(RunCtx {
        n7: None,
        // The fabricated log is written for a NUT at index 0, which initiates
        // to every emulated peer and so never needs a fallback dial.
        n0: n0::N0Ctx {
            reference_block_count,
            reference_chain: reference_chain.clone(),
            // A conforming node: the ascending walk returns the reference
            // chain itself, within the cap, FIN'd; the state slice is sorted,
            // in range and inside the size cap.
            ce128_probes: vec![n0::Ce128Probe {
                peer: n0::PEER_1,
                max_blocks: 64,
                from: genesis,
                returned: probed_blocks,
                finished: true,
                error: None,
            }],
            ce129_probes: vec![n0::Ce129Probe {
                peer: n0::PEER_1,
                start: [0u8; 31],
                end: [0xffu8; 31],
                max_size: 16 * 1024,
                keys: vec![[0u8; 31], [1u8; 31]],
                boundary_nodes: vec![[7u8; 64]],
                response_bytes: 128,
                entry_bytes: vec![64, 64],
                decoded: true,
                error: None,
            }],
            first_emu_peer: n0::PEER_1,
            handshake_completed: true,
            wrong_alpn_rejected: true,
            builder: Some(n0::BuilderProbeFacts {
                attempted: 21,
                accepted: 21,
                ce133_accepted: true,
                ce133_detail: None,
            }),
            nut_preferred_peers: vec![n0::PEER_1],
            emu_preferred_peers: Vec::new(),
            // A conforming node refuses by resetting the stream, so it ends
            // no connections.
            connection_ends: Vec::new(),
        },
        n1: Some(n1),
        n2: Some(n2),
        n3: Some(n3),
        n4: Some(n4),
        n6: Some(n6),
    })
}

#[cfg(test)]
mod tests {

    use super::*;

    /// Every implemented lane, which is what a run grades unless told
    /// otherwise.
    const ALL_LANES: LaneSet = LaneSet {
        n0: true,
        n1: true,
        n2: true,
        n3: true,
        n7: true,
        n4: true,
        n6: true,
    };

    /// A run that provoked nobody must report no N7 verdicts at all.
    ///
    /// The dry run is exactly that case, and it is the one most likely to
    /// go wrong quietly: `ALL_LANES` asks for N7, so the lane is selected,
    /// and only the missing context keeps it out of the report. A context
    /// built unconditionally would turn "we never poked it" into a clean
    /// robustness pass -- the one row in this suite nobody should be able
    /// to earn without being poked.
    #[test]
    fn a_run_that_provoked_nobody_reports_no_n7_verdict() {
        let run_ctx = fabricated_run_ctx(&m2_reference::oracle::Oracle::for_tests(), 3)
            .expect("fabricated run ctx builds");
        assert!(run_ctx.n7.is_none(), "a dry run provokes nobody");
        let log = fabricated_obs_log(3);
        let eval = evaluate(&log, &run_ctx, ALL_LANES);
        assert!(
            ALL_LANES.n7 && ALL_LANES.needs_provocation(),
            "the lane must be selected, or this proves nothing"
        );
        let n7: Vec<&str> = eval
            .outcomes
            .iter()
            .filter(|o| o.lane == "N7")
            .map(|o| o.id.as_str())
            .collect();
        assert!(n7.is_empty(), "N7 must be absent, not passed; got {n7:?}");
    }

    /// And a run that did provoke reports one verdict per provocation.
    #[test]
    fn a_provoked_run_reports_one_verdict_per_provocation() {
        use m2_scenario::scenarios::n7;
        let mut run_ctx = fabricated_run_ctx(&m2_reference::oracle::Oracle::for_tests(), 3)
            .expect("fabricated run ctx builds");
        run_ctx.n7 = Some(n7::N7Ctx {
            provocations: vec![
                n7::Provocation {
                    peer: n7::PROVOKER_PEER,
                    fault: n7::Fault::UnknownKind(130),
                    outcome: n7::StreamOutcome::Reset,
                    connection_reusable: Some(true),
                    at_wall_ms: 1_000,
                },
                n7::Provocation {
                    peer: n7::PROVOKER_PEER,
                    fault: n7::Fault::UnknownKind(200),
                    outcome: n7::StreamOutcome::Reset,
                    connection_reusable: Some(true),
                    at_wall_ms: 1_100,
                },
            ],
            alive_after: Some(true),
        });
        let log = fabricated_obs_log(3);
        let eval = evaluate(&log, &run_ctx, ALL_LANES);
        let contained = eval
            .outcomes
            .iter()
            .filter(|o| o.lane == "N7" && o.id.contains("contained"))
            .count();
        assert_eq!(contained, 2, "one containment row per provocation");
        assert!(
            eval.outcomes.iter().any(|o| o.lane == "N7"
                && o.id.contains("alive")
                && o.passed),
            "and the liveness row must be reported"
        );
    }

    #[test]
    fn evaluate_reports_lanes() {
        let run_ctx = fabricated_run_ctx(&m2_reference::oracle::Oracle::for_tests(), 3)
            .expect("fabricated run ctx builds");
        let log = fabricated_obs_log(3);
        let eval = evaluate(&log, &run_ctx, ALL_LANES);

        let hard_failures: Vec<&str> = eval
            .outcomes
            .iter()
            .filter(|o| !o.passed)
            .map(|o| o.id.as_str())
            .collect();
        assert!(
            eval.all_hard_passed,
            "fabricated log must pass all lanes; failed: {hard_failures:?}"
        );
        for lane in ["N0", "N1", "N2", "N3", "N4"] {
            let outcomes: Vec<&CheckOutcome> =
                eval.outcomes.iter().filter(|o| o.lane == lane).collect();
            assert!(!outcomes.is_empty(), "lane {lane} must produce outcomes");
            let failed: Vec<&str> = outcomes
                .iter()
                .filter(|o| !o.passed)
                .map(|o| o.id.as_str())
                .collect();
            assert!(
                failed.is_empty(),
                "lane {lane} must all pass; failed: {failed:?}"
            );
        }

        // N4's baseline is not vacuous: the rows have to be *present*, not
        // merely not failing. A lane whose every check reported "not
        // exercised" would pass this loop while grading nothing.
        let n4_rows: Vec<&str> = eval
            .outcomes
            .iter()
            .filter(|o| o.lane == "N4")
            .map(|o| o.id.as_str())
            .collect();
        for row in [
            "n4_ce137_reply_complete",
            "n4_ce137_justification_verifies",
            "n4_ce138_justification_verifies",
            "n4_ce139_140_one_shard_per_request",
            "n4_ce140_justifications_verify",
            "n4_ce148_one_segment_per_request",
            "n4_ce148_one_proof_per_segment",
            "n4_ce148_proofs_verify",
            "n4_ce141_well_formed",
            "n4_ce141_bits_have_reports",
            // Both halves of the inclusion rule: a baseline that only ever
            // offered sound assurances would never reach the second.
            "n4_ce141_valid_assurance_included",
            "n4_ce141_invalid_assurance_excluded",
            "n4_availability_threshold_reached",
        ] {
            assert!(
                n4_rows.iter().any(|id| id.ends_with(row)),
                "N4 must grade {row} on the baseline, not report it unexercised: {n4_rows:?}"
            );
        }
        assert!(
            !n4_rows.iter().any(|id| id.contains("not_exercised")),
            "nothing in the baseline is left ungraded: {n4_rows:?}"
        );

        // The N1 and N2 verdicts come from the ctx facts, not from markers in
        // the log, so the negative case has to change what the node did: drop
        // every CE 132 frame it sent and the broadcast and forwarding duties
        // both go unmet.
        let mut silent = run_ctx;
        let n2 = silent
            .n2
            .as_mut()
            .expect("the fabricated run has an N2 lane");
        n2.nut_tickets
            .retain(|f| f.delivery != m2_scenario::ctx::TicketDelivery::Ce132);
        let eval = evaluate(&log, &silent, ALL_LANES);
        assert!(
            !eval.all_hard_passed,
            "a node that broadcast no CE 132 at all must fail the run"
        );
        let failed: Vec<&str> = eval
            .outcomes
            .iter()
            .filter(|o| o.lane == "N2" && !o.passed)
            .map(|o| o.id.as_str())
            .collect();
        assert!(
            failed
                .iter()
                .any(|id| id.contains("n2_proxy_duty_forwarded")),
            "the unforwarded ticket must be named: {failed:?}"
        );
    }
}
