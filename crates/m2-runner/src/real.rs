//! Real-run N1/N2 context builders (m2-runner §4.4): reference-chain facts,
//! NUT-block imports, and ticket deliveries for the N1/N2 scenario lanes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use codec::Decode;
use jamnp_s::codec::ce131_136::TicketDistribution;
use jamnp_s::codec::up0::{Announcement, Handshake};
use jamnp_s::framing::{CE131, CE132, UP};
use jamnp_s::trace::{Direction as TraceDir, Trace};
use m2_reference::chain::RefChain;
use m2_reference::tickets::{
    first_delivery_slot, plan_tickets, verify_ticket, EmulatedTicket, ScheduledTicket, TicketCtx,
    TicketDelivery as ReferenceDelivery, TicketFault as ReferenceFault,
};
use m2_scenario::ctx::{
    DeliveredTicket, EmuTicket, ImportFact, N1Ctx, N2Ctx, NutBlock, NutBlockTickets, NutFinal,
    NutTicketFacts, TicketDelivery as CtxDelivery, TicketFault as CtxFault, SLOT_PERIOD_MS,
};

use m2_scenario::scenarios::n3::{
    DistributedReport, N3Ctx, ReportSeen, SharingSeen, SubmittedPackage,
};
use m2_scenario::scenarios::n4::{
    AssuranceOffered, N4Ctx, SegmentShardsServed, SegmentsServed, ShardServed,
};

use crate::scenario::RunCtx;

/// Reference-side facts the N1/N2 context builders read after the observation
/// window: the reference chain, the fetched NUT blocks, and the N2 ticket plan.
pub(crate) struct RealRunData {
    pub(crate) ref_chain: Arc<RefChain>,
    pub(crate) nut_blocks: Arc<Mutex<Vec<NutBlock>>>,
    pub(crate) deliveries: Arc<Mutex<Vec<DeliveredTicket>>>,
    pub(crate) ticket_ctx: TicketCtx,
    pub(crate) plan: Vec<ScheduledTicket>,
    pub(crate) target_epoch: u32,
    pub(crate) nut_index: usize,
    pub(crate) emu_indices: Vec<usize>,
    pub(crate) epoch_contexts: EpochContexts,
    /// CE 133 submissions the emulator made, with the node's answers.
    pub(crate) submissions: Arc<Mutex<Vec<SubmittedPackage>>>,
    /// CE 134 shares the node opened.
    pub(crate) sharing_seen: Arc<Mutex<Vec<SharingSeen>>>,
    /// CE 135 distributions the node sent.
    pub(crate) reports_seen: Arc<Mutex<Vec<ReportSeen>>>,
    /// The CE 134 answer planned for this run; its report hash is what the
    /// node's own report is compared against.
    pub(crate) sharing_answer: Arc<Mutex<Option<m2_reference::reports::SharingAnswer>>>,
    /// Reports the emulator distributed to the NUT, for the inclusion rows.
    pub(crate) distributed: Arc<Mutex<Vec<DistributedReport>>>,
    /// CE 134 shares the emulator opened to the NUT, with its answers.
    pub(crate) shared_to_nut: Arc<Mutex<Vec<m2_scenario::scenarios::n3::SharedToNut>>>,
    /// CE 137/138 replies the NUT served.
    pub(crate) shards_served: Arc<Mutex<Vec<ShardServed>>>,
    /// CE 139/140 replies the NUT served.
    pub(crate) segment_shards_served: Arc<Mutex<Vec<SegmentShardsServed>>>,
    pub(crate) segments_served: Arc<Mutex<Vec<SegmentsServed>>>,
    /// CE 141 assurances the NUT broadcast, as they arrived.
    pub(crate) assurances_seen: Arc<Mutex<Vec<m2_emu::avail_io::RawAssurance>>>,
    /// CE 141 assurances the emulator offered the NUT.
    pub(crate) assurances_offered: Arc<Mutex<Vec<AssuranceOffered>>>,
    /// Shard count the availability plan was built for, or `None` where no
    /// plan was ever set.
    pub(crate) avail_shard_count: Arc<Mutex<Option<u16>>>,
    /// Whether a block was seen carrying N6's solicit.
    pub(crate) preimage_solicited: Arc<Mutex<bool>>,
    /// Preimages the harness announced over CE 142.
    pub(crate) preimages_announced: Arc<Mutex<Vec<m2_scenario::scenarios::n6::AnnouncedPreimage>>>,
    /// CE 143 requests the NUT opened back on the announcing connection.
    pub(crate) preimage_requests: Arc<Mutex<Vec<m2_scenario::scenarios::n6::PreimageRequested>>>,
    /// CE 142 announcements the NUT made, by the peer that heard each.
    pub(crate) nut_announced_preimages: m2_scenario::scenarios::n6::HeardAnnouncements,
}

/// Ticket contexts the slot driver captured, one per epoch the run crossed,
/// keyed by the epoch whose tickets each one seals.
pub(crate) type EpochContexts = Arc<Mutex<Vec<(u32, TicketCtx)>>>;

/// The emulated validators' tickets for the epoch after the current one.
///
/// Ring-VRF proving is the single most expensive thing the harness does —
/// five authors times four attempts, tens of seconds — so it is split from
/// [`schedule_tickets`] and run while the node is still starting up.
///
/// The tickets are bound to the tickets-entropy *of the chain as it stands
/// when this is called*, so the caller must have the reference chain seeded
/// up to the current slot first, and `target_epoch` is the epoch that
/// entropy seals. Proving that is overtaken by an epoch boundary leaves
/// tickets whose submission window has already closed; relabelling them for
/// the new epoch would be a lie, since they were never built against its
/// entropy, so the caller regenerates instead (`plan_tickets_for_this_run`).
pub(crate) fn generate_tickets(
    ref_chain: &RefChain,
) -> Result<(TicketCtx, Vec<EmulatedTicket>, u32), m2_reference::chain::ChainError> {
    let ticket_ctx = ref_chain.ticket_ctx()?;
    // The epoch the context itself names, not one derived from the clock
    // here. These were computed separately and could disagree: the context
    // comes from the chain head and the clock does not, so a read taken while
    // the two straddled an epoch boundary labelled the tickets with the epoch
    // after the one they were sealed for.
    let target_epoch = ticket_ctx.epoch;
    let tickets = ref_chain.generate_tickets(&ticket_ctx)?;
    Ok((ticket_ctx, tickets, target_epoch))
}

/// Schedule the generated tickets into the submission window still open for
/// `target_epoch`, as of now.
///
/// Empty when that window has already closed — see
/// [`m2_reference::tickets::plan_tickets`].
pub(crate) fn schedule_tickets(
    ref_chain: &RefChain,
    tickets: &[EmulatedTicket],
    nut_index: usize,
    target_epoch: u32,
) -> Vec<ScheduledTicket> {
    let now_slot = ref_chain.next_slot();
    plan_tickets(
        tickets,
        nut_index,
        first_delivery_slot(now_slot),
        target_epoch,
    )
}

/// Map the reference crate's fault kind onto the lane's mirror of it.
///
/// The two enums are deliberate duplicates: `m2-scenario` cannot name
/// `m2-reference`'s, which it holds only as a dev-dependency. This function is
/// the single place they meet, so a variant added to one and not the other
/// fails to compile here rather than silently grading the wrong thing.
pub(crate) fn map_fault(fault: ReferenceFault) -> CtxFault {
    match fault {
        ReferenceFault::BadProof => CtxFault::BadProof,
        ReferenceFault::WrongProxy => CtxFault::WrongProxy,
        ReferenceFault::StaleEpoch => CtxFault::StaleEpoch,
        ReferenceFault::BadAttempt => CtxFault::BadAttempt,
        ReferenceFault::Duplicate => CtxFault::Duplicate,
        ReferenceFault::Late => CtxFault::Late,
        ReferenceFault::UnknownEpoch => CtxFault::UnknownEpoch,
    }
}

/// The ticket plan split per emulated validator, keyed by peer index, each
/// peer's tickets in the order they are to be delivered.
///
/// The sort is not cosmetic. A peer's sender walks its plan one entry at a
/// time, sleeping until each ticket's slot, so a ticket listed before one
/// scheduled earlier holds that earlier one back. The plan is built in ticket
/// order, and a peer's CE 132 slot is spread by author index while its CE 131
/// slot is the window's first — so for every author but the first, the ticket
/// proxied to the NUT sat behind a broadcast scheduled several slots later and
/// arrived that late. Observed: authors 0, 3 and 4 delivering their CE 131
/// tickets in epoch phases 3, 6 and 7 against a plan that said 3 for all of
/// them, which put them past the window any proxy could still forward in.
pub(crate) fn plans_by_peer(plan: &[ScheduledTicket]) -> HashMap<u16, Vec<ScheduledTicket>> {
    let mut plans: HashMap<u16, Vec<ScheduledTicket>> = HashMap::new();
    for scheduled in plan {
        plans
            .entry(scheduled.ticket.author as u16)
            .or_default()
            .push(scheduled.clone());
    }
    for peer_plan in plans.values_mut() {
        peer_plan.sort_by_key(|s| s.slot);
    }
    plans
}

/// Build the N1/N2 contexts for a real run from the post-window facts.
pub(crate) fn build_real_run_ctx(
    data: &RealRunData,
    trace: &Trace,
    n0: m2_scenario::scenarios::n0::N0Ctx,
) -> Result<RunCtx, m2_reference::chain::ChainError> {
    let nut_blocks = lock(&data.nut_blocks);
    let t = std::time::Instant::now();
    let contexts = ticket_contexts(data);
    crate::run::phase("ctx.ticket_contexts", t);
    let t = std::time::Instant::now();
    let nut_tickets = collect_nut_tickets(trace, &contexts);
    crate::run::phase("ctx.collect_nut_tickets", t);
    let t = std::time::Instant::now();
    let nut_finals = collect_nut_finals(trace);
    crate::run::phase("ctx.collect_nut_finals", t);
    // Every ticket the node announced is one it legitimately held, whether it
    // ran the lottery for it or is forwarding it as proxy. Both lanes need
    // this to tell "the node invented a ticket" from "the node is a validator".
    let own_ticket_ids: Vec<[u8; 32]> = nut_tickets
        .iter()
        .map(|f| m2_reference::tickets::ticket_id(&f.ticket.proof))
        .collect();
    let t = std::time::Instant::now();
    let n1 = build_n1_ctx(
        &data.ref_chain,
        &nut_blocks,
        &lock(&data.deliveries),
        own_ticket_ids.clone(),
    )?;
    crate::run::phase("ctx.build_n1", t);
    let t = std::time::Instant::now();
    let n2 = build_n2_ctx(
        &contexts,
        data,
        nut_tickets,
        nut_finals,
        &nut_blocks,
        own_ticket_ids,
    );
    crate::run::phase("ctx.build_n2", t);
    let t = std::time::Instant::now();
    // Always built, never gated on the lane: when N3 was not selected no
    // package was planned, so the records are empty and the lane is not
    // evaluated. When it was selected and nothing was submitted anyway, the
    // lane says the rule was not exercised, which is the truth and not a pass.
    // Taken before the literal, not inside it. A guard created in a struct
    // literal is a temporary that lives until the end of the whole `let`
    // statement, so reading `data.submissions` twice in one literal takes a
    // non-reentrant lock it is still holding -- which deadlocks, and did:
    // every phase of a real run finished in milliseconds and this one never
    // returned.
    let submissions = lock(&data.submissions).clone();
    let n3 = N3Ctx {
        nut_index: data.nut_index as u16,
        // The harness answers CE 134 whenever it planned a submission, which
        // is exactly when it has a report hash and signatures to answer with.
        answers_sharing: !submissions.is_empty(),
        submissions,
        shares: lock(&data.sharing_seen).clone(),
        reports: lock(&data.reports_seen).clone(),
        expected_report_hash: lock(&data.sharing_answer)
            .as_ref()
            .map(|answer| answer.report_hash),
        emulated_peers: data.emu_indices.iter().map(|i| *i as u16).collect(),
        distributed: lock(&data.distributed).clone(),
        shared_to_nut: lock(&data.shared_to_nut).clone(),
        // Report hashes the node put on chain, with the slot of the block
        // that carried them. Read off the blocks it announced: a report it
        // included is one it actually authored into a block, not one it
        // merely acknowledged on the wire.
        included: nut_blocks
            .iter()
            .flat_map(|nut| {
                let slot = nut.block.header.slot;
                nut.block
                    .extrinsic
                    .guarantees_prehashed()
                    .into_iter()
                    .map(move |(hash, _, _)| (hash.0, slot))
            })
            .collect(),
        authored_slots: nut_blocks.iter().map(|n| n.block.header.slot).collect(),
    };
    crate::run::phase("ctx.build_n3", t);
    let t = std::time::Instant::now();
    let n4 = build_n4_ctx(data, &nut_blocks);
    crate::run::phase("ctx.build_n4", t);
    let n6 = build_n6_ctx(data, &nut_blocks, data.nut_index, &data.emu_indices);
    Ok(RunCtx {
        n0,
        n1: Some(n1),
        n2: Some(n2),
        n3: Some(n3),
        n4: Some(n4),
        n6: Some(n6),
    })
}

/// Build the N6 context from what the preimage announcer recorded.
///
/// `included` is read from the NUT's own blocks rather than from the
/// reference's: the question is whether *this node* put the preimage it
/// obtained into a block it authored, and a reference block carrying it
/// would say nothing about that.
fn build_n6_ctx(
    data: &RealRunData,
    nut_blocks: &[crate::real::NutBlock],
    nut_index: usize,
    emu_indices: &[usize],
) -> m2_scenario::scenarios::n6::N6Ctx {
    let announced = data
        .preimages_announced
        .lock()
        .expect("the announcements")
        .clone();
    let first_announcement = announced.iter().map(|a| a.at_wall_ms).min();
    m2_scenario::scenarios::n6::N6Ctx {
        announced,
        requests: data.preimage_requests.lock().expect("the requests").clone(),
        solicited_on_chain: *data.preimage_solicited.lock().expect("the solicit flag"),
        nut_announced_to: data
            .nut_announced_preimages
            .lock()
            .expect("the gossip")
            .clone(),
        nut_index: nut_index as u16,
        emulated_peers: emu_indices.iter().map(|&i| i as u16).collect(),
        included: nut_blocks
            .iter()
            .flat_map(|n| n.block.extrinsic.preimages.iter())
            .map(|p| jam_std_common::hash_raw(p.blob()))
            .collect(),
        // Only blocks authored *after* the announcement can carry it, and a
        // run where the node authored none is a run where "not included" is
        // a fact about the lottery.
        authored_after_announcement: {
            if let Some(at) = first_announcement {
                eprintln!(
                    "[preimage] announced at wall {at} ms (slot {}); the NUT authored {} \
                     block(s), {} of them after",
                    m2_reference::chain::slot_of_ms(at),
                    nut_blocks.len(),
                    nut_blocks
                        .iter()
                        .filter(|n| m2_reference::chain::slot_start_ms(n.block.header.slot) > at)
                        .count()
                );
            }
            first_announcement.is_some_and(|at| {
                nut_blocks
                    .iter()
                    .any(|n| m2_reference::chain::slot_start_ms(n.block.header.slot) > at)
            })
        },
    }
}

/// Build the N4 context from what the availability driver recorded.
///
/// This is where the justifications are actually checked: the emulator
/// recorded the bytes, and the engine -- through the oracle -- says whether
/// they prove anything. Doing it here rather than on the wire keeps the
/// round trips out of the observation window, where a slow oracle would
/// shift the timing the other lanes are graded on.
fn build_n4_ctx(data: &RealRunData, nut_blocks: &[NutBlock]) -> N4Ctx {
    // The count the report declared, not the validator count this harness
    // assumes: a report may only be included if the two agree, but a node
    // that coded into some other number is exactly what a check should be
    // able to say, and substituting our own would hide it.
    let shard_count = lock(&data.avail_shard_count).unwrap_or_else(jam_types::max_val_count);

    let mut shards_served = lock(&data.shards_served).clone();
    verify_served_shards(data.ref_chain.oracle(), shard_count, &mut shards_served);
    let mut segment_shards_served = lock(&data.segment_shards_served).clone();
    verify_segment_shards(
        data.ref_chain.oracle(),
        shard_count,
        &mut segment_shards_served,
    );
    let mut segments_served = lock(&data.segments_served).clone();
    verify_import_proofs(data.ref_chain.oracle(), &mut segments_served);
    // Read once: the chain is another process and this is asked for twice,
    // here and for the engaged cores below.
    let reference_blocks = data.ref_chain.chain_blocks().unwrap_or_default();
    // Every block the harness has seen the node on. Which one it assures is
    // its own choice -- the head two seconds before a slot -- so the rule is
    // that the anchor names a block that exists, not a block the harness
    // picked.
    let known_anchors: Vec<[u8; 32]> = nut_blocks
        .iter()
        .map(|nut| nut.block.header.hash().0)
        .chain(reference_blocks.iter().map(|block| block.header.hash().0))
        .collect();
    // Cores that carried a report at those blocks, which is what an
    // assurance may claim.
    //
    // Off the whole chain, not only the node's own blocks. A core is
    // engaged by whichever block carries the guarantee, and the node
    // authors one slot in six -- so a report the *reference* included
    // engages a core just as much, and reading only the node's blocks
    // misses nearly all of them.
    //
    // And off the report, not off `guarantees_prehashed`. That returns
    // `(WorkReportHash, Slot, &GuaranteeSignatures)` and this read its
    // second element as a core index -- a truncated slot, which no core
    // index can equal, so `n4_ce141_bits_have_reports` failed every
    // assurance the node ever sent (`findings.md` §23).
    let reported_cores: Vec<u16> = nut_blocks
        .iter()
        .map(|nut| &nut.block)
        .chain(reference_blocks.iter())
        .flat_map(|block| {
            block
                .extrinsic
                .guarantees
                .iter()
                .map(|guarantee| guarantee.report.core_index)
        })
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();

    let assurances_seen = m2_emu::avail_io::assurances_for_lane(
        &lock(&data.assurances_seen),
        data.nut_index as u16,
        &known_anchors,
        &reported_cores,
        |at_wall_ms| {
            // Milliseconds before the start of the slot it was sent for,
            // which is the slot after the one it arrived in.
            let slot = m2_reference::chain::slot_of_ms(at_wall_ms);
            m2_reference::chain::slot_start_ms(slot + 1) as i64 - at_wall_ms as i64
        },
    );

    let mut assurances_offered = lock(&data.assurances_offered).clone();
    resolve_assurance_inclusion(&mut assurances_offered, nut_blocks);

    N4Ctx {
        nut_index: data.nut_index as u16,
        shards_served,
        segment_shards_served,
        segments_served,
        assurances_seen,
        assurances_offered,
        availability_threshold: jam_types::supermajority_threshold(jam_types::max_val_count()),
        assured_by_core: assured_by_core(nut_blocks),
    }
}

/// Decide, for each assurance the harness offered, whether the node carried
/// it and whether it ever had the chance.
///
/// **One block, not "some later block".** An assurances extrinsic is refused
/// unless every assurance in it anchors the block's *parent*
/// (`BadAttestationParent`), so an assurance can be carried in exactly one
/// block: the child of the block it names. A node that authored some other
/// block owed nothing, and grading it against "any later block" fails a node
/// doing exactly the right thing (findings.md §14).
///
/// Public because `m2-sim`'s inclusion test grades the same facts the runner
/// does, through this function rather than a second copy of the rule.
pub fn resolve_assurance_inclusion(offered: &mut [AssuranceOffered], nut_blocks: &[NutBlock]) {
    for offer in &mut *offered {
        // `sent_in_slot` is the slot the assurance was sent *for*: it goes
        // out a couple of seconds before that slot begins, aiming at the
        // block authored in it. A block of that slot or later is one the
        // node could still have put it in; an earlier one was already
        // authored when the assurance arrived.
        let child: Option<&NutBlock> = nut_blocks.iter().find(|nut| {
            nut.block.header.parent.0 == offer.anchor && nut.block.header.slot >= offer.sent_in_slot
        });
        offer.had_opportunity = child.is_some();
        offer.included = child.is_some_and(|nut| {
            nut.block
                .extrinsic
                .assurances
                .iter()
                .any(|a| a.signature.val_index == offer.validator)
        });
    }
    report_inclusion_opportunity(offered, nut_blocks);
}

/// Say why no assurance had an opportunity, when none did.
///
/// The same reason the `Ok(None)` arms elsewhere say why they returned
/// nothing: `n4_ce141_inclusion` reports *not exercised* both when the
/// harness offered nothing and when it offered plenty and the node never
/// authored the one block that could have carried any of them. Those are
/// different facts about a run and they print the same line, which is how a
/// reader concludes the rows are broken when the window simply missed.
///
/// Printed rather than made a finding: it is a fact about this run's
/// timing, not about the node.
fn report_inclusion_opportunity(offered: &[AssuranceOffered], nut_blocks: &[NutBlock]) {
    if offered.is_empty() || offered.iter().any(|offer| offer.had_opportunity) {
        return;
    }
    let slots: Vec<u32> = offered.iter().map(|offer| offer.sent_in_slot).collect();
    let (first, last) = (
        slots.iter().min().copied().unwrap_or(0),
        slots.iter().max().copied().unwrap_or(0),
    );
    let authored: Vec<u32> = nut_blocks.iter().map(|n| n.block.header.slot).collect();
    eprintln!(
        "[availability] none of {} assurance offer(s) across slots {first}..={last} could be \
         carried: an assurance is valid in exactly one block, the child of the block it \
         anchors, and the NUT authored slots {authored:?}",
        offered.len()
    );
}

/// Ask the engine whether each served bundle shard's justification proves it.
///
/// Done after the observation window rather than on the wire: the emulator
/// records bytes, the engine decides, and holding the round trips out of the
/// window keeps a slow oracle from shifting the timing the other lanes are
/// graded on.
///
/// Public because `m2-sim`'s N4 test grades the same facts the runner does.
/// A test that re-implemented this would be checking its own copy of the
/// rule rather than the one a run uses.
pub fn verify_served_shards(
    oracle: &Arc<m2_reference::oracle::Oracle>,
    shard_count: u16,
    served: &mut [ShardServed],
) {
    for shard in served {
        if shard.refused {
            continue;
        }
        match m2_reference::availability::check_served_shard(
            oracle,
            m2_reference::availability::ServedShard {
                protocol: shard.protocol,
                erasure_root: shard.erasure_root,
                shard_index: shard.shard_index,
                shard_count,
                bundle_shard: shard.bundle_shard.clone(),
                segment_shards: shard.segment_shards.clone(),
                justification: shard.justification.clone(),
            },
        ) {
            Ok(check) => {
                shard.justification_verified = check.verified;
                shard.justification_detail = check.detail;
            }
            // The oracle refusing to answer is the harness's problem, not
            // the node's. Left unverified with the reason on it, which the
            // lane reports as a justification it could not read rather than
            // as a proof that failed.
            Err(e) => shard.justification_detail = Some(format!("the oracle could not say: {e}")),
        }
    }
}

/// The same for CE 140's per-slice justifications.
pub fn verify_segment_shards(
    oracle: &Arc<m2_reference::oracle::Oracle>,
    shard_count: u16,
    served: &mut [SegmentShardsServed],
) {
    for shards in served {
        if shards.refused || shards.ragged || shards.protocol != 140 {
            continue;
        }
        // One justification per slice, paired by position: the reply carries
        // no indices, so position is the only thing tying the two together.
        for (i, slice) in shards.shards.iter().enumerate() {
            let Some(justification) = shards.justifications.get(i) else {
                shards.justifications_verified.push(None);
                shards
                    .justification_details
                    .push(Some("no justification was sent for this slice".into()));
                continue;
            };
            let segment_index = shards.requested.get(i).copied().unwrap_or(i as u16);
            match m2_reference::availability::check_segment_shard(
                oracle,
                shards.erasure_root,
                shards.shard_index,
                shard_count,
                segment_index,
                // The size of the tree the proof walks, which is every
                // segment the package exported -- not the handful this
                // request asked for. They coincide only when a run asks
                // for all of them, which is why the simulated node could
                // not see this (`findings.md` §26).
                shards.segment_count,
                slice.clone(),
                justification.clone(),
            ) {
                Ok(check) => {
                    shards.justifications_verified.push(check.verified);
                    shards.justification_details.push(check.detail);
                }
                Err(e) => {
                    shards.justifications_verified.push(None);
                    shards
                        .justification_details
                        .push(Some(format!("the oracle could not say: {e}")));
                }
            }
        }
    }
}

/// Ask the engine whether each CE 148 import proof puts its segment under
/// the segments root.
///
/// Done after the observation window, for the reason the other two are: the
/// emulator records bytes, the engine decides, and holding the round trips
/// out of the window keeps a slow oracle from shifting the timing the other
/// lanes are graded on.
///
/// Public because `m2-sim`'s N4 test grades the same facts a run does.
pub fn verify_import_proofs(
    oracle: &Arc<m2_reference::oracle::Oracle>,
    served: &mut [SegmentsServed],
) {
    for reply in served {
        if reply.refused || reply.ragged || reply.proofs_unreadable {
            continue;
        }
        // One proof per segment, paired by position: the reply carries no
        // indices, so position is the only thing tying the two together.
        for (i, segment) in reply.segments.iter().enumerate() {
            let Some(proof) = reply.proofs.get(i) else {
                reply.proofs_verified.push(None);
                reply
                    .proof_details
                    .push(Some("no proof was sent for this segment".into()));
                continue;
            };
            // The index the segment was asked for under, not its position
            // in the reply: the proof is over that leaf of the tree, and
            // checking it at the wrong index fails a node that answered
            // correctly.
            let segment_index = reply.requested.get(i).copied().unwrap_or(i as u16);
            match m2_reference::availability::check_import_proof(
                oracle,
                reply.segments_root,
                segment_index,
                segment.clone(),
                proof.clone(),
            ) {
                Ok(check) => {
                    reply.proofs_verified.push(check.verified);
                    reply.proof_details.push(check.detail);
                }
                Err(e) => {
                    reply.proofs_verified.push(None);
                    reply
                        .proof_details
                        .push(Some(format!("the oracle could not say: {e}")));
                }
            }
        }
    }
}

/// Which validators assured each core, as the NUT's own blocks recorded it.
fn assured_by_core(nut_blocks: &[NutBlock]) -> Vec<(u16, Vec<u16>)> {
    let cores = jam_types::core_count();
    let mut by_core: Vec<(u16, Vec<u16>)> = (0..cores).map(|core| (core, Vec::new())).collect();
    for nut in nut_blocks {
        for assurance in nut.block.extrinsic.assurances.iter() {
            let bitfield = jam_types::Encode::encode(&assurance.statement.bitfield);
            for core in 0..cores {
                let Some(byte) = bitfield.get(core as usize / 8) else {
                    continue;
                };
                if byte & (1 << (core % 8)) != 0 {
                    let who = assurance.signature.val_index;
                    let holders = &mut by_core[core as usize].1;
                    if !holders.contains(&who) {
                        holders.push(who);
                    }
                }
            }
        }
    }
    // Cores nobody assured are left out: a core with no report is not a
    // core that failed to reach the threshold.
    by_core.retain(|(_, holders)| !holders.is_empty());
    by_core
}

/// Every ticket context the harness can verify a proof against, by the epoch
/// whose tickets it seals.
///
/// A ring-VRF ticket proof is bound to the tickets-entropy of the epoch it
/// targets, so one context judges one epoch, and the entropy for epoch
/// `e + 1` can only be read while the chain is in epoch `e`. A run spans
/// several epochs and the node generates afresh in each, so one context is
/// never enough: the set is the one the harness generated its own tickets
/// against, plus the one the slot driver captured on each boundary it
/// crossed, plus a last read now. An epoch missing from the set is a ticket
/// the lane reports as unjudged rather than as unverified.
fn ticket_contexts(data: &RealRunData) -> TicketContexts {
    let mut by_epoch = vec![(data.target_epoch, data.ticket_ctx.clone())];
    by_epoch.extend(lock(&data.epoch_contexts).iter().cloned());
    // A last read, for an epoch the driver never reached -- it stops when the
    // observation window closes while the node may keep generating. Filed
    // under the epoch the context names: by this point the driver has been
    // aborted for a while, so the head is further behind the clock here than
    // anywhere else in the run, and a clock-derived label is most wrong
    // exactly where it was being used.
    if let Ok(late) = data.ref_chain.ticket_ctx() {
        by_epoch.push((late.epoch, late));
    }
    // First entry per epoch wins, and the generation-time context leads, so a
    // later read never displaces the one the emulator's own tickets were
    // built against.
    let mut seen = Vec::new();
    by_epoch.retain(|(epoch, _)| {
        let fresh = !seen.contains(epoch);
        seen.push(*epoch);
        fresh
    });
    TicketContexts { by_epoch }
}

/// The ticket contexts a run can verify proofs against, keyed by target epoch.
pub struct TicketContexts {
    by_epoch: Vec<(u32, TicketCtx)>,
}

impl TicketContexts {
    /// The contexts a self-test holds, newest-wins per epoch.
    ///
    /// Public for the same reason [`build_n1_ctx`] is: a simulated node is
    /// graded through the harness's own trace-to-facts path, not a copy of it.
    ///
    /// The epoch here is the caller's to choose, and a self-test's need not
    /// be [`TicketCtx::epoch`]. A live run's must be -- see
    /// [`ticket_contexts`] -- but a simulated node whose chain never leaves
    /// genesis seals its tickets with genesis entropy while the virtual clock
    /// is hundreds of thousands of epochs along, and the number is then only
    /// a key: the lottery and the grading use the same context, so they agree
    /// whatever it is called. Asserting the live-run invariant here fails
    /// that setup for no gain; `the_context_names_the_epoch_its_entropy_seals`
    /// in `m2-reference` pins it where it means something.
    pub fn from_epochs(by_epoch: Vec<(u32, TicketCtx)>) -> Self {
        Self { by_epoch }
    }
}

impl TicketContexts {
    /// Whether a ticket for `epoch` verifies, or `None` when no context
    /// covers that epoch — which is not the same answer as "it did not
    /// verify", and the lane keeps the two apart.
    fn verify(&self, epoch: u32, attempt: u8, proof: &[u8; 784]) -> Option<bool> {
        let (_, ctx) = self.by_epoch.iter().find(|(e, _)| *e == epoch)?;
        Some(verify_ticket(ctx, attempt, proof))
    }

    /// The context the emulator's own tickets were generated against.
    fn planned(&self) -> &TicketCtx {
        &self.by_epoch[0].1
    }
}

/// N1 facts: the reference chain with its slots, the fetched NUT blocks with
/// their import outcomes, and the tickets the emulator delivered to the NUT.
///
/// The chain is read before the imports run, so the reference best block is
/// the one the run actually ended on and not one re-imported here.
/// Public so the self-test can grade a simulated node through the *same*
/// assembly a live run uses.
///
/// A copy of this in a test would prove the N1 predicates again and say
/// nothing about the step that has actually gone wrong twice: turning what
/// came off the wire into the facts a lane reads.
pub fn build_n1_ctx(
    ref_chain: &RefChain,
    nut_blocks: &[NutBlock],
    deliveries: &[DeliveredTicket],
    own_ticket_ids: Vec<[u8; 32]>,
) -> Result<N1Ctx, m2_reference::chain::ChainError> {
    let chain = ref_chain.chain_blocks()?;
    let reference_best = chain
        .last()
        .map(|block| block.header.hash().0)
        .unwrap_or_else(|| ref_chain.genesis_hash());
    let reference_block_hashes: Vec<[u8; 32]> =
        chain.iter().map(|block| block.header.hash().0).collect();
    let reference_chain = chain
        .iter()
        .map(|block| (block.header.slot, block.header.hash().0))
        .collect();
    let imports = nut_blocks
        .iter()
        .map(|nut| {
            let outcome = ref_chain.import_nut_block(&nut.block)?;
            Ok(ImportFact {
                header_root: outcome.header_root,
                parent: outcome.parent,
                declared_parent_root: outcome.declared_parent_root,
                reference_parent_root: outcome.reference_parent_root,
                ok: outcome.ok,
                root: outcome.root,
                error: outcome.error,
            })
        })
        .collect::<Result<Vec<_>, m2_reference::chain::ChainError>>()?;
    Ok(N1Ctx {
        reference_best,
        reference_block_hashes,
        reference_chain,
        nut_blocks: nut_blocks.to_vec(),
        imports,
        delivered_tickets: deliveries.to_vec(),
        own_ticket_ids,
        slot_period_ms: SLOT_PERIOD_MS,
        epoch_period: jam_types::epoch_period(),
        epoch_tail_start: jam_types::epoch_tail_start(),
        max_tickets_per_block: jam_types::max_tickets_per_block(),
    })
}

/// N2 facts: the emulator's ticket plan plus every ticket the NUT distributed
/// back (CE 131/132 frames), and the NUT-authored block's ticket extrinsic.
fn build_n2_ctx(
    contexts: &TicketContexts,
    data: &RealRunData,
    nut_tickets: Vec<NutTicketFacts>,
    nut_finals: Vec<NutFinal>,
    nut_blocks: &[NutBlock],
    own_ticket_ids: Vec<[u8; 32]>,
) -> N2Ctx {
    let target_epoch = data.target_epoch;
    let epoch_start_slot = target_epoch * jam_types::epoch_period();
    // Tickets for `target_epoch` can only be submitted during the epoch before
    // it, so the block to judge is one authored in *that* epoch. Taking simply
    // the newest block judged a block from a later epoch against tickets it
    // could not legally have carried -- a check no node could pass once a run
    // outlived the epoch it generated for.
    let submission_epoch = target_epoch.saturating_sub(1);
    // Every block of that epoch, ascending. Taking only the newest left the
    // lane's prohibitions -- no faulted ticket, nothing the harness never
    // sent -- asserted of one block out of however many the node authored.
    let mut blocks: Vec<&NutBlock> = nut_blocks
        .iter()
        .filter(|nut| nut.block.header.slot / jam_types::epoch_period() == submission_epoch)
        .collect();
    blocks.sort_by_key(|nut| nut.block.header.slot);
    let nut_blocks_in_epoch: Vec<NutBlockTickets> = blocks
        .into_iter()
        .map(|nut| NutBlockTickets {
            slot: nut.block.header.slot,
            ticket_ids: nut
                .block
                .extrinsic
                .tickets
                .iter()
                .map(|t| t.id().0)
                .collect(),
        })
        .collect();
    N2Ctx {
        target_epoch,
        epoch_start_slot,
        emu_plan: plan_emu_tickets(&data.plan, contexts.planned(), &lock(&data.deliveries)),
        nut_tickets,
        nut_blocks: nut_blocks_in_epoch,
        nut_finals,
        own_ticket_ids,
        nut_index: data.nut_index as u16,
        emulated_peers: data.emu_indices.iter().map(|&i| i as u16).collect(),
        slot_period_ms: SLOT_PERIOD_MS,
        epoch_period: jam_types::epoch_period(),
        epoch_tail_start: jam_types::epoch_tail_start(),
        tickets_per_validator: jam_types::tickets_per_validator(jam_types::max_val_count()),
        max_tickets_per_block: jam_types::max_tickets_per_block(),
    }
}

/// Map the reference ticket plan onto the N2 lane's [`EmuTicket`] facts.
///
/// `deliveries` is what the emulator actually put on the wire, which is a
/// subset of the plan: the sender withholds a ticket the node is in no state
/// to accept, and a connection can die mid-run. The lane needs the difference,
/// because a rule about a ticket the NUT never received was not exercised
/// rather than broken.
/// The emulator's own plan as the lanes read it, delivery facts folded in.
///
/// Public for the self-test, like [`build_n1_ctx`]: what the harness believes
/// it delivered is half of every proxy-duty and inclusion verdict, and a copy
/// of this in a test would grade the copy.
pub fn plan_emu_tickets(
    plan: &[ScheduledTicket],
    ticket_ctx: &TicketCtx,
    deliveries: &[DeliveredTicket],
) -> Vec<EmuTicket> {
    plan.iter()
        .map(|scheduled| {
            let ticket = &scheduled.ticket;
            // By plan index, not by `(id, epoch)`. Three faults reuse an
            // honest ticket's proof, so they share its id, and `Duplicate`
            // shares its epoch too -- the pair stopped identifying a delivery
            // the moment the catalogue grew past the one probe it was widened
            // for.
            let delivery = deliveries
                .iter()
                .find(|d| d.plan_index == scheduled.plan_index);
            EmuTicket {
                // Keyed on the epoch as well as the id: the unknown-epoch
                // probe reuses a real ticket's proof, so the two entries share
                // an id and differ only in the epoch they name. Matching on
                // the id alone marked the probe delivered whenever the ticket
                // it borrowed from was.
                delivered_at_ms: delivery.map(|d| d.delivered_at_ms),
                refused: delivery.is_some_and(|d| d.refused),
                fault: scheduled.fault.map(map_fault),
                id: ticket.id,
                author: ticket.author as u16,
                attempt: ticket.attempt,
                proof: ticket.proof,
                proxy: ticket.proxy as u16,
                valid: verify_ticket(ticket_ctx, ticket.attempt, &ticket.proof),
                delivery: match scheduled.delivery {
                    ReferenceDelivery::Ce131 => CtxDelivery::Ce131,
                    ReferenceDelivery::Ce132 => CtxDelivery::Ce132,
                },
                slot: scheduled.slot,
                target_epoch: scheduled.target_epoch,
            }
        })
        .collect()
}

/// Every ticket the NUT distributed to the emulators (CE 131/132 frames the
/// NUT sent), verified against the reference ticket context.
/// Every CE 131/132 frame the node put on the wire, as the N2 lane's facts.
///
/// Public so a self-test can grade a simulated node through this step. It is
/// the one that has gone wrong before: the CE 131 decoder defect closed on
/// 2026-10-30 made the node's whole ticket output invisible, and every lane
/// above it read an empty list as a node that had sent nothing.
pub fn collect_nut_tickets(trace: &Trace, contexts: &TicketContexts) -> Vec<NutTicketFacts> {
    trace
        .records()
        .iter()
        .filter(|rec| rec.direction == TraceDir::Tx && matches!(rec.stream_kind, CE131 | CE132))
        .filter_map(|rec| {
            let Ok(distribution) = TicketDistribution::decode(&mut &rec.bytes[..]) else {
                return None;
            };
            let ticket = distribution.ticket;
            let epoch = distribution.epoch_index;
            Some(NutTicketFacts {
                epoch,
                ticket,
                // The wire carries attempt and proof; the id is the proof's
                // VRF output, and the lane needs it to judge the proxy the
                // node chose.
                id: m2_reference::tickets::ticket_id(&ticket.proof),
                peer: rec.peer_index,
                // The stream kind the node chose, not a guess from the peer
                // it reached: CE 131 names a proxy, CE 132 names everyone.
                delivery: match rec.stream_kind {
                    CE131 => CtxDelivery::Ce131,
                    _ => CtxDelivery::Ce132,
                },
                verified: contexts.verify(epoch, ticket.attempt, &ticket.proof),
                received_at_ms: rec.wall_ts,
            })
        })
        .collect()
}

/// Every `Final` the NUT advertised over UP 0, in the order it sent them.
///
/// Both UP 0 message shapes carry one: the handshake that opens the stream
/// and every announcement after it. They are told apart the way the
/// emulator's own UP 0 handler tells them apart (`m2-emu`'s `handle_up0`) --
/// an announcement is a header followed by the `Final`, a handshake is the
/// `Final` followed by the leaves, and only one of the two decodes -- so a
/// frame that is neither is skipped rather than guessed at.
/// Public alongside [`collect_nut_tickets`]: the stopping rule is judged
/// against the node's own account of finality, so a self-test has to read it
/// off the wire the same way a live run does.
pub fn collect_nut_finals(trace: &Trace) -> Vec<NutFinal> {
    trace
        .records()
        .iter()
        .filter(|rec| rec.direction == TraceDir::Tx && rec.stream_kind == UP)
        .filter_map(|rec| {
            let slot = match Announcement::decode(&mut &rec.bytes[..]) {
                Ok(announcement) => announcement.final_block.slot,
                Err(_) => {
                    Handshake::decode(&mut &rec.bytes[..])
                        .ok()?
                        .final_block
                        .slot
                }
            };
            Some(NutFinal {
                at_ms: rec.wall_ts,
                slot,
            })
        })
        .collect()
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::Encode;
    use jamnp_s::codec::ce131_136::Ticket;
    use jamnp_s::trace::TraceRecord;
    use m2_reference::chain::ChainError;

    /// The ticket contexts a test run holds: one, covering `epoch`.
    fn contexts_for(epoch: u32, ctx: TicketCtx) -> TicketContexts {
        TicketContexts {
            by_epoch: vec![(epoch, ctx)],
        }
    }

    fn record(
        direction: TraceDir,
        peer: u16,
        kind: u8,
        bytes: Vec<u8>,
        wall_ts: u64,
    ) -> TraceRecord {
        TraceRecord {
            direction,
            peer_index: peer,
            stream_kind: kind,
            stream_id: 0,
            mono_ts: 0,
            wall_ts,
            bytes,
        }
    }

    #[test]
    fn run_collect_nut_tickets() -> Result<(), ChainError> {
        let ref_chain = RefChain::tiny(&m2_reference::oracle::Oracle::for_tests(), 0)?;
        let ticket_ctx = ref_chain.ticket_ctx()?;
        let tickets = ref_chain.generate_tickets(&ticket_ctx)?;
        let ticket = &tickets[0];
        let distribution = TicketDistribution {
            epoch_index: 7,
            ticket: Ticket {
                attempt: ticket.attempt,
                proof: ticket.proof,
            },
        };

        let mut trace = Trace::default();
        trace.push(record(TraceDir::Tx, 2, CE131, distribution.encode(), 1234));
        let contexts = contexts_for(7, ticket_ctx);
        let facts = collect_nut_tickets(&trace, &contexts);
        assert_eq!(
            facts.len(),
            1,
            "one NUT CE 131 distribution yields one fact"
        );
        assert_eq!(facts[0].epoch, 7);
        assert_eq!(facts[0].peer, 2);
        assert_eq!(facts[0].ticket.attempt, ticket.attempt);
        assert_eq!(facts[0].received_at_ms, 1234);
        assert_eq!(facts[0].delivery, CtxDelivery::Ce131);
        assert_eq!(
            facts[0].verified,
            Some(true),
            "a generated ticket verifies against its own epoch's context"
        );

        // A non-decodable CE 131 frame from the NUT is skipped, not a fact.
        let mut bad = Trace::default();
        bad.push(record(TraceDir::Tx, 2, CE131, vec![0xde, 0xad], 1));
        assert!(
            collect_nut_tickets(&bad, &contexts).is_empty(),
            "garbage CE 131 is skipped"
        );
        Ok(())
    }

    /// A proof is bound to the entropy of the epoch it targets, so a ticket
    /// for an epoch the harness holds no context for cannot be judged at all.
    /// Verifying it against the wrong epoch's ring would report a conforming
    /// node's ticket as a forged one.
    #[test]
    fn run_nut_tickets_for_an_uncovered_epoch_are_unjudged() -> Result<(), ChainError> {
        let ref_chain = RefChain::tiny(&m2_reference::oracle::Oracle::for_tests(), 0)?;
        let ticket_ctx = ref_chain.ticket_ctx()?;
        let tickets = ref_chain.generate_tickets(&ticket_ctx)?;
        let ticket = &tickets[0];
        let distribution = TicketDistribution {
            epoch_index: 9,
            ticket: Ticket {
                attempt: ticket.attempt,
                proof: ticket.proof,
            },
        };
        let mut trace = Trace::default();
        trace.push(record(TraceDir::Tx, 2, CE132, distribution.encode(), 1));
        let facts = collect_nut_tickets(&trace, &contexts_for(7, ticket_ctx));
        assert_eq!(facts[0].verified, None, "epoch 9 has no context");
        assert_eq!(facts[0].delivery, CtxDelivery::Ce132);
        Ok(())
    }

    /// The NUT's own account of finality, which only UP 0 carries. Both
    /// message shapes hold a `Final` and the collector tells them apart by
    /// which one decodes, so a handshake must not be read as an
    /// announcement -- the two put the `Final` at opposite ends.
    #[test]
    fn run_collect_nut_finals_reads_both_up0_shapes() -> Result<(), ChainError> {
        use jam_types::HeaderHash;
        use jamnp_s::codec::up0::Final;

        let chain = RefChain::tiny(&m2_reference::oracle::Oracle::for_tests(), 0)?;
        let start = chain.next_slot();
        let block = (start..start + 24)
            .find_map(|slot| chain.author_block(slot).ok().flatten())
            .ok_or_else(|| ChainError::Chain("no emulated slot in 24 slots".into()))?;
        let final_at = |slot| Final {
            header_hash: HeaderHash::from([slot as u8; 32]),
            slot,
        };
        let handshake = Handshake {
            final_block: final_at(7),
            leaves: vec![],
        };
        let announcement = Announcement {
            header: (**block.header).clone(),
            final_block: final_at(9),
        };

        let mut trace = Trace::default();
        trace.push(record(TraceDir::Tx, 2, UP, handshake.encode(), 1000));
        trace.push(record(TraceDir::Tx, 2, UP, announcement.encode(), 2000));
        // The emulator's own announcements travel the same stream, and they
        // say what the *harness* finalized.
        trace.push(record(TraceDir::Rx, 2, UP, announcement.encode(), 3000));
        trace.push(record(TraceDir::Tx, 2, UP, vec![0xde, 0xad], 4000));

        let finals = collect_nut_finals(&trace);

        assert_eq!(
            finals.iter().map(|f| (f.at_ms, f.slot)).collect::<Vec<_>>(),
            vec![(1000, 7), (2000, 9)],
            "both NUT-sent shapes are read, in wire order; the harness's own \
             announcement and the undecodable frame are not"
        );
        Ok(())
    }

    /// Trace convention (`jamnp_s::trace::Direction`): `Tx` is NUT → peer,
    /// `Rx` is peer → NUT. N2 judges the NUT, so tickets the emulator itself
    /// sent (`Rx`) must never be counted as NUT behaviour.
    #[test]
    fn run_collect_nut_tickets_ignores_harness_sent_frames() -> Result<(), ChainError> {
        let ref_chain = RefChain::tiny(&m2_reference::oracle::Oracle::for_tests(), 0)?;
        let ticket_ctx = ref_chain.ticket_ctx()?;
        let tickets = ref_chain.generate_tickets(&ticket_ctx)?;
        let nut_ticket = &tickets[0];
        let emu_ticket = &tickets[1];
        let distribution = |t: &m2_reference::tickets::EmulatedTicket, epoch| TicketDistribution {
            epoch_index: epoch,
            ticket: Ticket {
                attempt: t.attempt,
                proof: t.proof,
            },
        };

        let mut trace = Trace::default();
        trace.push(record(
            TraceDir::Tx,
            2,
            CE131,
            distribution(nut_ticket, 7).encode(),
            1234,
        ));
        trace.push(record(
            TraceDir::Rx,
            3,
            CE132,
            distribution(emu_ticket, 7).encode(),
            2345,
        ));

        let facts = collect_nut_tickets(&trace, &contexts_for(7, ticket_ctx));

        assert_eq!(
            facts.len(),
            1,
            "only the NUT-sent (Tx) ticket is a NUT fact; the harness-sent \
             (Rx) ticket must be ignored"
        );
        assert_eq!(facts[0].peer, 2);
        assert_eq!(facts[0].received_at_ms, 1234);
        Ok(())
    }

    #[test]
    fn run_build_n1_from_nut_blocks() -> Result<(), ChainError> {
        let ref_chain = RefChain::tiny(&m2_reference::oracle::Oracle::for_tests(), 0)?;
        let start = ref_chain.next_slot();
        let mut authored = None;
        for slot in start..start + 12 {
            if let Some(block) = ref_chain.author_block(slot)? {
                authored = Some(block);
                break;
            }
        }
        let block =
            authored.ok_or_else(|| ChainError::Chain("no emulated slot in 12 slots".into()))?;
        let nut_blocks = vec![NutBlock {
            block: block.clone(),
            announced_wall_ms: 1000,
        }];
        let n1 = build_n1_ctx(&ref_chain, &nut_blocks, &[], Vec::new())?;

        assert_eq!(n1.imports.len(), 1, "one import per NUT block");
        assert!(n1.imports[0].ok, "a re-authored block imports OK");
        assert_eq!(n1.imports[0].header_root, block.header.hash().0);
        assert_eq!(n1.imports[0].parent, block.header.parent.0);
        assert_eq!(
            n1.imports[0].reference_parent_root,
            Some(n1.imports[0].declared_parent_root),
            "the reference agrees with the header about the parent's root"
        );
        assert_eq!(n1.nut_blocks.len(), 1);
        assert_eq!(n1.slot_period_ms, SLOT_PERIOD_MS);
        assert_eq!(
            n1.reference_block_hashes.len(),
            ref_chain.chain_blocks()?.len(),
            "reference block hashes cover the whole chain"
        );
        assert_eq!(
            n1.reference_chain.len(),
            n1.reference_block_hashes.len(),
            "the chain timeline covers the same blocks, with their slots"
        );
        assert!(
            n1.reference_chain.windows(2).all(|w| w[0].0 < w[1].0),
            "the chain timeline is ascending by slot"
        );
        // The block was authored on the chain head, so the head as of its slot
        // is its parent.
        assert_eq!(
            n1.reference_best_at(block.header.slot),
            Some(block.header.parent.0)
        );
        Ok(())
    }

    /// The per-peer split is what lets whichever side connects first deliver a
    /// peer's tickets; every ticket must land in exactly one peer's plan.
    #[test]
    fn run_plans_split_by_author() -> Result<(), ChainError> {
        let ref_chain = RefChain::tiny(&m2_reference::oracle::Oracle::for_tests(), 0)?;
        let ticket_ctx = ref_chain.ticket_ctx()?;
        let tickets = ref_chain.generate_tickets(&ticket_ctx)?;
        let period = jam_types::epoch_period();
        let plan = plan_tickets(&tickets, 5, 41 * period, 42);
        assert!(!plan.is_empty());

        let plans = plans_by_peer(&plan);

        assert_eq!(
            plans.values().map(Vec::len).sum::<usize>(),
            plan.len(),
            "every scheduled ticket lands in exactly one peer's plan"
        );
        for (peer, peer_plan) in &plans {
            assert!(
                peer_plan.iter().all(|s| s.ticket.author as u16 == *peer),
                "peer {peer} only delivers its own tickets"
            );
            // The sender walks the plan in order and sleeps until each slot,
            // so an out-of-order plan delays every ticket behind the late one.
            assert!(
                peer_plan.windows(2).all(|w| w[0].slot <= w[1].slot),
                "peer {peer}'s plan is in delivery order: {:?}",
                peer_plan.iter().map(|s| s.slot).collect::<Vec<_>>()
            );
        }
        Ok(())
    }

    #[test]
    fn run_plan_maps_to_emu_tickets() -> Result<(), ChainError> {
        let ref_chain = RefChain::tiny(&m2_reference::oracle::Oracle::for_tests(), 0)?;
        let ticket_ctx = ref_chain.ticket_ctx()?;
        let tickets = ref_chain.generate_tickets(&ticket_ctx)?;
        let nut_index = 5;
        let plan = plan_tickets(&tickets, nut_index, 1001, 84);
        // Only the first entry reached the wire: the rest stand for the ones
        // the sender withheld, and the lane must be able to tell them apart.
        let deliveries = vec![DeliveredTicket {
            plan_index: plan[0].plan_index,
            id: plan[0].ticket.id,
            delivered_at_ms: 1,
            target_epoch: plan[0].target_epoch,
            probe: false,
            refused: false,
        }];

        let emu_plan = plan_emu_tickets(&plan, &ticket_ctx, &deliveries);

        assert_eq!(emu_plan.len(), plan.len());
        assert_eq!(
            emu_plan[0].delivered_at_ms,
            Some(1),
            "the delivered entry carries the time it went out"
        );
        assert!(
            emu_plan[1..].iter().all(|t| !t.delivered()),
            "a planned ticket the emulator never sent is not marked delivered"
        );
        for (emu, scheduled) in emu_plan.iter().zip(&plan) {
            assert_eq!(emu.id, scheduled.ticket.id);
            assert_eq!(emu.author as usize, scheduled.ticket.author);
            assert_eq!(emu.proxy as usize, scheduled.ticket.proxy);
            assert_eq!(emu.slot, scheduled.slot);
            assert_eq!(emu.fault.is_some(), scheduled.fault.is_some());
            // `valid` is the ring-signature verdict and nothing else. Two
            // faults fail it: the corrupted proof, and -- less obviously --
            // the bad attempt, because the attempt is part of the message the
            // ring signs, so relabelling it invalidates the proof for the new
            // value. That is not a second defect in the ticket: the node
            // checks the attempt bound before it looks at the proof, and
            // refuses it on the attempt. Every other fault verifies perfectly
            // well, which is exactly why `valid` cannot stand in for `fault`.
            let signature_breaks = matches!(
                scheduled.fault,
                Some(ReferenceFault::BadProof) | Some(ReferenceFault::BadAttempt)
            );
            assert_eq!(
                emu.valid, !signature_breaks,
                "{:?} verification",
                scheduled.fault
            );
        }
        Ok(())
    }

    /// Deliveries are matched to plan entries by plan index. Ids do not
    /// serve: three faults reuse an honest ticket's proof, and the duplicate
    /// fault shares its target epoch as well, so the `(id, epoch)` pair this
    /// used to key on picks out two entries at once.
    #[test]
    fn deliveries_are_matched_by_plan_index_not_by_ticket_id() -> Result<(), ChainError> {
        let ref_chain = RefChain::tiny(&m2_reference::oracle::Oracle::for_tests(), 0)?;
        let ticket_ctx = ref_chain.ticket_ctx()?;
        let tickets = ref_chain.generate_tickets(&ticket_ctx)?;
        let plan = plan_tickets(&tickets, 5, 1001, 84);

        let duplicate = plan
            .iter()
            .find(|s| s.fault == Some(ReferenceFault::Duplicate))
            .expect("the plan injects a duplicate");
        let twin = plan
            .iter()
            .find(|s| s.fault.is_none() && s.ticket.id == duplicate.ticket.id)
            .expect("whose honest delivery is still in the plan");
        assert_eq!(
            twin.target_epoch, duplicate.target_epoch,
            "the two share an id and an epoch, which is what made the old key fail"
        );

        // Deliver only the duplicate.
        let deliveries = vec![DeliveredTicket {
            plan_index: duplicate.plan_index,
            id: duplicate.ticket.id,
            delivered_at_ms: 7,
            target_epoch: duplicate.target_epoch,
            probe: false,
            refused: false,
        }];

        let emu_plan = plan_emu_tickets(&plan, &ticket_ctx, &deliveries);

        assert_eq!(
            emu_plan[duplicate.plan_index].delivered_at_ms,
            Some(7),
            "the entry that was delivered is marked delivered"
        );
        assert!(
            !emu_plan[twin.plan_index].delivered(),
            "and its twin, which shares id and epoch, is not"
        );
        Ok(())
    }
}
