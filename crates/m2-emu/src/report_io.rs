//! N3 guaranteeing I/O for the emulated validators (CE 133/134/135).
//!
//! Outbound: a work package is submitted over CE 133. Inbound: the NUT's CE
//! 134 sharing streams are recorded and answered, and its CE 135 report
//! distributions are recorded. Nothing here refines, signs or judges
//! anything — the answer's hash and signature are computed in `m2-reference`
//! when the submission is planned, and the records go to the N3 lane.

use std::sync::{Arc, Mutex};

use jam_types::{Decode, Encode};
use jamnp_s::{
    clock,
    codec::ce131_136::{
        GuaranteedWorkReport, SharingBundle, SharingContext, SharingReply, WorkPackageSubmission,
    },
    codec::ce137_148::BundleSubmission,
    framing::{frame, frame_message, CE133, CE134, CE135, CE146},
    trace::{wall_ts, Direction as TraceDir, Trace},
    transport::{Conn, ReadError, SendHalf},
};
use m2_reference::reports::{ScheduledSubmission, SharingAnswer, SubmissionFault};
use m2_scenario::dsl::{ObsKind, ObsLog};
use m2_scenario::scenarios::n3::{
    DistributedReport, ReportSeen, SharedToNut, SharingSeen, SubmittedPackage,
};
use m2_scenario::scenarios::obs::{
    EMU_ANSWERED_134, EMU_SENT_133, EMU_SENT_134, EMU_SENT_135, EMU_SENT_146, NUT_ANSWERED_134,
    NUT_SENT_BAD_REPORT, NUT_SENT_BAD_SHARING, PACKAGE_REFUSED,
};

use crate::emu::{record, slot_start_ms, StreamReader};

/// Read a CE 134 sharing stream the NUT opened, recording what it shared.
///
/// Message 1 is the sharing context and message 2 is the bundle
/// (`simple.md:447-454`). They are separate messages on one stream, and a node
/// can send the first and stop, so the bundle is recorded as `None` rather
/// than the whole stream being discarded — "announced a share and did not
/// follow through" is a finding the lane can only make if the first message
/// survives.
///
/// No reply is sent. The protocol's reply is the work-report hash and a
/// signature over it, which means refining the bundle; until that is wired to
/// the reference, FIN-without-reply is the honest thing to do, and it is also
/// a case the spec covers — the NUT should proceed with its other
/// co-guarantor. The lane must therefore not read a missing guarantee
/// signature as the node's defect while this is true.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_inbound_sharing(
    first: &[u8],
    reader: &mut StreamReader,
    send: &mut SendHalf,
    peer: u16,
    obs: &Mutex<ObsLog>,
    seen: &Mutex<Vec<SharingSeen>>,
    answer: &Mutex<Option<SharingAnswer>>,
) {
    let at_wall_ms = wall_ts();
    let Ok(context) = SharingContext::decode(&mut &first[..]) else {
        record(obs, peer, ObsKind::Other(NUT_SENT_BAD_SHARING));
        return;
    };
    record(obs, peer, ObsKind::Ce134Msg1);

    // Message 2, if it comes. A clean end of stream here is the "no bundle"
    // case; a protocol error is recorded as a malformed share.
    let bundle = match reader.next().await {
        Ok(Some((_, content))) => match SharingBundle::decode(&mut &content[..]) {
            Ok(b) => {
                record(obs, peer, ObsKind::Ce134Msg2);
                Some(b.bundle)
            }
            Err(_) => {
                record(obs, peer, ObsKind::Other(NUT_SENT_BAD_SHARING));
                None
            }
        },
        Ok(None) => None,
        Err(_) => {
            record(obs, peer, ObsKind::Other(NUT_SENT_BAD_SHARING));
            None
        }
    };

    crate::emu::lock(seen).push(SharingSeen {
        peer,
        core_index: context.core_index,
        shard_count: context.shard_count,
        mappings: context.mappings,
        bundle,
        at_wall_ms,
    });

    // `Work-Report Hash ++ Ed25519 Signature`, then FIN. Only for a validator
    // that holds the core: a signature from one that does not is not a
    // weaker answer, it is one the node must reject, and sending it would
    // make the harness the source of the defect.
    let reply = crate::emu::lock(answer)
        .as_ref()
        .and_then(|answer| {
            answer
                .signature_for(peer)
                .map(|signature| (answer.report_hash, signature))
        })
        .map(|(report_hash, signature)| SharingReply {
            report_hash: jam_types::WorkReportHash::from(report_hash),
            signature,
        });
    if let Some(reply) = reply {
        record(obs, peer, ObsKind::Other(EMU_ANSWERED_134));
        let _ = send.write_all(&frame_message(&reply.encode())).await;
    }
    send.finish();
}

/// Record a CE 135 work-report distribution the NUT sent, and pool it
/// (`simple.md:460-485`).
///
/// The report is kept encoded as well as hashed. The lane compares against
/// the reference's report, and a hash match alone would say the two agree
/// without being able to show where they differ when they do not.
///
/// Returns the distribution so the caller can pool it, which is the other
/// half of being sent one and is [`pool_distributed_report`]. Recording and
/// pooling are split so this decoder can be tested without an engine behind
/// it.
pub fn handle_inbound_report(
    content: &[u8],
    peer: u16,
    obs: &Mutex<ObsLog>,
    seen: &Mutex<Vec<ReportSeen>>,
) -> Option<GuaranteedWorkReport> {
    let at_wall_ms = wall_ts();
    let mut input: &[u8] = content;
    let Ok(distribution) = GuaranteedWorkReport::decode(&mut input) else {
        record(obs, peer, ObsKind::Other(NUT_SENT_BAD_REPORT));
        return None;
    };
    // `Report ++ Slot ++ len++[(Idx, Sig)]` and nothing after it.
    if !input.is_empty() {
        record(obs, peer, ObsKind::Other(NUT_SENT_BAD_REPORT));
        return None;
    }
    record(obs, peer, ObsKind::Ce135Report);
    crate::emu::lock(seen).push(ReportSeen {
        peer,
        report_hash: distribution.report.hash().0,
        slot: distribution.slot,
        signatures: distribution.signatures.clone(),
        encoded_report: jam_types::Encode::encode(&distribution.report),
        at_wall_ms,
    });
    Some(distribution)
}

/// Pool a report the NUT distributed, so the next block the reference chain
/// authors carries it.
///
/// What a validator does with a guaranteed report it is sent, and what the
/// harness did not do. Recording alone left every live run with **no core
/// engaged**: an assurance is valid only for a core carrying a report *on
/// chain*, distributing one does not put it there, and the reference chain
/// authors five slots in six. Every assurance the harness sent was
/// therefore invalid, and the node lost each slot it owned to `assurances
/// error: core not engaged` (`findings.md` §21).
///
/// A failure is said rather than swallowed. Everything downstream -- the CE
/// 135 inclusion row and all of N4's assurance rows -- would otherwise go
/// quiet, with no way to tell that from a node that did nothing.
pub fn pool_distributed_report(
    distribution: GuaranteedWorkReport,
    ref_chain: &m2_reference::chain::RefChain,
) {
    let signatures: Vec<jam_std_common::ValSignature> = distribution
        .signatures
        .into_iter()
        .map(|(val_index, signature)| jam_std_common::ValSignature {
            val_index,
            signature: jam_std_common::ed25519::Signature(signature.into()),
        })
        .collect();
    // More signatures than a core has validators. The engine's bounded
    // vector refuses it and so does the lane, which grades the count under
    // `n3_ce135_has_enough_signatures`; nothing is owed here.
    let Ok(signatures) = signatures.try_into() else {
        return;
    };
    if let Err(e) = ref_chain.submit_guarantee(&jam_std_common::ReportGuarantee {
        report: distribution.report,
        slot: distribution.slot,
        signatures,
    }) {
        eprintln!("[distributor] could not pool the report the NUT distributed: {e}");
    }
}

/// Submit `plan`'s work package to the NUT over CE 133 or CE 146, as a
/// builder (`simple.md:351-376`, `simple.md:378-404`).
///
/// CE 133 is two messages on one stream, then FIN: `Core Index ++
/// Work-Package`, then the extrinsic bodies concatenated. CE 146 is the
/// whole-bundle form and takes five: `Core Index ++ Segments-Root
/// Mappings`, the work-package on its own, then the extrinsics, the
/// imported segments and their import proofs. The split exists so a
/// guarantor can authorize the package before downloading the rest, which
/// is also why only the package message carries the size cap.
///
/// Either way the node answers with its own FIN to accept, or resets the
/// stream to refuse, and the refusal is recorded against this submission
/// rather than into the log alone -- a reset carries no reason, so only the
/// sender knows which package was refused.
///
/// The submission goes out at the start of its slot rather than ahead of it,
/// which is the opposite of a ticket. A ticket has to be in the node's hands
/// before the slot it is expected in; a package is work for the rotation it
/// arrives in, and one that arrives early names a core the node may not hold
/// yet.
pub async fn spawn_package_sender(
    connection: Conn,
    plan: ScheduledSubmission,
    trace: Arc<std::sync::Mutex<Trace>>,
    obs: Arc<Mutex<ObsLog>>,
    submissions: Arc<Mutex<Vec<SubmittedPackage>>>,
    peer: u16,
) {
    sleep_until_slot(plan.slot).await;

    let Ok((mut send, mut recv)) = connection.open_bi().await else {
        return;
    };
    let kind = if plan.protocol == u16::from(CE146) {
        CE146
    } else {
        CE133
    };
    // The extrinsic-mismatch fault lives here and nowhere else: the package
    // is well-formed and only the bytes that follow it are wrong. One byte
    // too many makes the message size differ from the sum of the lengths the
    // package declares, which is the rule `simple.md:373` states, and which
    // CE 146 states again at `simple.md:399`.
    let mut bodies = plan.extrinsics.concat();
    if plan.fault == Some(SubmissionFault::ExtrinsicSizeMismatch) {
        bodies.push(0xff);
    }
    let messages: Vec<Vec<u8>> = if kind == CE146 {
        let bundle = BundleSubmission {
            core_index: plan.core,
            mappings: plan.mappings.clone(),
            work_package: plan.package.clone(),
            extrinsics: plan.extrinsics.clone(),
            segments: plan.segments.clone(),
            import_proofs: plan.import_proofs.clone(),
        };
        vec![
            bundle.encode_initial(),
            // The package alone, with no length of its own: the frame is
            // what says how long it is.
            bundle.work_package.clone(),
            bodies,
            bundle.encode_segments(),
            bundle.encode_import_proofs(),
        ]
    } else {
        let submission = WorkPackageSubmission {
            core_index: plan.core,
            work_package: plan.package.clone(),
            extrinsics: plan.extrinsics.clone(),
        };
        vec![submission.encode_initial(), bodies]
    };

    // The first message carries the stream kind; the rest are bare framed
    // messages on the stream it opened.
    let mut wire: Vec<Vec<u8>> = Vec::with_capacity(messages.len());
    for (i, body) in messages.iter().enumerate() {
        wire.push(if i == 0 {
            frame(kind, body)
        } else {
            frame_message(body)
        });
    }
    for bytes in &wire {
        crate::emu::trace_record(peer, kind, send.id(), bytes, &trace, TraceDir::Rx);
    }
    record(
        &obs,
        peer,
        ObsKind::Other(if kind == CE146 {
            EMU_SENT_146
        } else {
            EMU_SENT_133
        }),
    );
    for bytes in &wire {
        if send.write_all(bytes).await.is_err() {
            return;
        }
    }

    let index = {
        let mut recorded = crate::emu::lock(&submissions);
        recorded.push(SubmittedPackage {
            peer,
            protocol: plan.protocol,
            core: plan.core,
            slot: plan.slot,
            package_hash: plan.package_hash,
            sent_at_wall_ms: wall_ts(),
            // Not known until the node answers, below.
            refused: false,
            reset_code: None,
            fault: lane_fault(plan.fault),
            co_guarantors: plan.co_guarantors.clone(),
        });
        recorded.len() - 1
    };
    send.finish();

    // Only a reset counts as a refusal. A connection that died for its own
    // reasons also fails this read, and recording that as a refusal would
    // credit the node with a judgement it never made.
    let mut buf = [0u8; 1024];
    if let Err(ReadError::Reset(code)) = recv.read(&mut buf).await {
        {
            let mut recorded = crate::emu::lock(&submissions);
            recorded[index].refused = true;
            recorded[index].reset_code = Some(code);
        }
        record(&obs, peer, ObsKind::Other(PACKAGE_REFUSED));
    }
}

/// Distribute a reference-guaranteed work-report to the NUT over CE 135
/// (`simple.md:460-485`), so the node can be graded on including it.
///
/// One message, then FIN. Unlike CE 133 there is no judgement to read back:
/// the spec's answer is a bare FIN, and whether the node accepted the report
/// shows up in its next block, not on this stream.
#[allow(clippy::too_many_arguments)]
pub async fn spawn_report_sender(
    connection: Conn,
    slot: u32,
    nut: u16,
    ref_chain: Arc<m2_reference::chain::RefChain>,
    trace: Arc<Mutex<Trace>>,
    obs: Arc<Mutex<ObsLog>>,
    distributed: Arc<Mutex<Vec<DistributedReport>>>,
    peer: u16,
) {
    // Composed a short lead before its distribution, and told the slot it
    // will be distributed in rather than the one it is composed in.
    //
    // Two constraints that pull opposite ways, both in the node's own words.
    // Composed when the run is planned, the report's refine-context anchor
    // has aged out by the time it goes out seven to eleven slots later:
    // `Invalid guarantee: anchor is not recent`. Composed against the very
    // head, the guarantee names a slot the reference has reached and the
    // node has not. A short lead keeps the anchor fresh; passing the
    // distribution slot keeps the cohort and the declared slot on the right
    // side of the epoch boundary the lane aims at, which a lead alone does
    // not -- two slots before a phase-0 target is the *previous* epoch, with
    // a different cohort entirely.
    sleep_until_slot(slot.saturating_sub(REPORT_COMPOSE_LEAD_SLOTS)).await;
    let plan = match ref_chain.report_to_distribute(
        // A payload of its own: built moments after the submission from the
        // same template, an identical one would be the same package and the
        // node would refuse whichever arrived second.
        vec![m2_reference::reports::work_item_with_payload(
            b"n3-distributed".to_vec(),
        )],
        nut,
        slot,
    ) {
        Ok(Some(plan)) => plan,
        // Said rather than returned silently, the same as the arm below. A
        // report that could not be composed leaves the CE 135 rows with
        // nothing to grade, and a reader has no way to tell that from a node
        // that ignored a report it was sent.
        Ok(None) => {
            eprintln!(
                "[distributor] no report to distribute in slot {slot}: the NUT holds no core \
                 there in the epoch view, or there is only one core"
            );
            return;
        }
        Err(e) => {
            eprintln!("[distributor] could not compose the report: {e}");
            return;
        }
    };

    sleep_until_slot(slot).await;

    // Both failures below are said rather than returned silently, the same
    // as the compose arms above. A report that never left the harness and a
    // report the node ignored both leave `n3_ce135_inclusion` reporting
    // *not exercised*, and those are different facts about a run.
    let Ok((mut send, _recv)) = connection.open_bi().await else {
        eprintln!(
            "[distributor] could not open a stream to distribute the report in slot {}",
            plan.slot
        );
        return;
    };
    let wire = frame(CE135, &plan.wire);
    crate::emu::trace_record(peer, CE135, send.id(), &wire, &trace, TraceDir::Rx);
    record(&obs, peer, ObsKind::Other(EMU_SENT_135));
    if send.write_all(&wire).await.is_err() {
        eprintln!(
            "[distributor] the stream closed before the report for slot {} was written",
            plan.slot
        );
        return;
    }
    crate::emu::lock(&distributed).push(DistributedReport {
        peer,
        core: plan.core,
        report_hash: plan.report_hash,
        sent_in_slot: plan.slot,
        sent_at_wall_ms: wall_ts(),
    });
    send.finish();
}

/// Open a CE 134 share to the NUT and read the answer it gives
/// (`simple.md:406-458`).
///
/// The harness is the sharing guarantor here. Two messages then FIN, and the
/// node answers with the hash of the report it refined and a signature over
/// it -- or resets, which is its way of refusing to refine at all.
pub async fn spawn_share_sender(
    connection: Conn,
    plan: m2_reference::reports::ScheduledShare,
    trace: Arc<Mutex<Trace>>,
    obs: Arc<Mutex<ObsLog>>,
    shared_to_nut: Arc<Mutex<Vec<SharedToNut>>>,
    peer: u16,
) {
    sleep_until_slot(plan.slot).await;

    let Ok((mut send, mut recv)) = connection.open_bi().await else {
        return;
    };
    let context = SharingContext {
        core_index: plan.core,
        shard_count: plan.shard_count,
        mappings: plan.mappings.clone(),
    };
    let first = frame(CE134, &context.encode());
    let second = frame_message(
        &SharingBundle {
            bundle: plan.bundle.clone(),
        }
        .encode(),
    );
    crate::emu::trace_record(peer, CE134, send.id(), &first, &trace, TraceDir::Rx);
    record(&obs, peer, ObsKind::Other(EMU_SENT_134));
    if send.write_all(&first).await.is_err() || send.write_all(&second).await.is_err() {
        return;
    }
    send.finish();

    // The answer, or a reset. Both are the node's verdict; a connection that
    // died for its own reasons is neither, so it is recorded as no reply
    // rather than as a refusal.
    // We opened the stream, so the answer is a bare message under CE 134.
    let mut reader = jamnp_s::framing::FrameReader::with_kind(CE134);
    let mut buf = [0u8; 4096];
    let mut reply = None;
    let mut refused = false;
    let mut reset_code = None;
    loop {
        if let Ok(Some((_, content))) = reader.next_frame() {
            if let Ok(answer) = SharingReply::decode(&mut &content[..]) {
                reply = Some((answer.report_hash.0, answer.signature));
                record(&obs, peer, ObsKind::Other(NUT_ANSWERED_134));
            } else {
                record(&obs, peer, ObsKind::Other(NUT_SENT_BAD_SHARING));
            }
            break;
        }
        match recv.read(&mut buf).await {
            Ok(Some(n)) => reader.push(&buf[..n]),
            // A clean end with no answer: the node neither refused nor
            // refined, which the lane reports as its own thing.
            Ok(None) => break,
            // Only a reset is a refusal. A connection that died for its own
            // reasons is not the node's verdict on the bundle.
            Err(ReadError::Reset(code)) => {
                refused = true;
                reset_code = Some(code);
                break;
            }
            Err(_) => break,
        }
    }

    crate::emu::lock(&shared_to_nut).push(SharedToNut {
        peer,
        core: plan.core,
        slot: plan.slot,
        shard_count: plan.shard_count,
        expected_report_hash: plan.expected_report_hash,
        reply,
        refused,
        reset_code,
        fault: lane_share_fault(plan.fault),
        sent_at_wall_ms: wall_ts(),
    });
}

/// Map the reference's share fault onto the lane's copy.
fn lane_share_fault(
    fault: Option<m2_reference::reports::ShareFault>,
) -> Option<m2_scenario::scenarios::n3::ShareFault> {
    use m2_scenario::scenarios::n3::ShareFault as Lane;
    fault.map(|f| match f {
        m2_reference::reports::ShareFault::WrongShardCount => Lane::WrongShardCount,
    })
}

/// Map the reference's fault onto the lane's own copy.
///
/// Two enums rather than a shared one, as the ticket faults already do: the
/// reference knows how to pose a fault and the lane describes what was
/// posed, and neither crate depends on the other.
fn lane_fault(
    fault: Option<SubmissionFault>,
) -> Option<m2_scenario::scenarios::n3::SubmissionFault> {
    use m2_scenario::scenarios::n3::SubmissionFault as Lane;
    fault.map(|f| match f {
        SubmissionFault::Oversized => Lane::Oversized,
        SubmissionFault::NotAGuarantor => Lane::NotAGuarantor,
        SubmissionFault::Unauthorized => Lane::Unauthorized,
        SubmissionFault::ExtrinsicSizeMismatch => Lane::ExtrinsicSizeMismatch,
    })
}

/// Slots before its distribution at which the report is composed.
const REPORT_COMPOSE_LEAD_SLOTS: u32 = 2;

/// Wait until `slot` begins.
async fn sleep_until_slot(slot: u32) {
    let target_ms = slot_start_ms(slot);
    loop {
        let now = wall_ts();
        if now >= target_ms {
            return;
        }
        clock::current()
            .sleep(std::time::Duration::from_millis(target_ms - now))
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jam_types::Encode;
    use jamnp_s::codec::ce131_136::SharingReply;
    use m2_scenario::dsl::ObsLog;

    fn obs_codes(obs: &Mutex<ObsLog>) -> Vec<u8> {
        crate::emu::lock(obs)
            .events()
            .iter()
            .map(|(_, o)| o.kind.code())
            .collect()
    }

    /// A CE 135 frame that will not decode is recorded as the node's defect
    /// and leaves no report behind: a half-read distribution must not reach
    /// the lane as though the node had sent one.
    #[test]
    fn an_undecodable_ce135_frame_records_nothing_but_the_defect() {
        let obs = Mutex::new(ObsLog::new());
        let seen = Mutex::new(Vec::new());
        handle_inbound_report(&[0xff; 8], 1, &obs, &seen);
        assert!(crate::emu::lock(&seen).is_empty(), "no report was recorded");
        assert_eq!(obs_codes(&obs), vec![NUT_SENT_BAD_REPORT]);
    }

    /// Trailing bytes after a well-formed distribution are a defect too.
    ///
    /// `Decode` stops at the end of the value it understands, so without the
    /// explicit check a node could append anything and the frame would still
    /// be accepted -- the same hole as CE 133's work-package.
    #[test]
    fn trailing_bytes_after_a_ce135_distribution_are_a_defect() {
        // A reply is not a distribution, but it is a value this decoder will
        // read a prefix of and stop, which is all this test needs.
        let mut wire = SharingReply {
            report_hash: jam_types::WorkReportHash::from([7u8; 32]),
            signature: [0u8; 64],
        }
        .encode();
        wire.push(0xff);
        let obs = Mutex::new(ObsLog::new());
        let seen = Mutex::new(Vec::new());
        handle_inbound_report(&wire, 1, &obs, &seen);
        assert!(crate::emu::lock(&seen).is_empty());
        assert_eq!(obs_codes(&obs), vec![NUT_SENT_BAD_REPORT]);
    }
}
