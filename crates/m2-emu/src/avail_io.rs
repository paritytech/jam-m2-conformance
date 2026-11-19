//! CE 137/138/139/140/141: asking the node for shards, and the assurances
//! that travel both ways.
//!
//! Every judgement here belongs to the lane, not to this module. What it
//! does is put a request on the wire, record what came back, and hand the
//! bytes on; whether a shard is the right shard and whether a justification
//! proves anything is decided in `m2-scenario::scenarios::n4` from facts the
//! *engine* produced. A module that answered those questions itself would be
//! a second implementation of the rules it is grading against.
//!
//! What it does own is the *shape* of the wire, and that shape is not
//! self-describing. Each reply is a sequence of whole framed messages whose
//! lengths the stream already carries: a bundle shard, CE 137's segment
//! shards concatenated with no boundary marked, a justification whose
//! elements run back to back with no count in front of them. Nothing in the
//! reply says how long any of it is, so what this module reads is messages,
//! and it hands each one on whole.

use std::sync::{Arc, Mutex};

use jam_types::{Decode, Encode};
use jamnp_s::{
    codec::{
        ce137_148::{SegmentRequest, SegmentResponse, SegmentShardRequest, ShardRequest},
        ce141_145::Assurance,
    },
    framing::{frame, CE137, CE138, CE139, CE140, CE141, CE148},
    trace::{wall_ts, Direction as TraceDir, Trace},
    transport::Conn,
};
use m2_scenario::dsl::{ObsKind, ObsLog};
use m2_scenario::scenarios::n4::{
    AssuranceFaultKind, AssuranceOffered, AssuranceSeen, SegmentShardsServed, SegmentsServed,
    ShardServed,
};
use m2_scenario::scenarios::obs::{
    NUT_SENT_BAD_ASSURANCE, SENT_ASSURANCE, SERVED_BUNDLE_SHARD, SERVED_SEGMENTS,
    SERVED_SEGMENT_SHARDS,
};

use crate::emu::{lock, record, trace_record, StreamReader};

/// Record a CE 141 assurance the node broadcast.
///
/// The assurance is decoded and kept; it is *not* verified here. Verifying
/// needs the anchor the lane expects and the cores it knows carried reports,
/// neither of which this module has — and splitting the decision across two
/// places is how two implementations of one rule begin.
pub fn handle_inbound_assurance(
    content: &[u8],
    peer: u16,
    obs: &Mutex<ObsLog>,
    seen: &Mutex<Vec<RawAssurance>>,
) {
    let at_wall_ms = wall_ts();
    let mut input: &[u8] = content;
    let Ok(assurance) = Assurance::decode(&mut input) else {
        record(obs, peer, ObsKind::Other(NUT_SENT_BAD_ASSURANCE));
        return;
    };
    // `Anchor ++ Bitfield ++ Signature` and nothing after it.
    if !input.is_empty() {
        record(obs, peer, ObsKind::Other(NUT_SENT_BAD_ASSURANCE));
        return;
    }
    record(obs, peer, ObsKind::Ce141Assurance);
    lock(seen).push(RawAssurance {
        peer,
        assurance,
        at_wall_ms,
    });
}

/// An assurance as received, before the lane has anything to judge it
/// against.
#[derive(Clone, Debug)]
pub struct RawAssurance {
    pub peer: u16,
    pub assurance: Assurance,
    pub at_wall_ms: u64,
}

/// Send one assurance to the NUT over CE 141.
///
/// CE 141 is one message and no reply (`simple.md:688`), so there is nothing
/// to read back; whether the node accepted it shows up later, in whether a
/// block carries it.
pub async fn send_assurance(
    connection: &Conn,
    assurance: &Assurance,
    peer: u16,
    trace: &Arc<Mutex<Trace>>,
    obs: &Arc<Mutex<ObsLog>>,
) -> bool {
    let Ok((mut send, _recv)) = connection.open_bi().await else {
        return false;
    };
    let wire = frame(CE141, &assurance.encode());
    trace_record(peer, CE141, send.id(), &wire, trace, TraceDir::Rx);
    if send.write_all(&wire).await.is_err() {
        return false;
    }
    send.finish();
    record(obs, peer, ObsKind::Other(SENT_ASSURANCE));
    true
}

/// Ask the NUT for a bundle shard over CE 137 or CE 138.
///
/// The reply is not one self-describing structure: it is a sequence of whole
/// messages, `Bundle Shard`, then CE 137's segment shards, then the
/// justification (`simple.md:552-554`, `simple.md:577-578`). Each carries its
/// own length, so nothing here needs to know a shard length in advance -- and
/// a reply short of its messages is recorded as short rather than read as an
/// empty one.
///
/// `expected_bundle_shard` is what the reference coded for that index, when
/// the caller knows the bundle. It is carried through rather than compared
/// here so that the comparison, and the decision about what a mismatch means,
/// stay in one place.
#[allow(clippy::too_many_arguments)]
pub async fn request_shard(
    connection: &Conn,
    protocol: u8,
    erasure_root: [u8; 32],
    shard_index: u16,
    expected_bundle_shard: Option<Vec<u8>>,
    peer: u16,
    trace: &Arc<Mutex<Trace>>,
    obs: &Arc<Mutex<ObsLog>>,
) -> Option<ShardServed> {
    let request = ShardRequest {
        erasure_root,
        shard_index,
    };
    let reply = exchange(connection, protocol, &request.encode(), peer, trace).await?;

    let mut served = ShardServed {
        protocol: protocol as u16,
        erasure_root,
        shard_index,
        bundle_shard: Vec::new(),
        expected_bundle_shard,
        segment_shards: Vec::new(),
        messages: 0,
        justification: Vec::new(),
        // Filled by the caller, which can reach the oracle; this module
        // deliberately cannot.
        justification_verified: None,
        justification_detail: None,
        refused: false,
    };
    let Exchange::Answered(messages) = reply else {
        served.refused = true;
        return Some(served);
    };
    // Recorded only once something came back. "Serves CE 137" logged for a
    // stream the node reset would say the opposite of what happened, and the
    // refusal already rides on the fact.
    record(
        obs,
        peer,
        if protocol == CE137 {
            ObsKind::ServesCe137
        } else {
            ObsKind::Other(SERVED_BUNDLE_SHARD)
        },
    );
    served.messages = messages.len();

    // Taken by position, and only where the position exists. CE 137 puts the
    // segment shards in the middle, so the justification is the second
    // message for CE 138 and the third for CE 137; reading it from the end
    // instead would quietly mistake a two-message CE 137 reply for a
    // complete one.
    let mut messages = messages.into_iter();
    served.bundle_shard = messages.next().unwrap_or_default();
    let justification = if protocol == CE137 {
        served.segment_shards = messages.next().unwrap_or_default();
        messages.next()
    } else {
        messages.next()
    };
    served.justification = justification.unwrap_or_default();
    Some(served)
}

/// Ask the NUT for segment shards over CE 139 or CE 140.
///
/// The slices come back concatenated in one message, with no boundary marked
/// and no index attached: `segment_slice_len` of the shard count says where
/// one ends, and position says which segment it is. CE 140 then sends one
/// further message per requested index, each a justification.
#[allow(clippy::too_many_arguments)]
pub async fn request_segment_shards(
    connection: &Conn,
    protocol: u8,
    erasure_root: [u8; 32],
    shard_index: u16,
    shard_count: u16,
    segment_indices: Vec<u16>,
    // Segments the package exports in total, which is the size of the tree
    // a justification proves against -- not the number asked for here.
    segment_count: u32,
    peer: u16,
    trace: &Arc<Mutex<Trace>>,
    obs: &Arc<Mutex<ObsLog>>,
) -> Option<SegmentShardsServed> {
    let request = SegmentShardRequest {
        erasure_root,
        shard_index,
        segment_indices: segment_indices.clone(),
    };
    let reply = exchange(connection, protocol, &request.encode(), peer, trace).await?;

    let mut served = SegmentShardsServed {
        protocol: protocol as u16,
        erasure_root,
        shard_index,
        requested: segment_indices,
        segment_count,
        shards: Vec::new(),
        justifications: Vec::new(),
        justifications_verified: Vec::new(),
        justification_details: Vec::new(),
        ragged: false,
        refused: false,
    };
    let Exchange::Answered(messages) = reply else {
        served.refused = true;
        return Some(served);
    };
    record(obs, peer, ObsKind::Other(SERVED_SEGMENT_SHARDS));

    let slice_len = jam_types::segment_slice_len(shard_count as usize);
    let mut messages = messages.into_iter();
    let data = messages.next().unwrap_or_default();
    if slice_len == 0 || !data.len().is_multiple_of(slice_len) {
        served.ragged = true;
        return Some(served);
    }
    served.shards = data.chunks(slice_len).map(<[u8]>::to_vec).collect();
    // CE 140's justifications follow, one message each. Kept as they
    // arrived: checking one needs the engine, and this module does not have
    // it.
    if protocol == CE140 {
        served.justifications = messages.collect();
    }
    Some(served)
}

/// Ask the NUT for whole imported segments over CE 148
/// (`simple.md:650-673`).
///
/// One request message, then two reply messages: the segments concatenated,
/// then one import proof per segment. Nothing in either says how long it
/// is, so what arrived is counted rather than trusted -- and the proofs are
/// kept as they came, because whether one proves anything is the engine's
/// answer and this module does not have it.
pub async fn request_segments(
    connection: &Conn,
    segments_root: [u8; 32],
    segment_indices: Vec<u16>,
    peer: u16,
    trace: &Arc<Mutex<Trace>>,
    obs: &Arc<Mutex<ObsLog>>,
) -> Option<SegmentsServed> {
    let request = SegmentRequest {
        segments_root,
        segment_indices: segment_indices.clone(),
    };
    let reply = exchange(connection, CE148, &request.encode(), peer, trace).await?;

    let mut served = SegmentsServed {
        segments_root,
        requested: segment_indices,
        segments: Vec::new(),
        proofs: Vec::new(),
        proofs_verified: Vec::new(),
        proof_details: Vec::new(),
        ragged: false,
        proofs_unreadable: false,
        messages: 0,
        refused: false,
    };
    let Exchange::Answered(messages) = reply else {
        served.refused = true;
        return Some(served);
    };
    record(obs, peer, ObsKind::Other(SERVED_SEGMENTS));
    served.messages = messages.len();

    let mut messages = messages.into_iter();
    let data = messages.next().unwrap_or_default();
    match SegmentResponse::decode_segments(&data, jam_types::SEGMENT_LEN) {
        Ok(segments) => served.segments = segments,
        Err(_) => {
            served.ragged = true;
            return Some(served);
        }
    }
    // The proof message, if it came at all. A reply that stopped after the
    // segments is short rather than unreadable, and the row that counts
    // messages is the one that says so.
    if let Some(proofs) = messages.next() {
        match SegmentResponse::decode_import_proofs(&proofs) {
            Ok(proofs) => served.proofs = proofs,
            Err(_) => served.proofs_unreadable = true,
        }
    }
    Some(served)
}

/// What came of a request: the messages that came back, or a refusal.
enum Exchange {
    /// Every message the node sent before the stream ended, in order.
    Answered(Vec<Vec<u8>>),
    Refused,
}

/// Open a stream, send one message, read the reply until the stream ends.
///
/// `None` only when the stream could not be opened at all, which is a
/// harness-side failure rather than anything the node did. A reset before any
/// reply is `Refused`, which is an answer and belongs in the facts; a reset
/// *after* some of it keeps what arrived, so the caller can say the reply was
/// short rather than that there was none.
async fn exchange(
    connection: &Conn,
    protocol: u8,
    message: &[u8],
    peer: u16,
    trace: &Arc<Mutex<Trace>>,
) -> Option<Exchange> {
    let (mut send, recv) = connection.open_bi().await.ok()?;
    let stream_id = send.id();
    let wire = frame(protocol, message);
    trace_record(peer, protocol, stream_id, &wire, trace, TraceDir::Rx);
    if send.write_all(&wire).await.is_err() {
        return Some(Exchange::Refused);
    }
    send.finish();

    // `with_kind`, not `new`: we opened the stream and wrote the kind byte
    // ourselves, so the node's replies are bare `[len][content]` messages. A
    // reader built for an accepted stream would take the first byte of the
    // length prefix for a kind and misread every reply that followed.
    let mut reader = StreamReader::with_kind(recv, protocol);
    let mut messages = Vec::new();
    // A clean end, or a reset: either way there is no more. Whether what
    // arrived is enough is the lane's question, not this one's.
    while let Ok(Some((_, content))) = reader.next().await {
        trace_record(peer, protocol, stream_id, &content, trace, TraceDir::Tx);
        messages.push(content);
    }
    if messages.is_empty() {
        return Some(Exchange::Refused);
    }
    Some(Exchange::Answered(messages))
}

/// What one emulated validator does about availability in a run.
///
/// The erasure root is not known when the run is planned: it is the one the
/// NUT published in a report it guaranteed, so it exists only once the node
/// has guaranteed something. The plan is therefore set mid-run, which is why
/// it travels on its own watch rather than with the rest.
#[derive(Clone, Debug)]
pub struct AvailPlan {
    /// The erasure root the NUT guaranteed. Its own: a root the harness
    /// guaranteed would be one the node is right to answer `NoData` for.
    pub erasure_root: [u8; 32],
    /// The segments root the NUT exported (`exports_root`), which is what a
    /// CE 148 request names.
    ///
    /// A different root from `erasure_root` and a different question: one
    /// asks for a coded shard of the bundle, the other for the whole
    /// segments the package exported. Both come off the same report.
    pub segments_root: [u8; 32],
    /// Shards the report declared it was coded into (`erasure_shards`).
    pub shard_count: u16,
    /// Segments the package exports in total.
    ///
    /// The size of the tree a segment justification proves against, which
    /// is not the number of segments a run asks for: those coincide only
    /// when a run asks for all of them (`findings.md` §26).
    pub segment_count: u32,
    /// Segment indices to ask for over CE 139 and CE 140.
    ///
    /// Empty where the package exported nothing, in which case those two
    /// protocols are not exercised rather than asked for segments that do
    /// not exist.
    pub segment_indices: Vec<u16>,
    /// First slot an assurance goes out for.
    pub honest_slot: u32,
    /// How many slots in a row to assure for, starting at `honest_slot`.
    ///
    /// A validator assures the head every slot, and an assurance can be
    /// carried in exactly one block -- the child of the block it anchors.
    /// Offering in a single slot would leave the inclusion rows exercised
    /// only if the node happened to author that one slot's child, which is
    /// about one slot in three.
    pub assurance_slots: u32,
    /// First slot whose offer is spoiled instead of honest.
    ///
    /// A boundary rather than one named slot. An assurance is carried in
    /// exactly one block -- the child of the block it anchors -- so a single
    /// spoiled offer is graded only if the node happens to author that one
    /// block, and the row asking whether invalid assurances are excluded
    /// would spend most runs unexercised.
    ///
    /// The two halves are kept apart because they must land on different
    /// blocks. A validator that sent an honest assurance and a spoiled one
    /// for the *same* anchor would have its second dropped as a duplicate,
    /// and the exclusion row would pass for a reason that has nothing to do
    /// with the assurance being invalid.
    pub spoiled_from: u32,
}

/// Run one emulated validator's availability exchange against the NUT.
///
/// Four fetches for its own shard index, then an honest assurance, then a
/// spoiled one. Everything it learns goes into the shared records; nothing
/// here decides whether any of it was right.
#[allow(clippy::too_many_arguments)]
pub async fn drive_availability(
    connection: &Conn,
    peer: u16,
    plan: &AvailPlan,
    // Whether to fetch shards and segments, or go straight to assuring.
    // False on a reconnection: the fetches are a one-off per validator and
    // the node is right to refuse a repeat once the report has left the
    // core (`findings.md` §24).
    fetch_shards: bool,
    trace: &Arc<Mutex<Trace>>,
    obs: &Arc<Mutex<ObsLog>>,
    shards_served: &Arc<Mutex<Vec<ShardServed>>>,
    segment_shards_served: &Arc<Mutex<Vec<SegmentShardsServed>>>,
    segments_served: &Arc<Mutex<Vec<SegmentsServed>>>,
    assurances_offered: &Arc<Mutex<Vec<AssuranceOffered>>>,
    // The last anchor each validator assured, shared across this peer's
    // connections. A peer can have two live ones -- dialled and accepted --
    // and both drive this loop; a `previous` local to each would put two
    // assurances from one validator under one anchor.
    last_assured: &Arc<Mutex<std::collections::HashMap<u16, [u8; 32]>>>,
    anchor_of: impl Fn() -> Option<[u8; 32]>,
    // The cores carrying a report right now, read every slot for the same
    // reason the anchor is: both are chain state. A core is engaged when a
    // block carries its guarantee and freed once the report is available,
    // so a set chosen when the plan was written is wrong for most of a run
    // -- and assuring a freed core cost a live node every authoring slot it
    // owned (`findings.md` §21).
    engaged_cores: impl Fn() -> Vec<u16>,
) -> bool {
    // Its own index, because that is the shard a validator is entitled to:
    // `simple.md:523-556` is a validator fetching the piece it must assure.
    let shard_index = peer;

    // Whether the fetches actually reached the node. A refusal counts --
    // that is an answer, and the serve rows grade it. What does not count
    // is a stream that never opened, which is a connection dying rather
    // than a node saying no, and the caller retries that on the next one.
    let mut reached = false;
    if fetch_shards {
        for protocol in [CE137, CE138] {
            if let Some(served) = request_shard(
                connection,
                protocol,
                plan.erasure_root,
                shard_index,
                // The lane leaves the byte comparison unmade: the harness did
                // not build this bundle, the node did, so it has nothing to
                // compare against. Predicting it would mean refining the
                // package a second time and calling the result authoritative.
                None,
                peer,
                trace,
                obs,
            )
            .await
            {
                reached = true;
                lock(shards_served).push(served);
            }
        }

        if !plan.segment_indices.is_empty() {
            // The whole-segment shortcut first. A requester is meant to try CE
            // 148 and fall back to CE 139/140 (`simple.md:660`), and asking in
            // that order is also what lets the lane see a node that serves one
            // and not the other.
            if let Some(served) = request_segments(
                connection,
                plan.segments_root,
                plan.segment_indices.clone(),
                peer,
                trace,
                obs,
            )
            .await
            {
                lock(segments_served).push(served);
            }
            for protocol in [CE139, CE140] {
                if let Some(served) = request_segment_shards(
                    connection,
                    protocol,
                    plan.erasure_root,
                    shard_index,
                    plan.shard_count,
                    plan.segment_indices.clone(),
                    plan.segment_count,
                    peer,
                    trace,
                    obs,
                )
                .await
                {
                    lock(segment_shards_served).push(served);
                }
            }
        }
    }

    // One assurance per slot, which is what a validator does: it assures the
    // head, and the head moves every slot. The anchor is read at send time
    // rather than planned, because an assurance names the block it is about
    // and a hash chosen when the plan was written names a block several
    // slots old by then.
    let kind = spoil_for(peer);
    let mut last_engaged: Option<Vec<u16>> = None;
    for slot in plan.honest_slot..plan.honest_slot.saturating_add(plan.assurance_slots) {
        // A reconnection restarts this loop at the plan's first slot, which
        // is by then in the past: `sleep_until_lead` returns at once and the
        // offer would be recorded against a slot its anchor has nothing to
        // do with. The inclusion rows read `sent_in_slot`, so a stale one
        // makes them look at the wrong blocks.
        if slot < m2_reference::chain::wall_clock_slot() {
            continue;
        }
        sleep_until_lead(slot).await;
        let Some(anchor) = anchor_of() else { continue };
        // The head has not moved, so there is nothing new to assure. Sending
        // anyway would put two assurances from this validator under one
        // anchor -- and if one of them were the spoiled one, the two rows
        // would be judging the same block against opposite expectations.
        //
        // Checked and claimed under one lock, because this peer's other
        // connection may be in the same place at the same moment.
        {
            let mut held = lock(last_assured);
            if held.get(&peer) == Some(&anchor) {
                continue;
            }
            held.insert(peer, anchor);
        }

        // Read here rather than above the loop: the answer changes as
        // reports are guaranteed and become available, and this slot's
        // assurance has to claim this slot's cores.
        let engaged = engaged_cores();
        // Said when it moves, because when it moves is the whole question.
        // The harness reads this a couple of seconds before the slot and
        // the node checks it when it authors; anything that frees a core in
        // between leaves a valid assurance looking invalid by the time it
        // is used, which is how a node loses a slot it owned to a peer
        // doing nothing wrong (`findings.md` §21, §22).
        if last_engaged.as_deref() != Some(&engaged[..]) {
            eprintln!(
                "[availability] validator {peer} sees cores {engaged:?} engaged at slot {slot},                  was {last_engaged:?}"
            );
            last_engaged = Some(engaged.clone());
        }
        let (assurance, cores, fault) = if slot >= plan.spoiled_from {
            // `None` where this validator cannot pose its fault -- there is
            // no empty core to claim when every core carried a report.
            // Sending some other fault instead would mean the run graded a
            // different rule from the one it recorded.
            match spoil(peer, anchor, &engaged, kind) {
                Some((assurance, claimed)) => (assurance, claimed, Some(kind)),
                None => continue,
            }
        } else {
            (
                m2_reference::assurance::sign_assurance(peer, anchor, &engaged),
                engaged,
                None,
            )
        };
        if send_assurance(connection, &assurance, peer, trace, obs).await {
            lock(assurances_offered).push(AssuranceOffered {
                validator: peer,
                anchor: assurance.anchor.0,
                cores,
                sent_in_slot: slot,
                included: false,
                had_opportunity: false,
                fault,
            });
        }
    }
    reached
}

/// Which fault this validator poses.
///
/// By index, so a run poses all three where there are three or more
/// emulated validators, and so the same validator poses the same one on
/// every run. A random choice would make a failing row unreproducible.
fn spoil_for(peer: u16) -> AssuranceFaultKind {
    match peer % 3 {
        0 => AssuranceFaultKind::WrongAnchor,
        1 => AssuranceFaultKind::BadSignature,
        _ => AssuranceFaultKind::EmptyCore,
    }
}

/// Build an assurance that is wrong in exactly one way.
///
/// Each fault is posed at the level it belongs to: a wrong anchor is signed
/// genuinely over a block that does not exist, a bad signature is a genuine
/// statement signed by someone else, and an empty core is a genuine
/// signature over a claim about a core carrying nothing. A node that catches
/// one and not another is a node with a specific hole, which is what the
/// lane grades them separately for.
fn spoil(
    peer: u16,
    anchor: [u8; 32],
    cores: &[u16],
    kind: AssuranceFaultKind,
) -> Option<(Assurance, Vec<u16>)> {
    match kind {
        AssuranceFaultKind::WrongAnchor => {
            // A hash nothing hashes to: the block it names was never
            // authored, so there is nothing to assure. The signature over it
            // is genuine, so a node that lets this through is not checking
            // anchors at all.
            let mut absent = anchor;
            absent[0] ^= 0xff;
            Some((
                m2_reference::assurance::sign_assurance(peer, absent, cores),
                cores.to_vec(),
            ))
        }
        AssuranceFaultKind::BadSignature => {
            // Signed by the next validator along and sent as this one. CE
            // 141 carries no validator index -- the node reads it off the
            // connection -- so the statement is sound and only the hand that
            // signed it is wrong.
            Some((
                m2_reference::assurance::sign_assurance(peer.wrapping_add(1), anchor, cores),
                cores.to_vec(),
            ))
        }
        AssuranceFaultKind::EmptyCore => {
            // A core the harness knows carried no report, signed properly,
            // so only the claim is false. Where every core carried one there
            // is no such claim to make, and posing some other fault instead
            // would grade a different rule from the one recorded.
            let empty = (0..jam_types::core_count()).find(|core| !cores.contains(core))?;
            let claimed = vec![empty];
            Some((
                m2_reference::assurance::sign_assurance(peer, anchor, &claimed),
                claimed,
            ))
        }
    }
}

/// Wait until an assurance for `slot` is due: the lead `simple.md:679-680`
/// asks for, before the slot begins.
///
/// Sent then rather than at the slot's start because that is when the anchor
/// is right. The block to assure is the head at that instant, which is the
/// parent of the block about to be authored -- and an assurance anchored at
/// anything but that block's parent cannot be carried in it at all.
async fn sleep_until_lead(slot: u32) {
    let target_ms = crate::emu::slot_start_ms(slot)
        .saturating_sub(m2_scenario::scenarios::n4::ASSURANCE_LEAD_MS as u64);
    loop {
        let now = wall_ts();
        if now >= target_ms {
            return;
        }
        jamnp_s::clock::current()
            .sleep(std::time::Duration::from_millis(target_ms - now))
            .await;
    }
}

/// Turn the assurances the node sent into the lane's facts.
///
/// The blocks the node could have been assuring and the cores that carried
/// reports come from the run; this only pairs them with what arrived.
pub fn assurances_for_lane(
    raw: &[RawAssurance],
    nut_index: u16,
    known_anchors: &[[u8; 32]],
    reported_cores: &[u16],
    slot_start_ms: impl Fn(u64) -> i64,
) -> Vec<AssuranceSeen> {
    raw.iter()
        .map(|entry| {
            let fault = m2_reference::assurance::check_assurance(
                &entry.assurance,
                nut_index,
                known_anchors,
            )
            .err()
            .map(|fault| format!("{fault:?}"));
            AssuranceSeen {
                from: entry.peer,
                anchor: entry.assurance.anchor.0,
                cores: m2_reference::assurance::assured_cores(&entry.assurance),
                fault,
                lead_ms: slot_start_ms(entry.at_wall_ms),
                reported_cores: reported_cores.to_vec(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use m2_scenario::dsl::ObsLog;

    fn tiny() {
        jam_types::ProtocolParameters::tiny()
            .apply()
            .expect("the tiny parameters are valid");
    }

    fn obs_codes(obs: &Mutex<ObsLog>) -> Vec<u8> {
        lock(obs)
            .events()
            .iter()
            .map(|(_, o)| o.kind.code())
            .collect()
    }

    #[test]
    fn an_assurance_is_recorded_as_it_arrived() {
        tiny();
        let anchor = [0x7c; 32];
        let assurance = m2_reference::assurance::sign_assurance(5, anchor, &[0]);

        let obs = Mutex::new(ObsLog::default());
        let seen = Mutex::new(Vec::new());
        handle_inbound_assurance(&assurance.encode(), 5, &obs, &seen);

        assert_eq!(obs_codes(&obs), vec![ObsKind::Ce141Assurance.code()]);
        let recorded = lock(&seen);
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].peer, 5);
        assert_eq!(recorded[0].assurance.anchor.0, anchor);
    }

    /// Trailing bytes after the assurance are not an assurance with a
    /// suffix: the message is `Anchor ++ Bitfield ++ Signature` and nothing
    /// else, so this is recorded as malformed rather than accepted.
    #[test]
    fn trailing_bytes_are_refused() {
        tiny();
        let assurance = m2_reference::assurance::sign_assurance(5, [0x7c; 32], &[0]);
        let mut wire = assurance.encode();
        wire.push(0);

        let obs = Mutex::new(ObsLog::default());
        let seen = Mutex::new(Vec::new());
        handle_inbound_assurance(&wire, 5, &obs, &seen);

        assert_eq!(obs_codes(&obs), vec![NUT_SENT_BAD_ASSURANCE]);
        assert!(
            lock(&seen).is_empty(),
            "nothing is recorded as an assurance"
        );
    }

    #[test]
    fn a_truncated_assurance_is_refused() {
        tiny();
        let obs = Mutex::new(ObsLog::default());
        let seen = Mutex::new(Vec::new());
        handle_inbound_assurance(&[0x01, 0x02], 5, &obs, &seen);

        assert_eq!(obs_codes(&obs), vec![NUT_SENT_BAD_ASSURANCE]);
        assert!(lock(&seen).is_empty());
    }

    /// The module records; the lane judges. A received assurance is paired
    /// with the anchor the run expected only here, at the boundary, so a
    /// node that assured the wrong block is a *fault on a fact* rather than
    /// a message this module silently dropped.
    #[test]
    fn judging_happens_at_the_boundary_not_on_arrival() {
        tiny();
        let anchor = [0x7c; 32];
        let assurance = m2_reference::assurance::sign_assurance(5, anchor, &[0]);

        let obs = Mutex::new(ObsLog::default());
        let seen = Mutex::new(Vec::new());
        // Arrives and is recorded even though it names the wrong block.
        handle_inbound_assurance(&assurance.encode(), 5, &obs, &seen);
        assert_eq!(lock(&seen).len(), 1);

        let facts = assurances_for_lane(&lock(&seen), 5, &[[0x7d; 32]], &[0], |_| 2000);
        assert_eq!(facts.len(), 1);
        assert!(
            facts[0]
                .fault
                .as_deref()
                .is_some_and(|f| f.contains("WrongAnchor")),
            "the fault is named on the fact: {:?}",
            facts[0].fault
        );
        assert_eq!(facts[0].cores, vec![0]);
    }

    #[test]
    fn a_sound_assurance_reaches_the_lane_without_a_fault() {
        tiny();
        let anchor = [0x7c; 32];
        let assurance = m2_reference::assurance::sign_assurance(5, anchor, &[0]);
        let obs = Mutex::new(ObsLog::default());
        let seen = Mutex::new(Vec::new());
        handle_inbound_assurance(&assurance.encode(), 5, &obs, &seen);

        let facts = assurances_for_lane(&lock(&seen), 5, &[anchor], &[0], |_| 1500);
        assert_eq!(facts[0].fault, None);
        assert_eq!(facts[0].lead_ms, 1500);
        assert_eq!(facts[0].reported_cores, vec![0]);
    }
}
