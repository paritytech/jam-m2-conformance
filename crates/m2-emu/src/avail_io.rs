//! CE 137/138/139/140/141: asking the node for shards, and the assurances
//! that travel both ways.
//!
//! Every judgement here belongs to the lane, not to this module. What it
//! does is put a request on the wire, record what came back, and hand the
//! bytes on; whether a shard is the right shard and whether a justification
//! proves anything is decided in `m2-scenario::scenarios::n4` from facts the
//! *engine* produced. A module that answered those questions itself would be
//! a second implementation of the rules it is grading against.

use std::sync::{Arc, Mutex};

use jam_types::{Decode, Encode};
use jamnp_s::{
    codec::{
        ce137_148::{
            ProvenSegmentShardsResponse, SegmentShardRequest, SegmentShardsResponse, ShardRequest,
            ShardResponse,
        },
        ce141_145::Assurance,
    },
    framing::{frame, CE137, CE140, CE141},
    trace::{wall_ts, Direction as TraceDir, Trace},
    transport::Conn,
};
use m2_scenario::dsl::{ObsKind, ObsLog};
use m2_scenario::scenarios::n4::{AssuranceSeen, SegmentShardsServed, ShardServed};

use crate::emu::{lock, record, trace_record, StreamReader};

/// The NUT sent something on CE 141 that is not an assurance.
pub const NUT_SENT_BAD_ASSURANCE: u8 = 0xA1;

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
    record(obs, peer, ObsKind::Other(crate::avail_io::SENT_ASSURANCE));
    true
}

/// The harness offered the node an assurance.
pub const SENT_ASSURANCE: u8 = 0xA2;

/// Ask the NUT for a bundle shard over CE 137 or CE 138.
///
/// `expected_bundle_shard` is what the reference coded for that index, when
/// the caller knows the bundle. It is carried through rather than compared
/// here so that the comparison, and the decision about what a mismatch
/// means, stay in one place.
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
        erasure_root: erasure_root.into(),
        shard_index,
    };
    let reply = exchange(connection, protocol, &request.encode(), peer, trace).await?;
    record(obs, peer, ObsKind::ServesCe137);

    let mut served = ShardServed {
        protocol: protocol as u16,
        erasure_root,
        shard_index,
        bundle_shard: Vec::new(),
        expected_bundle_shard,
        segment_shards: Vec::new(),
        // Filled by the caller, which can reach the oracle; this module
        // deliberately cannot.
        justification_verified: None,
        justification_detail: None,
        refused: false,
    };
    let Exchange::Answered(content) = reply else {
        served.refused = true;
        return Some(served);
    };

    // CE 138's reply carries no segment shards, so the two protocols decode
    // into different types even though the lane grades them alike.
    let mut input: &[u8] = &content;
    if protocol == CE137 {
        let Ok(response) = ShardResponse::decode(&mut input) else {
            served.justification_detail = Some("the CE 137 response did not decode".into());
            return Some(served);
        };
        served.bundle_shard = response.bundle_shard;
        served.segment_shards = response.segment_shards;
        served.justification_detail = Some(hex(&response.justification.encode()));
    } else {
        let Ok(response) = jamnp_s::codec::ce137_148::AuditShardResponse::decode(&mut input) else {
            served.justification_detail = Some("the CE 138 response did not decode".into());
            return Some(served);
        };
        served.bundle_shard = response.bundle_shard;
        served.justification_detail = Some(hex(&response.justification.encode()));
    }
    Some(served)
}

/// Ask the NUT for segment shards over CE 139 or CE 140.
#[allow(clippy::too_many_arguments)]
pub async fn request_segment_shards(
    connection: &Conn,
    protocol: u8,
    erasure_root: [u8; 32],
    shard_index: u16,
    segment_indices: Vec<u16>,
    peer: u16,
    trace: &Arc<Mutex<Trace>>,
    obs: &Arc<Mutex<ObsLog>>,
) -> Option<SegmentShardsServed> {
    let request = SegmentShardRequest {
        erasure_root: erasure_root.into(),
        shard_index,
        segment_indices: segment_indices.clone(),
    };
    let reply = exchange(connection, protocol, &request.encode(), peer, trace).await?;
    record(obs, peer, ObsKind::Other(SERVED_SEGMENT_SHARDS));

    let mut served = SegmentShardsServed {
        protocol: protocol as u16,
        erasure_root,
        shard_index,
        requested: segment_indices,
        shards: Vec::new(),
        justifications_verified: Vec::new(),
        refused: false,
    };
    let Exchange::Answered(content) = reply else {
        served.refused = true;
        return Some(served);
    };

    let mut input: &[u8] = &content;
    if protocol == CE140 {
        // CE 140 adds one justification per shard, which the caller checks.
        if let Ok(response) = ProvenSegmentShardsResponse::decode(&mut input) {
            served.shards = response.segment_shards;
        }
    } else if let Ok(response) = SegmentShardsResponse::decode(&mut input) {
        served.shards = response.segment_shards;
    }
    Some(served)
}

/// The NUT answered a CE 139/140 segment-shard request.
pub const SERVED_SEGMENT_SHARDS: u8 = 0xA3;

/// What came of a request: an answer, or a refusal.
enum Exchange {
    Answered(Vec<u8>),
    Refused,
}

/// Open a stream, send one message, read one reply.
///
/// `None` only when the stream could not be opened at all, which is a
/// harness-side failure rather than anything the node did; a reset is
/// `Refused`, which is an answer and belongs in the facts.
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

    let mut reader = StreamReader::new(recv);
    match reader.next().await {
        Ok(Some((_, content))) => {
            trace_record(peer, protocol, stream_id, &content, trace, TraceDir::Tx);
            Some(Exchange::Answered(content.to_vec()))
        }
        // A clean close with no reply, or a reset: either way the node
        // declined to serve, which the lane grades.
        Ok(None) | Err(_) => Some(Exchange::Refused),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Turn the assurances the node sent into the lane's facts.
///
/// The anchor it should have used and the cores that carried reports come
/// from the run; this only pairs them with what arrived.
pub fn assurances_for_lane(
    raw: &[RawAssurance],
    nut_index: u16,
    expected_anchor: [u8; 32],
    reported_cores: &[u16],
    slot_start_ms: impl Fn(u64) -> i64,
) -> Vec<AssuranceSeen> {
    raw.iter()
        .map(|entry| {
            let fault = m2_reference::assurance::check_assurance(
                &entry.assurance,
                nut_index,
                expected_anchor,
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

        let facts = assurances_for_lane(&lock(&seen), 5, [0x7d; 32], &[0], |_| 2000);
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

        let facts = assurances_for_lane(&lock(&seen), 5, anchor, &[0], |_| 1500);
        assert_eq!(facts[0].fault, None);
        assert_eq!(facts[0].lead_ms, 1500);
        assert_eq!(facts[0].reported_cores, vec![0]);
    }
}
