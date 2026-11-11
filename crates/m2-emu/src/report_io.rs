//! N3 guaranteeing I/O for the emulated validators (CE 133/134/135).
//!
//! Inbound only, so far: the NUT's CE 134 sharing streams and CE 135 report
//! distributions are decoded and recorded. Nothing here refines, signs or
//! judges anything — the records go to the N3 lane, which grades them against
//! values `m2-reference` computed.

use std::sync::Mutex;

use jam_types::Decode;
use jamnp_s::{
    codec::ce131_136::{GuaranteedWorkReport, SharingBundle, SharingContext},
    trace::wall_ts,
};
use m2_scenario::dsl::{ObsKind, ObsLog};
use m2_scenario::scenarios::n3::{ReportSeen, SharingSeen};
use m2_scenario::scenarios::obs::{NUT_SENT_BAD_REPORT, NUT_SENT_BAD_SHARING};

use crate::emu::{record, StreamReader};

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
pub(crate) async fn handle_inbound_sharing(
    first: &[u8],
    reader: &mut StreamReader,
    peer: u16,
    obs: &Mutex<ObsLog>,
    seen: &Mutex<Vec<SharingSeen>>,
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
}

/// Record a CE 135 work-report distribution the NUT sent
/// (`simple.md:460-485`).
///
/// The report is kept encoded as well as hashed. The lane compares against
/// the reference's report, and a hash match alone would say the two agree
/// without being able to show where they differ when they do not.
pub fn handle_inbound_report(
    content: &[u8],
    peer: u16,
    obs: &Mutex<ObsLog>,
    seen: &Mutex<Vec<ReportSeen>>,
) {
    let at_wall_ms = wall_ts();
    let mut input: &[u8] = content;
    let Ok(distribution) = GuaranteedWorkReport::decode(&mut input) else {
        record(obs, peer, ObsKind::Other(NUT_SENT_BAD_REPORT));
        return;
    };
    // `Report ++ Slot ++ len++[(Idx, Sig)]` and nothing after it.
    if !input.is_empty() {
        record(obs, peer, ObsKind::Other(NUT_SENT_BAD_REPORT));
        return;
    }
    record(obs, peer, ObsKind::Ce135Report);
    crate::emu::lock(seen).push(ReportSeen {
        peer,
        report_hash: distribution.report.hash().0,
        slot: distribution.slot,
        signatures: distribution.signatures,
        encoded_report: jam_types::Encode::encode(&distribution.report),
        at_wall_ms,
    });
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
