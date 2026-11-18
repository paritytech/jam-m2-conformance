//! Erasure coding and justification checking, as the engine does them.
//!
//! Four questions, all of them sessionless: coding is a function of the bytes
//! and the shard count, and checking a proof is a function of the proof. None
//! of them touches a chain, so none of them takes a session.
//!
//! The counterpart of [`crate::assurance`], and the opposite answer to the
//! same test. There, the whole computation lived in `jam-std-common` and both
//! sides of the socket would have been calling the same library code, so a
//! round trip bought nothing. Here the work is in `jam-node`, which only the
//! oracle links, and a harness that coded its own shards would be grading a
//! node against a second implementation of Reed-Solomon.

use std::sync::Arc;

use m2_oracle_proto::Message;

use crate::chain::ChainError;
use crate::oracle::Oracle;

/// A bundle coded into one shard per validator.
#[derive(Clone, Debug)]
pub struct CodedBundle {
    /// One shard per validator, in validator order.
    pub shards: Vec<Vec<u8>>,
    /// How many shards reconstruct the bundle: `D(v)`, which for six
    /// validators is three.
    pub recovery_threshold: u16,
    /// The length every shard has.
    pub shard_len: u32,
}

/// A work package's exported segments, coded into one row per validator.
#[derive(Clone, Debug)]
pub struct CodedSegments {
    /// One shard per validator: that validator's slice of every segment,
    /// concatenated in segment order.
    pub shards: Vec<Vec<u8>>,
    /// The slice boundary inside each shard. A property of the coding, not a
    /// protocol constant, which is why it travels with the shards.
    pub slice_len: u32,
}

/// What a justification check said.
///
/// `verified` is `None` where the justification could not be read at all.
/// That is a disagreement about the structure of the message, not a proof
/// that failed, and the two belong in different findings: one sends a reader
/// to the codec, the other to the node's Merkle tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardCheck {
    pub verified: Option<bool>,
    pub detail: Option<String>,
}

/// Erasure-code a work-package bundle into `shard_count` shards.
pub fn code_bundle(
    oracle: &Arc<Oracle>,
    bundle: Vec<u8>,
    shard_count: u16,
) -> Result<CodedBundle, ChainError> {
    match oracle.expect(Message::CodeBundle {
        bundle,
        shard_count,
    })? {
        Message::CodedBundle {
            shards,
            recovery_threshold,
            shard_len,
        } => Ok(CodedBundle {
            shards,
            recovery_threshold,
            shard_len,
        }),
        other => Err(ChainError::Oracle(format!("CodeBundle answered {other:?}"))),
    }
}

/// Erasure-code exported segments into one shard per validator.
///
/// Every segment must be `SEGMENT_LEN` bytes; a shorter one is an error
/// rather than a padded segment, because padding would code into shards that
/// are wrong in a way no later check would attribute to this.
pub fn code_segments(
    oracle: &Arc<Oracle>,
    segments: Vec<Vec<u8>>,
    shard_count: u16,
) -> Result<CodedSegments, ChainError> {
    match oracle.expect(Message::CodeSegments {
        segments,
        shard_count,
    })? {
        Message::CodedSegments { shards, slice_len } => Ok(CodedSegments { shards, slice_len }),
        other => Err(ChainError::Oracle(format!(
            "CodeSegments answered {other:?}"
        ))),
    }
}

/// Everything needed to serve a bundle's shards, as a guarantor holds it.
#[derive(Clone, Debug)]
pub struct AvailableShards {
    pub erasure_root: [u8; 32],
    /// Per validator, in validator order.
    pub bundle_shards: Vec<Vec<u8>>,
    /// Per validator: that validator's slice of every segment, concatenated.
    pub segment_shards: Vec<Vec<u8>>,
    /// CE 137's justification per validator.
    pub shard_justifications: Vec<Vec<u8>>,
    /// CE 138's per validator, with the segment root appended.
    pub audit_justifications: Vec<Vec<u8>>,
    /// CE 140's, per validator and then per segment index.
    pub segment_justifications: Vec<Vec<Vec<u8>>>,
}

/// Code a bundle and its segments into servable shards with justifications.
///
/// The half of availability that was unreachable until `hazmat::merkle` was
/// exported (findings.md §9), and what lets a simulated node serve CE
/// 137/138/139/140 at all -- which is what it takes to show those rows
/// failing against a node that serves them wrongly.
pub fn make_available(
    oracle: &Arc<Oracle>,
    bundle: Vec<u8>,
    segments: Vec<Vec<u8>>,
    shard_count: u16,
) -> Result<AvailableShards, ChainError> {
    match oracle.expect(Message::MakeAvailable {
        bundle,
        segments,
        shard_count,
    })? {
        Message::AvailableShards {
            erasure_root,
            bundle_shards,
            segment_shards,
            shard_justifications,
            audit_justifications,
            segment_justifications,
        } => Ok(AvailableShards {
            erasure_root,
            bundle_shards,
            segment_shards,
            shard_justifications,
            audit_justifications,
            segment_justifications,
        }),
        other => Err(ChainError::Oracle(format!(
            "MakeAvailable answered {other:?}"
        ))),
    }
}

/// A CE 137 or CE 138 reply, as it came off the wire.
///
/// Carried whole rather than picked apart here, because the two protocols
/// take their segment root from different places and that choice is a rule
/// both sides must apply identically. It is applied once, in the oracle.
#[derive(Clone, Debug)]
pub struct ServedShard {
    /// 137 or 138.
    pub protocol: u16,
    pub erasure_root: [u8; 32],
    pub shard_index: u16,
    pub shard_count: u16,
    pub bundle_shard: Vec<u8>,
    /// CE 137's segment shards, as the raw concatenation the wire carries.
    /// Empty for CE 138.
    ///
    /// No slice length beside them: `jam_types::segment_slice_len` derives
    /// one from the shard count, and both sides link it.
    pub segment_shards: Vec<u8>,
    /// The justification's bytes exactly as received, not re-encoded through
    /// this harness's own type. Re-encoding would hide the disagreement
    /// worth finding: a check that passed on bytes the node never sent.
    pub justification: Vec<u8>,
}

/// Check a bundle-shard justification the way a node checks one it was
/// served.
pub fn check_served_shard(
    oracle: &Arc<Oracle>,
    served: ServedShard,
) -> Result<ShardCheck, ChainError> {
    match oracle.request(Message::CheckServedShard {
        protocol: served.protocol,
        erasure_root: served.erasure_root,
        shard_index: served.shard_index,
        shard_count: served.shard_count,
        bundle_shard: served.bundle_shard,
        segment_shards: served.segment_shards,
        justification: served.justification,
    })? {
        Message::ShardChecked { verified, detail } => Ok(ShardCheck { verified, detail }),
        // An `Error` here is the harness asking for a protocol that serves no
        // bundle shards, which is the caller's mistake and not the node's.
        Message::Error(why) => Err(ChainError::Chain(why)),
        other => Err(ChainError::Oracle(format!(
            "CheckServedShard answered {other:?}"
        ))),
    }
}

/// Check one CE 139/140 segment-shard justification.
#[allow(clippy::too_many_arguments)]
pub fn check_segment_shard(
    oracle: &Arc<Oracle>,
    erasure_root: [u8; 32],
    shard_index: u16,
    shard_count: u16,
    segment_index: u16,
    segment_count: u32,
    segment_slice: Vec<u8>,
    justification: Vec<u8>,
) -> Result<ShardCheck, ChainError> {
    match oracle.expect(Message::CheckSegmentShard {
        erasure_root,
        shard_index,
        shard_count,
        segment_index,
        segment_count,
        segment_slice,
        justification,
    })? {
        Message::ShardChecked { verified, detail } => Ok(ShardCheck { verified, detail }),
        other => Err(ChainError::Oracle(format!(
            "CheckSegmentShard answered {other:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The coding is the engine's, and it is deterministic: two sides of a
    /// run that coded differently would disagree about what a node owed.
    #[test]
    fn a_bundle_codes_the_same_way_twice() {
        let oracle = Oracle::for_tests();
        let bundle: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let first = code_bundle(&oracle, bundle.clone(), 6).expect("the bundle codes");
        let again = code_bundle(&oracle, bundle, 6).expect("the bundle codes again");

        assert_eq!(first.shards.len(), 6, "one shard per validator");
        assert_eq!(first.recovery_threshold, 3, "D(6) is three, not two");
        for shard in &first.shards {
            assert_eq!(shard.len() as u32, first.shard_len);
        }
        assert_eq!(again.shards, first.shards);
    }

    /// A row is one validator's slice of *every* segment, so three segments
    /// for six validators give six shards of three slices each -- not three
    /// shards, and not one shard per segment.
    #[test]
    fn segments_code_into_one_row_per_validator() {
        let oracle = Oracle::for_tests();
        let segments = vec![
            vec![0xa1; jam_types::SEGMENT_LEN],
            vec![0xb2; jam_types::SEGMENT_LEN],
            vec![0xc3; jam_types::SEGMENT_LEN],
        ];
        let coded = code_segments(&oracle, segments, 6).expect("the segments code");

        assert_eq!(coded.shards.len(), 6, "one row per validator");
        for shard in &coded.shards {
            assert_eq!(
                shard.len() as u32,
                coded.slice_len * 3,
                "each row holds one slice of each of the three segments"
            );
        }
    }

    /// A segment of the wrong length is refused rather than padded: padding
    /// would code into shards that are wrong in a way no later check could
    /// attribute to this.
    #[test]
    fn a_short_segment_is_refused() {
        let oracle = Oracle::for_tests();
        let error = code_segments(&oracle, vec![vec![0xa1; 8]], 6)
            .expect_err("a short segment is not codeable");
        assert!(
            format!("{error}").contains("8 bytes"),
            "the refusal says what was wrong: {error}"
        );
    }

    /// Where the segment root comes from is the one thing CE 137 and CE 138
    /// do differently, and the same bytes are read either way depending on
    /// which asked. One element is a whole proof for CE 137 and a root with
    /// nothing left for CE 138.
    #[test]
    fn the_protocol_decides_where_the_segment_root_comes_from() {
        let oracle = Oracle::for_tests();
        let mut element = vec![0u8];
        element.extend_from_slice(&[0x33; 32]);
        let served = |protocol: u16| ServedShard {
            protocol,
            erasure_root: [0x11; 32],
            shard_index: 0,
            shard_count: 6,
            bundle_shard: vec![0x22; 64],
            segment_shards: Vec::new(),
            justification: element.clone(),
        };

        let ce137 = check_served_shard(&oracle, served(137)).expect("CE 137 is checkable");
        assert_eq!(
            ce137.verified,
            Some(false),
            "CE 137 reads it as a proof, which does not verify: {:?}",
            ce137.detail
        );

        let ce138 = check_served_shard(&oracle, served(138)).expect("CE 138 is checkable");
        assert_eq!(
            ce138.verified, None,
            "CE 138 reads it as the segment root, leaving no proof at all"
        );
    }

    /// The two halves have to meet: a shard built by `make_available` must
    /// verify through `check_served_shard`, under both protocols.
    ///
    /// This is the test the rest of N4 rests on. If building and checking
    /// disagree -- about where the segment root comes from, about the
    /// element layout, about which validator's slices pair with which
    /// bundle shard -- then every row that grades a served shard is grading
    /// the harness against itself.
    #[test]
    fn a_shard_this_builds_is_a_shard_this_accepts() {
        let oracle = Oracle::for_tests();
        let bundle: Vec<u8> = (0..6000u32).map(|i| (i % 251) as u8).collect();
        let segments = vec![
            vec![0xa1; jam_types::SEGMENT_LEN],
            vec![0xb2; jam_types::SEGMENT_LEN],
        ];
        let held = make_available(&oracle, bundle, segments, 6).expect("the bundle is codeable");

        assert_eq!(held.bundle_shards.len(), 6);
        assert_eq!(held.segment_shards.len(), 6);
        assert_eq!(held.segment_justifications.len(), 6);

        for index in 0..6u16 {
            let i = index as usize;
            // CE 137: the segment shards travel beside the bundle shard and
            // their root is taken from them.
            let ce137 = check_served_shard(
                &oracle,
                ServedShard {
                    protocol: 137,
                    erasure_root: held.erasure_root,
                    shard_index: index,
                    shard_count: 6,
                    bundle_shard: held.bundle_shards[i].clone(),
                    segment_shards: held.segment_shards[i].clone(),
                    justification: held.shard_justifications[i].clone(),
                },
            )
            .expect("the oracle answers");
            assert_eq!(
                ce137.verified,
                Some(true),
                "CE 137 shard {index} must verify: {:?}",
                ce137.detail
            );

            // CE 138: no segment shards, and the root rides at the end of
            // the justification instead.
            let ce138 = check_served_shard(
                &oracle,
                ServedShard {
                    protocol: 138,
                    erasure_root: held.erasure_root,
                    shard_index: index,
                    shard_count: 6,
                    bundle_shard: held.bundle_shards[i].clone(),
                    segment_shards: Vec::new(),
                    justification: held.audit_justifications[i].clone(),
                },
            )
            .expect("the oracle answers");
            assert_eq!(
                ce138.verified,
                Some(true),
                "CE 138 shard {index} must verify: {:?}",
                ce138.detail
            );
        }
    }

    /// And CE 140's per-segment justifications likewise.
    #[test]
    fn a_segment_justification_this_builds_is_one_this_accepts() {
        let oracle = Oracle::for_tests();
        let segments = vec![
            vec![0xa1; jam_types::SEGMENT_LEN],
            vec![0xb2; jam_types::SEGMENT_LEN],
            vec![0xc3; jam_types::SEGMENT_LEN],
        ];
        let held = make_available(&oracle, vec![0x5a; 4096], segments.clone(), 6)
            .expect("the bundle is codeable");
        let slice_len = jam_types::segment_slice_len(6);

        for index in 0..6u16 {
            let i = index as usize;
            let row = &held.segment_shards[i];
            for segment in 0..segments.len() {
                let slice = row[segment * slice_len..(segment + 1) * slice_len].to_vec();
                let check = check_segment_shard(
                    &oracle,
                    held.erasure_root,
                    index,
                    6,
                    segment as u16,
                    segments.len() as u32,
                    slice,
                    held.segment_justifications[i][segment].clone(),
                )
                .expect("the oracle answers");
                assert_eq!(
                    check.verified,
                    Some(true),
                    "shard {index} segment {segment} must verify: {:?}",
                    check.detail
                );
            }
        }
    }

    /// A justification that is not a sequence of elements is reported as
    /// unreadable, not as a proof that failed. The two send a reader to
    /// different places.
    #[test]
    fn an_unreadable_justification_is_not_a_failed_proof() {
        let oracle = Oracle::for_tests();
        let check = check_served_shard(
            &oracle,
            ServedShard {
                protocol: 138,
                erasure_root: [0x11; 32],
                shard_index: 0,
                shard_count: 6,
                bundle_shard: vec![0x22; 64],
                segment_shards: Vec::new(),
                justification: vec![0xff, 0xff, 0xff],
            },
        )
        .expect("the oracle answers");
        assert_eq!(check.verified, None);
        assert!(check.detail.is_some(), "and it says why");
    }

    /// Asking a protocol that serves no bundle shards is the harness's
    /// mistake, and comes back as an error rather than as a node that failed
    /// a check.
    #[test]
    fn a_protocol_that_serves_no_shards_is_the_callers_error() {
        let oracle = Oracle::for_tests();
        let error = check_served_shard(
            &oracle,
            ServedShard {
                protocol: 140,
                erasure_root: [0x11; 32],
                shard_index: 0,
                shard_count: 6,
                bundle_shard: Vec::new(),
                segment_shards: Vec::new(),
                justification: Vec::new(),
            },
        )
        .expect_err("CE 140 does not serve bundle shards");
        assert!(format!("{error}").contains("140"), "{error}");
    }
}
