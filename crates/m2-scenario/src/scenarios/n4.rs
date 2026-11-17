//! N4 — availability: CE 137/138/139/140 serving and CE 141 assurances.
//!
//! Five of DESIGN §11 N4's seven rows. The two missing ones are the ones
//! where the *harness* must serve shards to the node — CE 137 fetch and
//! CE 139/140 fetch — and they are blocked upstream: `bundle_justification`
//! takes a proof nothing outside `jam-node` can build (findings.md §9).
//! Every row here is the node producing and the harness checking, which the
//! exported `check_bundle_proof` and `check_segment_proof` cover.
//!
//! **What this lane does not re-implement.** Erasure coding, justification
//! checking and assurance signing all come from the engine, through
//! `m2-reference`. A lane that coded its own shards would be grading a node
//! against a second implementation of Reed–Solomon, which is the mistake
//! `proxy_index` already made once in this harness.
//!
//! **What a pass here does not yet mean.** Every row is graded on a
//! deterministic baseline and none of them has been shown to *fail* against
//! a node that misbehaves: there are no availability variants in `m2-sim`,
//! so nothing proves these checks catch anything. Until there are, `n4` is
//! asked for by name rather than being in the default lane set, and a green
//! N4 should be read as "nothing contradicted the node", not as "the node
//! was checked".

use crate::dsl::{check, log, Check, Control, Severity};

/// A CE 137 or CE 138 response the NUT served.
///
/// `justification_verified` is `None` where the justification could not be
/// decoded at all: that is a disagreement about the structure rather than a
/// proof that failed, and the two are different findings.
#[derive(Clone, Debug)]
pub struct ShardServed {
    /// Which protocol asked: 137 carries segment shards, 138 does not.
    pub protocol: u16,
    pub erasure_root: [u8; 32],
    pub shard_index: u16,
    /// The bundle shard the NUT sent.
    pub bundle_shard: Vec<u8>,
    /// What the reference coded for that index, when the lane knows the
    /// bundle. `None` leaves the byte comparison unmade rather than passed.
    pub expected_bundle_shard: Option<Vec<u8>>,
    /// CE 137's segment shards, as the raw concatenation the wire carries.
    ///
    /// Not split into one `Vec` per segment, because the wire does not split
    /// them: the reply is one message of slices back to back, and where the
    /// boundaries fall follows from the shard count. Splitting here would be
    /// this harness's second opinion about that.
    pub segment_shards: Vec<u8>,
    /// How many messages the NUT sent before closing the stream.
    ///
    /// CE 137 owes three -- shard, segment shards, justification -- and CE
    /// 138 owes two. A reply short of its count is a different complaint
    /// from one whose justification does not verify.
    pub messages: usize,
    /// The justification exactly as it came off the wire.
    ///
    /// Kept as bytes rather than decoded here: whether it proves anything is
    /// the engine's answer, and re-encoding it through this harness's own
    /// type on the way would hide the disagreement worth finding.
    pub justification: Vec<u8>,
    pub justification_verified: Option<bool>,
    /// Why a justification could not be read, when it could not.
    pub justification_detail: Option<String>,
    /// The NUT reset the stream instead of answering.
    pub refused: bool,
}

impl ShardServed {
    /// Messages a well-formed reply carries: `simple.md:552-554` for CE 137,
    /// `simple.md:577-578` for CE 138.
    pub fn messages_owed(protocol: u16) -> usize {
        if protocol == 137 {
            3
        } else {
            2
        }
    }
}

/// A CE 139 or CE 140 response: segment shards for named indices.
#[derive(Clone, Debug)]
pub struct SegmentShardsServed {
    /// 139 carries shards alone, 140 adds a justification per shard.
    pub protocol: u16,
    pub erasure_root: [u8; 32],
    pub shard_index: u16,
    /// The segment indices asked for, in request order.
    pub requested: Vec<u16>,
    /// The slices the NUT returned, split at the slice length the shard
    /// count fixes. One per index asked for, in the order asked: the reply
    /// carries no indices of its own, so position is the only thing tying a
    /// slice to its segment.
    pub shards: Vec<Vec<u8>>,
    /// CE 140's justifications, one message per requested index, as they
    /// arrived. Empty for CE 139, which sends none.
    pub justifications: Vec<Vec<u8>>,
    /// Per-shard verification for CE 140; empty for CE 139, which carries
    /// no justification to check.
    pub justifications_verified: Vec<Option<bool>>,
    /// Why a justification could not be read, by shard, when one could not.
    pub justification_details: Vec<Option<String>>,
    /// The NUT's one data message was not a whole number of slices.
    ///
    /// Kept apart from a short reply: a reply of the wrong *length* says the
    /// two sides disagree about the slice width, which no count of shards
    /// would show.
    pub ragged: bool,
    pub refused: bool,
}

/// A CE 141 assurance the NUT broadcast.
#[derive(Clone, Debug)]
pub struct AssuranceSeen {
    /// The validator the harness received it on, which must be the NUT.
    pub from: u16,
    pub anchor: [u8; 32],
    /// Cores the bitfield claims.
    pub cores: Vec<u16>,
    /// `None` when the assurance was well formed and verified; otherwise why
    /// it was refused, in the reference's words.
    pub fault: Option<String>,
    /// Milliseconds before the start of the slot it was sent for.
    ///
    /// `simple.md:679-680` asks for roughly two seconds' lead. Negative
    /// means it arrived after the slot had begun.
    pub lead_ms: i64,
    /// Cores the harness knows had a report at that anchor, so a bit set
    /// for anything else is a claim about an empty core.
    pub reported_cores: Vec<u16>,
}

/// An assurance the harness sent the NUT, and whether a block carried it.
#[derive(Clone, Debug)]
pub struct AssuranceOffered {
    pub validator: u16,
    pub anchor: [u8; 32],
    pub cores: Vec<u16>,
    /// Slot it was sent in, so only later blocks are expected to carry it.
    pub sent_in_slot: u32,
    /// True when a NUT block authored after `sent_in_slot` carried it.
    pub included: bool,
    /// Whether the NUT authored any block after it was sent. Without one
    /// there was no opportunity to include anything.
    pub had_opportunity: bool,
    /// Deliberately invalid, and so expected to be left out.
    pub fault: Option<AssuranceFaultKind>,
}

/// An assurance the harness spoiled on purpose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssuranceFaultKind {
    /// Anchored to a block that is not the one being assured.
    WrongAnchor,
    /// Signed by a key that is not the claimed validator's.
    BadSignature,
    /// A bit set for a core carrying no report.
    EmptyCore,
}

impl AssuranceFaultKind {
    pub fn describe(&self) -> &'static str {
        match self {
            Self::WrongAnchor => "an assurance anchored to the wrong block",
            Self::BadSignature => "an assurance signed by the wrong key",
            Self::EmptyCore => "an assurance claiming a core with no report",
        }
    }
}

/// Facts the N4 lane grades.
#[derive(Clone, Debug, Default)]
pub struct N4Ctx {
    pub nut_index: u16,
    /// CE 137/138 responses, as served by the NUT.
    pub shards_served: Vec<ShardServed>,
    /// CE 139/140 responses.
    pub segment_shards_served: Vec<SegmentShardsServed>,
    /// CE 141 assurances the NUT sent.
    pub assurances_seen: Vec<AssuranceSeen>,
    /// CE 141 assurances the harness sent the NUT.
    pub assurances_offered: Vec<AssuranceOffered>,
    /// How many validators must assure a core for its report to be
    /// available. Carried rather than computed: it is a protocol quantity
    /// and a lane holding its own copy is one re-pin from being wrong.
    pub availability_threshold: u16,
    /// Validators that assured each core, by core, as the NUT's own blocks
    /// recorded them.
    pub assured_by_core: Vec<(u16, Vec<u16>)>,
}

/// CE 137: the NUT serves a bundle shard with its segment shards and a
/// justification (`simple.md:523-556`).
pub fn n4_ce137_serve(ctx: &N4Ctx) -> Check {
    let ctx = ctx.clone();
    check("n4_ce137_serve", Severity::Hard, move |_obs| {
        let served: Vec<_> = ctx
            .shards_served
            .iter()
            .filter(|s| s.protocol == 137)
            .collect();
        let control = Control::new(
            "n4_ce137_not_exercised",
            "a CE 137 shard request the NUT answered",
            !served.is_empty(),
        );
        if !control.present() {
            return vec![control.absent("n4_ce137_not_exercised")];
        }
        let mut results = Vec::new();
        for shard in served {
            results.extend(grade_served_shard(shard, "n4_ce137"));
        }
        results
    })
}

/// CE 138: the bundle shard alone, with a justification carrying the
/// segment-shard root (`simple.md:558-580`).
pub fn n4_ce138_serve(ctx: &N4Ctx) -> Check {
    let ctx = ctx.clone();
    check("n4_ce138_serve", Severity::Hard, move |_obs| {
        let served: Vec<_> = ctx
            .shards_served
            .iter()
            .filter(|s| s.protocol == 138)
            .collect();
        let control = Control::new(
            "n4_ce138_not_exercised",
            "a CE 138 shard request the NUT answered",
            !served.is_empty(),
        );
        if !control.present() {
            return vec![control.absent("n4_ce138_not_exercised")];
        }
        let mut results = Vec::new();
        for shard in served {
            results.extend(grade_served_shard(shard, "n4_ce138"));
        }
        results
    })
}

/// The rules CE 137 and CE 138 share: the stream is answered, the shard is
/// the reference's, and the justification proves it.
fn grade_served_shard(shard: &ShardServed, prefix: &'static str) -> Vec<crate::dsl::CheckResult> {
    let mut results = vec![log::check_detail(
        leak(format!("{prefix}_answered")),
        !shard.refused,
        Severity::Hard,
        || {
            format!(
                "the NUT reset the CE {} stream for root {} index {}",
                shard.protocol,
                short(&shard.erasure_root),
                shard.shard_index
            )
        },
    )];
    if shard.refused {
        return results;
    }

    // The reply is a sequence of whole messages, and how many of them there
    // are is the shape of the protocol: `Bundle Shard ++ [Segment Shard] ++
    // Justification` for CE 137, and the same without the middle one for CE
    // 138. A reply one message short is a different complaint from one whose
    // justification does not verify -- it says the node stopped, not that it
    // proved something untrue -- and the rows below would otherwise read the
    // missing message as an empty one.
    //
    // This is the row that carries CE 137's segment shards. Counting them
    // instead would fail a package that legitimately exports none: it still
    // owes the message, empty.
    let owed = ShardServed::messages_owed(shard.protocol);
    results.push(log::check_detail(
        leak(format!("{prefix}_reply_complete")),
        shard.messages == owed,
        Severity::Hard,
        || {
            format!(
                "CE {} for root {} index {} sent {} message(s) and owes {owed}",
                shard.protocol,
                short(&shard.erasure_root),
                shard.shard_index,
                shard.messages
            )
        },
    ));

    // Byte-for-byte against what the reference coded. Only when the lane
    // knows the bundle: a shard it cannot predict is not a shard the node
    // got wrong.
    if let Some(expected) = &shard.expected_bundle_shard {
        results.push(log::check_detail(
            leak(format!("{prefix}_shard_matches_the_reference")),
            &shard.bundle_shard == expected,
            Severity::Hard,
            || {
                format!(
                    "the NUT's bundle shard for root {} index {} is {} bytes and the \
                     reference coded {} bytes",
                    short(&shard.erasure_root),
                    shard.shard_index,
                    shard.bundle_shard.len(),
                    expected.len()
                )
            },
        ));
    }

    // A justification that cannot be decoded is reported on its own, not as
    // a proof that failed: one says the two sides read the structure
    // differently, the other says the node proved something untrue.
    match shard.justification_verified {
        None => results.push(log::check_detail(
            leak(format!("{prefix}_justification_decodes")),
            false,
            Severity::Hard,
            || {
                format!(
                    "the justification for root {} index {} could not be read: {}",
                    short(&shard.erasure_root),
                    shard.shard_index,
                    shard.justification_detail.as_deref().unwrap_or("no detail")
                )
            },
        )),
        Some(verified) => results.push(log::check_detail(
            leak(format!("{prefix}_justification_verifies")),
            verified,
            Severity::Hard,
            || {
                format!(
                    "the justification for root {} index {} does not prove that shard sits \
                     under that root",
                    short(&shard.erasure_root),
                    shard.shard_index
                )
            },
        )),
    }
    results
}

/// CE 139/140: segment shards for named indices, 140 with justifications
/// (`simple.md:597-648`).
pub fn n4_ce139_140_serve(ctx: &N4Ctx) -> Check {
    let ctx = ctx.clone();
    check("n4_ce139_140_serve", Severity::Hard, move |_obs| {
        let control = Control::new(
            "n4_ce139_140_not_exercised",
            "a CE 139 or CE 140 segment-shard request the NUT answered",
            !ctx.segment_shards_served.is_empty(),
        );
        if !control.present() {
            return vec![control.absent("n4_ce139_140_not_exercised")];
        }
        let mut results = Vec::new();
        for served in &ctx.segment_shards_served {
            results.push(log::check_detail(
                "n4_ce139_140_answered",
                !served.refused,
                Severity::Hard,
                || {
                    format!(
                        "the NUT reset the CE {} stream for root {} index {}",
                        served.protocol,
                        short(&served.erasure_root),
                        served.shard_index
                    )
                },
            ));
            if served.refused {
                continue;
            }

            // The slices arrive concatenated in one message, so the first
            // thing to establish is that its length is a whole number of
            // them. A ragged message means the two sides disagree about the
            // slice width, and every count below it would then be counting
            // the wrong thing.
            results.push(log::check_detail(
                "n4_ce139_140_slices_are_whole",
                !served.ragged,
                Severity::Hard,
                || {
                    format!(
                        "CE {} for root {} index {} returned a data message that is not a \
                         whole number of segment slices",
                        served.protocol,
                        short(&served.erasure_root),
                        served.shard_index
                    )
                },
            ));
            if served.ragged {
                continue;
            }

            // One shard per index asked for, in the order asked. The reply
            // carries no indices of its own, so position is the only thing
            // tying a shard to the segment it belongs to.
            results.push(log::check_detail(
                "n4_ce139_140_one_shard_per_request",
                served.shards.len() == served.requested.len(),
                Severity::Hard,
                || {
                    format!(
                        "CE {} asked for {} segment shards and {} came back",
                        served.protocol,
                        served.requested.len(),
                        served.shards.len()
                    )
                },
            ));

            if served.protocol == 140 {
                let all_verified = !served.justifications_verified.is_empty()
                    && served
                        .justifications_verified
                        .iter()
                        .all(|v| *v == Some(true));
                results.push(log::check_detail(
                    "n4_ce140_justifications_verify",
                    all_verified,
                    Severity::Hard,
                    || {
                        let bad = served
                            .justifications_verified
                            .iter()
                            .enumerate()
                            .filter(|(_, v)| **v != Some(true))
                            .map(|(i, v)| match v {
                                None => format!(
                                    "{i}: unreadable ({})",
                                    served
                                        .justification_details
                                        .get(i)
                                        .and_then(|d| d.as_deref())
                                        .unwrap_or("no detail")
                                ),
                                Some(_) => format!("{i}: did not verify"),
                            })
                            .collect::<Vec<_>>();
                        format!(
                            "CE 140 for root {} index {}: {}",
                            short(&served.erasure_root),
                            served.shard_index,
                            if bad.is_empty() {
                                "no justifications at all".to_string()
                            } else {
                                bad.join(", ")
                            }
                        )
                    },
                ));
            }
        }
        results
    })
}

/// CE 141 send: the NUT broadcasts assurances (`simple.md:675-695`).
pub fn n4_ce141_send(ctx: &N4Ctx) -> Check {
    let ctx = ctx.clone();
    check("n4_ce141_send", Severity::Hard, move |_obs| {
        let control = Control::new(
            "n4_ce141_not_exercised",
            "an assurance the NUT broadcast",
            !ctx.assurances_seen.is_empty(),
        );
        if !control.present() {
            return vec![control.absent("n4_ce141_not_exercised")];
        }
        let mut results = Vec::new();
        for seen in &ctx.assurances_seen {
            results.push(log::check_detail(
                "n4_ce141_well_formed",
                seen.fault.is_none(),
                Severity::Hard,
                || {
                    format!(
                        "the assurance from validator {} for anchor {} was refused: {}",
                        seen.from,
                        short(&seen.anchor),
                        seen.fault.as_deref().unwrap_or("no reason")
                    )
                },
            ));
            if seen.fault.is_some() {
                continue;
            }

            // A bit set for a core with no report claims availability for
            // nothing. `simple.md` lists it as its own exclusion, so it is
            // graded apart from the signature being sound.
            let empty: Vec<u16> = seen
                .cores
                .iter()
                .copied()
                .filter(|core| !seen.reported_cores.contains(core))
                .collect();
            results.push(log::check_detail(
                "n4_ce141_bits_have_reports",
                empty.is_empty(),
                Severity::Hard,
                || {
                    format!(
                        "the assurance for anchor {} claims core(s) {empty:?} that carried no \
                         report; cores with reports were {:?}",
                        short(&seen.anchor),
                        seen.reported_cores
                    )
                },
            ));

            // Soft: `simple.md:679-680` says roughly two seconds before the
            // slot, and "roughly" is not a number a node can be failed on.
            results.push(log::check_detail(
                "n4_ce141_sent_before_the_slot",
                seen.lead_ms > 0,
                Severity::Soft,
                || {
                    format!(
                        "the assurance for anchor {} arrived {} ms after its slot began; \
                         `simple.md:679-680` asks for roughly 2000 ms before",
                        short(&seen.anchor),
                        -seen.lead_ms
                    )
                },
            ));
        }
        results
    })
}

/// CE 141 receive: the NUT includes valid assurances and leaves out the
/// rest.
pub fn n4_ce141_inclusion(ctx: &N4Ctx) -> Check {
    let ctx = ctx.clone();
    check("n4_ce141_inclusion", Severity::Hard, move |_obs| {
        let control = Control::new(
            "n4_ce141_inclusion_not_exercised",
            "an assurance offered to the NUT",
            !ctx.assurances_offered.is_empty(),
        );
        if !control.present() {
            return vec![control.absent("n4_ce141_inclusion_not_exercised")];
        }

        let mut results = Vec::new();
        for offered in &ctx.assurances_offered {
            // A node that authored nothing after the offer had no chance to
            // include it, and saying so is not the same as passing it.
            if !offered.had_opportunity {
                results.push(
                    Control::new(
                        "n4_ce141_inclusion_not_exercised",
                        "a NUT block authored after the assurance was offered",
                        false,
                    )
                    .absent("n4_ce141_inclusion_not_exercised"),
                );
                continue;
            }
            match offered.fault {
                None => results.push(log::check_detail(
                    "n4_ce141_valid_assurance_included",
                    offered.included,
                    Severity::Hard,
                    || {
                        format!(
                            "the NUT authored a block after validator {}'s assurance for \
                             anchor {} and did not carry it",
                            offered.validator,
                            short(&offered.anchor)
                        )
                    },
                )),
                Some(fault) => results.push(log::check_detail(
                    "n4_ce141_invalid_assurance_excluded",
                    !offered.included,
                    Severity::Hard,
                    || {
                        format!(
                            "the NUT included {} from validator {} for anchor {}",
                            fault.describe(),
                            offered.validator,
                            short(&offered.anchor)
                        )
                    },
                )),
            }
        }

        // A report is available once enough validators have assured its
        // core. The threshold travels in the context rather than being
        // recomputed here.
        for (core, assurers) in &ctx.assured_by_core {
            results.push(log::check_detail(
                "n4_availability_threshold_reached",
                assurers.len() as u16 >= ctx.availability_threshold,
                Severity::Soft,
                || {
                    format!(
                        "core {core} was assured by {} validator(s) and needs {}: {assurers:?}",
                        assurers.len(),
                        ctx.availability_threshold
                    )
                },
            ));
        }
        results
    })
}

/// Every N4 check.
pub fn all(ctx: &N4Ctx) -> Vec<Check> {
    vec![
        n4_ce137_serve(ctx),
        n4_ce138_serve(ctx),
        n4_ce139_140_serve(ctx),
        n4_ce141_send(ctx),
        n4_ce141_inclusion(ctx),
    ]
}

fn short(bytes: &[u8; 32]) -> String {
    bytes[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// Row names are `&'static str` and CE 137 and CE 138 share their rules, so
/// the shared grader builds the name per protocol.
///
/// Leaked rather than threaded through as an owned string: a check's name
/// outlives the call that produced it, and there are at most a dozen.
fn leak(name: String) -> &'static str {
    Box::leak(name.into_boxed_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsl::Outcome;

    fn results(check: Check) -> Vec<(String, Outcome)> {
        let log = crate::dsl::ObsLog::default();
        (check.run)(&log)
            .into_iter()
            .map(|r| (r.name.to_string(), r.outcome))
            .collect()
    }

    fn names(check: Check) -> Vec<String> {
        results(check).into_iter().map(|(n, _)| n).collect()
    }

    fn served(protocol: u16) -> ShardServed {
        ShardServed {
            protocol,
            erasure_root: [0x11; 32],
            shard_index: 2,
            bundle_shard: vec![1, 2, 3],
            expected_bundle_shard: Some(vec![1, 2, 3]),
            segment_shards: vec![4, 5],
            messages: ShardServed::messages_owed(protocol),
            justification: vec![0, 9],
            justification_verified: Some(true),
            justification_detail: None,
            refused: false,
        }
    }

    #[test]
    fn a_lane_with_nothing_in_it_reports_unexercised() {
        let ctx = N4Ctx::default();
        for check in all(&ctx) {
            let out = results(check);
            assert_eq!(out.len(), 1, "one control row each: {out:?}");
            assert!(
                out[0].0.ends_with("not_exercised"),
                "and it names itself unexercised: {out:?}"
            );
        }
    }

    #[test]
    fn a_well_served_ce137_passes_every_row() {
        let ctx = N4Ctx {
            shards_served: vec![served(137)],
            ..Default::default()
        };
        let out = results(n4_ce137_serve(&ctx));
        assert!(
            out.iter().all(|(_, o)| *o == Outcome::Pass),
            "all rows pass: {out:?}"
        );
        assert!(out.iter().any(|(n, _)| n == "n4_ce137_reply_complete"));
    }

    /// CE 137 owes three messages and CE 138 two, so a CE 137 reply that
    /// stopped after the bundle shard and its justification is short --
    /// even though those are exactly the two messages CE 138 owes.
    ///
    /// Counting the segment shards instead would fail a package that
    /// legitimately exports none: it still owes the message, empty.
    #[test]
    fn a_ce137_reply_missing_its_segment_shards_is_short() {
        let ctx = N4Ctx {
            shards_served: vec![ShardServed {
                messages: 2,
                segment_shards: Vec::new(),
                ..served(137)
            }],
            ..Default::default()
        };
        let out = results(n4_ce137_serve(&ctx));
        assert!(
            out.iter()
                .any(|(n, o)| n == "n4_ce137_reply_complete" && matches!(o, Outcome::Fail(_))),
            "{out:?}"
        );

        // The same two messages are a whole CE 138 reply.
        let ctx = N4Ctx {
            shards_served: vec![ShardServed {
                messages: 2,
                segment_shards: Vec::new(),
                ..served(138)
            }],
            ..Default::default()
        };
        let out = results(n4_ce138_serve(&ctx));
        assert!(
            out.iter().all(|(_, o)| *o == Outcome::Pass),
            "CE 138 owes two and sent two: {out:?}"
        );
        assert!(out
            .iter()
            .any(|(n, _)| n == "n4_ce138_justification_verifies"));
    }

    /// A package exporting no segments still owes the message, so an empty
    /// one is a complete reply and not a missing shard.
    #[test]
    fn a_ce137_reply_with_no_exported_segments_is_complete() {
        let ctx = N4Ctx {
            shards_served: vec![ShardServed {
                segment_shards: Vec::new(),
                ..served(137)
            }],
            ..Default::default()
        };
        let out = results(n4_ce137_serve(&ctx));
        assert!(
            out.iter().all(|(_, o)| *o == Outcome::Pass),
            "three messages, the middle one empty: {out:?}"
        );
    }

    /// An unreadable justification and one that fails to verify are
    /// different rows, because they send a reader to different places.
    #[test]
    fn an_unreadable_justification_is_its_own_row() {
        let ctx = N4Ctx {
            shards_served: vec![ShardServed {
                justification_verified: None,
                justification_detail: Some("trailing bytes".into()),
                ..served(137)
            }],
            ..Default::default()
        };
        let out = results(n4_ce137_serve(&ctx));
        assert!(
            out.iter()
                .any(|(n, o)| n == "n4_ce137_justification_decodes" && *o != Outcome::Pass),
            "{out:?}"
        );
        assert!(
            !out.iter()
                .any(|(n, _)| n == "n4_ce137_justification_verifies"),
            "and not also reported as a proof that failed: {out:?}"
        );
    }

    #[test]
    fn a_refused_stream_stops_the_other_rows() {
        let ctx = N4Ctx {
            shards_served: vec![ShardServed {
                refused: true,
                ..served(137)
            }],
            ..Default::default()
        };
        let out = results(n4_ce137_serve(&ctx));
        // Answering is the only question worth asking of a reset stream;
        // grading the shard bytes of a reply that never came would report
        // several failures for one fault.
        assert_eq!(out.len(), 1, "answered, and nothing else: {out:?}");
        assert!(out
            .iter()
            .any(|(n, o)| n == "n4_ce137_answered" && matches!(o, Outcome::Fail(_))));
    }

    #[test]
    fn a_shard_the_lane_cannot_predict_is_not_compared() {
        let ctx = N4Ctx {
            shards_served: vec![ShardServed {
                expected_bundle_shard: None,
                ..served(137)
            }],
            ..Default::default()
        };
        let out = names(n4_ce137_serve(&ctx));
        assert!(
            !out.iter().any(|n| n.contains("matches_the_reference")),
            "no comparison row without a reference shard: {out:?}"
        );
    }

    #[test]
    fn an_assurance_claiming_an_empty_core_fails_its_own_row() {
        let ctx = N4Ctx {
            assurances_seen: vec![AssuranceSeen {
                from: 5,
                anchor: [0x22; 32],
                cores: vec![0, 1],
                fault: None,
                lead_ms: 2000,
                reported_cores: vec![0],
            }],
            ..Default::default()
        };
        let out = results(n4_ce141_send(&ctx));
        assert!(
            out.iter()
                .any(|(n, o)| n == "n4_ce141_bits_have_reports" && matches!(o, Outcome::Fail(_))),
            "{out:?}"
        );
        assert!(
            out.iter()
                .any(|(n, o)| n == "n4_ce141_well_formed" && *o == Outcome::Pass),
            "the signature was sound; only the claim was not: {out:?}"
        );
    }

    /// Lateness is soft: the spec says "roughly" two seconds, and a node
    /// cannot be hard-failed on a word like that.
    #[test]
    fn a_late_assurance_is_soft() {
        let ctx = N4Ctx {
            assurances_seen: vec![AssuranceSeen {
                from: 5,
                anchor: [0x22; 32],
                cores: vec![0],
                fault: None,
                lead_ms: -500,
                reported_cores: vec![0],
            }],
            ..Default::default()
        };
        let out = results(n4_ce141_send(&ctx));
        assert!(
            out.iter().any(|(n, o)| n == "n4_ce141_sent_before_the_slot"
                && *o == Outcome::Fail(Severity::Soft)),
            "{out:?}"
        );
    }

    #[test]
    fn a_spoiled_assurance_must_be_left_out() {
        let ctx = N4Ctx {
            assurances_offered: vec![
                AssuranceOffered {
                    validator: 1,
                    anchor: [0x33; 32],
                    cores: vec![0],
                    sent_in_slot: 10,
                    included: true,
                    had_opportunity: true,
                    fault: None,
                },
                AssuranceOffered {
                    validator: 2,
                    anchor: [0x33; 32],
                    cores: vec![0],
                    sent_in_slot: 10,
                    included: true,
                    had_opportunity: true,
                    fault: Some(AssuranceFaultKind::BadSignature),
                },
            ],
            availability_threshold: 5,
            ..Default::default()
        };
        let out = results(n4_ce141_inclusion(&ctx));
        assert!(out
            .iter()
            .any(|(n, o)| n == "n4_ce141_valid_assurance_included" && *o == Outcome::Pass));
        assert!(
            out.iter()
                .any(|(n, o)| n == "n4_ce141_invalid_assurance_excluded"
                    && matches!(o, Outcome::Fail(_))),
            "a badly signed assurance that was included fails: {out:?}"
        );
    }

    /// A node that authored nothing after the offer was never asked the
    /// question, and must not be passed for it either.
    #[test]
    fn no_block_after_the_offer_leaves_the_row_unexercised() {
        let ctx = N4Ctx {
            assurances_offered: vec![AssuranceOffered {
                validator: 1,
                anchor: [0x33; 32],
                cores: vec![0],
                sent_in_slot: 10,
                included: false,
                had_opportunity: false,
                fault: None,
            }],
            ..Default::default()
        };
        let out = results(n4_ce141_inclusion(&ctx));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "n4_ce141_inclusion_not_exercised");
        assert!(matches!(out[0].1, Outcome::Fail(Severity::Soft)));
    }

    #[test]
    fn a_core_short_of_the_threshold_is_reported() {
        let ctx = N4Ctx {
            assurances_offered: vec![AssuranceOffered {
                validator: 1,
                anchor: [0x33; 32],
                cores: vec![0],
                sent_in_slot: 10,
                included: true,
                had_opportunity: true,
                fault: None,
            }],
            availability_threshold: 5,
            assured_by_core: vec![(0, vec![1, 2, 3])],
            ..Default::default()
        };
        let out = results(n4_ce141_inclusion(&ctx));
        assert!(
            out.iter()
                .any(|(n, o)| n == "n4_availability_threshold_reached"
                    && *o == Outcome::Fail(Severity::Soft)),
            "three of five is short: {out:?}"
        );
    }

    #[test]
    fn ce140_without_justifications_fails_rather_than_passing_vacuously() {
        let ctx = N4Ctx {
            segment_shards_served: vec![SegmentShardsServed {
                protocol: 140,
                erasure_root: [0x44; 32],
                shard_index: 1,
                requested: vec![0, 1],
                shards: vec![vec![1], vec![2]],
                justifications: Vec::new(),
                justifications_verified: Vec::new(),
                justification_details: Vec::new(),
                ragged: false,
                refused: false,
            }],
            ..Default::default()
        };
        let out = results(n4_ce139_140_serve(&ctx));
        assert!(
            out.iter().any(
                |(n, o)| n == "n4_ce140_justifications_verify" && matches!(o, Outcome::Fail(_))
            ),
            "an empty list of justifications is not every justification verifying: {out:?}"
        );
    }

    /// CE 139 carries no justifications, so it must not be graded for them.
    #[test]
    fn ce139_is_not_graded_for_justifications() {
        let ctx = N4Ctx {
            segment_shards_served: vec![SegmentShardsServed {
                protocol: 139,
                erasure_root: [0x44; 32],
                shard_index: 1,
                requested: vec![0],
                shards: vec![vec![1]],
                justifications: Vec::new(),
                justifications_verified: Vec::new(),
                justification_details: Vec::new(),
                ragged: false,
                refused: false,
            }],
            ..Default::default()
        };
        let out = names(n4_ce139_140_serve(&ctx));
        assert!(
            !out.iter().any(|n| n.contains("justifications_verify")),
            "{out:?}"
        );
        assert!(out
            .iter()
            .any(|n| n == "n4_ce139_140_one_shard_per_request"));
    }

    /// A data message that is not a whole number of slices means the two
    /// sides disagree about the slice width, which no count of shards would
    /// show -- so it is its own row, and it stops the rest.
    #[test]
    fn a_ragged_reply_is_its_own_row() {
        let ctx = N4Ctx {
            segment_shards_served: vec![SegmentShardsServed {
                protocol: 140,
                erasure_root: [0x44; 32],
                shard_index: 1,
                requested: vec![0, 1],
                shards: Vec::new(),
                justifications: Vec::new(),
                justifications_verified: Vec::new(),
                justification_details: Vec::new(),
                ragged: true,
                refused: false,
            }],
            ..Default::default()
        };
        let out = results(n4_ce139_140_serve(&ctx));
        assert!(
            out.iter()
                .any(|(n, o)| n == "n4_ce139_140_slices_are_whole"
                    && matches!(o, Outcome::Fail(_))),
            "{out:?}"
        );
        assert!(
            !out.iter()
                .any(|(n, _)| n == "n4_ce139_140_one_shard_per_request"),
            "counting slices nobody could split is not a second finding: {out:?}"
        );
    }

    #[test]
    fn a_short_reply_fails_the_count_row() {
        let ctx = N4Ctx {
            segment_shards_served: vec![SegmentShardsServed {
                protocol: 139,
                erasure_root: [0x44; 32],
                shard_index: 1,
                requested: vec![0, 1, 2],
                shards: vec![vec![1]],
                justifications: Vec::new(),
                justifications_verified: Vec::new(),
                justification_details: Vec::new(),
                ragged: false,
                refused: false,
            }],
            ..Default::default()
        };
        let out = results(n4_ce139_140_serve(&ctx));
        assert!(
            out.iter()
                .any(|(n, o)| n == "n4_ce139_140_one_shard_per_request"
                    && matches!(o, Outcome::Fail(_))),
            "{out:?}"
        );
    }
}
