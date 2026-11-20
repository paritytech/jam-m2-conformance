//! N6 — preimages, CE 142/143 (DESIGN.md §11).
//!
//! The harness plays a *non-validator* here, which it does nowhere else.
//! `simple.md:702-703` writes CE 142 as the way non-validator nodes
//! introduce preimages, and polkajam reads it the same way: an announcement
//! from a validator the NUT does not neighbour is refused on the peer class
//! alone, before the preimage is looked at.
//!
//! The lane's precondition is on chain, not on the wire. A node follows up
//! an announcement "provided the preimage has been requested on chain by
//! the given service" (`:705-707`), so the run has to get a `Solicit`
//! accumulated before it announces anything. Until that lands the correct
//! node behaviour is silence, and a row that read silence as a defect would
//! fail a conforming node for the harness's own timing.

use crate::dsl::{check, log, Check, Control, ObsLog, Severity};

/// A preimage the harness announced over CE 142.
#[derive(Debug, Clone)]
pub struct AnnouncedPreimage {
    /// Whether this one was solicited on chain before being announced.
    pub solicited: Solicited,
    /// The peer index the announcement was recorded under.
    ///
    /// An ordinary peer, outside the validator range: the announcement is
    /// made on a connection whose certificate key is not in the validator
    /// set, which is what makes the node read it as a non-validator's.
    pub peer: u16,
    /// The service that solicited it on chain.
    pub service_id: u32,
    /// Hash of the announced blob.
    pub hash: [u8; 32],
    /// Its length, which is part of the on-chain request and not just a
    /// convenience: a request is keyed on `(service, hash, len)`.
    pub length: u32,
    pub at_wall_ms: u64,
}

/// A CE 143 request the NUT opened back on the announcing connection.
#[derive(Debug, Clone)]
pub struct PreimageRequested {
    pub peer: u16,
    /// The hash the node asked for.
    pub asked: [u8; 32],
    /// Whether that is the hash the harness announced.
    pub matched_announcement: bool,
    /// How long after the announcement the request arrived.
    ///
    /// Kept because the spec puts a bound on the *announcer*, not the
    /// requester: `:707-710` asks a non-validator to hold the connection
    /// about ten seconds. A request that arrived inside the hold says the
    /// node used the window; the row reports the number rather than
    /// grading it, because the spec sets no deadline for asking.
    pub after_announcement_ms: u64,
    /// Whether the harness served it.
    pub answered: bool,
    /// Whether what the harness served actually hashes to what was asked
    /// for.
    ///
    /// `false` where the run deliberately served a blob that does not
    /// match, which is the only way to show that the node checks. A node
    /// that includes it has taken a preimage on the sender's word.
    pub served_matches_hash: bool,
}

/// What the harness arranged about a preimage before announcing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Solicited {
    /// A service asked for it on chain, so the node owes a follow-up.
    OnChain,
    /// Nobody asked for it. The node must *not* follow up
    /// (`simple.md:705-707`), and this is the only way the lane can show
    /// that the node reads the condition rather than asking for whatever
    /// it is told about.
    Never,
}

/// Everything N6 grades.
#[derive(Debug, Clone, Default)]
pub struct N6Ctx {
    pub announced: Vec<AnnouncedPreimage>,
    pub requests: Vec<PreimageRequested>,
    /// Whether the run got the solicit accumulated before announcing.
    ///
    /// The lane's precondition, and the control for every row below. A run
    /// that announced a preimage no service had asked for is a run where
    /// the correct node behaviour is to do nothing, so a row that failed
    /// the node would be reporting the harness's own timing as a defect.
    pub solicited_on_chain: bool,
    /// Preimage hashes the NUT included in a block it authored.
    pub included: Vec<[u8; 32]>,
    /// Announcements the NUT made to the emulated validators, by peer.
    ///
    /// `simple.md:712-713`: once a validator has obtained a requested
    /// preimage it should announce possession to its grid neighbours.
    pub nut_announced_to: Vec<(u16, [u8; 32])>,
    /// The NUT's index, and the emulated validators that neighbour it.
    pub nut_index: u16,
    pub emulated_peers: Vec<u16>,
    /// Whether the run saw the NUT author at all after the announcement.
    ///
    /// Without a block there is nothing to have included a preimage in, and
    /// "not included" would be a fact about the lottery rather than the
    /// node.
    pub authored_after_announcement: bool,
}

/// Did the node ask for a preimage it was told about and had been asked for
/// on chain?
///
/// The one row that reads the protocol's purpose. Hard: `:705-707` says the
/// recipient "is expected to follow up by requesting the preimage", and the
/// two conditions it attaches are both arranged by the run -- the preimage
/// is solicited on chain, and the node cannot already hold it because the
/// run invented it.
pub fn requests_announced(ctx: &N6Ctx) -> Check {
    let ctx = ctx.clone();
    check("n6_ce142_announce", Severity::Hard, move |_obs: &ObsLog| {
        let control = Control::new(
            "n6_preimage_not_solicited",
            "a preimage solicited on chain and then announced",
            ctx.solicited_on_chain && !ctx.announced.is_empty(),
        );
        if !control.present() {
            return vec![control.absent("n6_preimage_not_solicited")];
        }

        let mut results = Vec::new();
        for announced in &ctx.announced {
            let asked = ctx
                .requests
                .iter()
                .any(|r| r.asked == announced.hash && r.peer == announced.peer);
            match announced.solicited {
                Solicited::OnChain => results.push(log::check_detail(
                    "n6_ce143_requested_after_announcement",
                    asked,
                    Severity::Hard,
                    || {
                        format!(
                            "the NUT did not ask for the preimage {} that service {} had \
                             solicited on chain, within the {} ms the announcer held the \
                             connection open",
                            short(&announced.hash),
                            announced.service_id,
                            HOLD_MS,
                        )
                    },
                )),
                // The other half of the same sentence. `:705-707` makes the
                // follow-up conditional, and a lane that only ever announced
                // solicited preimages would pass a node that asked for
                // everything it was told about.
                //
                // Attributable because the solicited announcement in the
                // same run is the control: a node that asked for that one
                // and not for this one is reading the condition. Without
                // that control this row is not reported at all.
                Solicited::Never => {
                    if ctx.announced.iter().any(|a| {
                        a.solicited == Solicited::OnChain
                            && ctx.requests.iter().any(|r| r.asked == a.hash)
                    }) {
                        results.push(log::check_detail(
                            "n6_unsolicited_not_requested",
                            !asked,
                            Severity::Hard,
                            || {
                                format!(
                                    "the NUT asked for {}, which no service had solicited \
                                     on chain",
                                    short(&announced.hash)
                                )
                            },
                        ));
                    } else {
                        results.push(log::check_detail(
                            "n6_unsolicited_not_exercised",
                            false,
                            Severity::Soft,
                            || {
                                "an unsolicited preimage was announced, but the solicited \
                                 one beside it drew no request either, so the node's \
                                 silence says nothing about the condition"
                                    .to_string()
                            },
                        ));
                    }
                }
            }
        }

        // Every request the node made, graded against what it was told
        // about. Separate from the row above because they are different
        // failures: one is a node that never asked, the other is a node
        // that asked for something nobody announced to it.
        //
        // Graded over *all* requests rather than over the matching one.
        // The first draft of this row read the matching request and
        // asserted it matched, which is true by construction -- a row that
        // cannot fail, of exactly the kind §5's shard-count row turned out
        // to be. The sim test is what found it: the fault that asks for
        // another hash made the row vanish rather than fail.
        for request in &ctx.requests {
            results.push(log::check_detail(
                "n6_ce143_asked_for_what_was_announced",
                ctx.announced.iter().any(|a| a.hash == request.asked),
                Severity::Hard,
                || {
                    format!(
                        "the NUT asked for {}, which this run never announced to it",
                        short(&request.asked)
                    )
                },
            ));
        }
        results
    })
}

/// Did the preimage reach a block?
///
/// Separate from the request because they are different duties and a node
/// can do one without the other. Soft, and deliberately: `simple.md` says
/// nothing about when an obtained preimage must be included, and the GP's
/// rule is about what a block *may* carry rather than what the next block
/// must. A node that asked, got the blob and has not yet authored is not in
/// breach of anything the harness can cite.
pub fn includes_obtained(ctx: &N6Ctx) -> Check {
    let ctx = ctx.clone();
    check("n6_inclusion", Severity::Soft, move |_obs: &ObsLog| {
        let served: Vec<&PreimageRequested> = ctx.requests.iter().filter(|r| r.answered).collect();
        let control = Control::new(
            "n6_inclusion_not_exercised",
            "a preimage the NUT asked for and the harness served",
            !served.is_empty() && ctx.authored_after_announcement,
        );
        if !control.present() {
            return vec![control.absent("n6_inclusion_not_exercised")];
        }
        served
            .iter()
            .map(|request| {
                if request.served_matches_hash {
                    log::check_detail(
                        "n6_preimage_included",
                        ctx.included.contains(&request.asked),
                        Severity::Soft,
                        || {
                            format!(
                                "the NUT asked for {} and was served it, and no block it \
                                 authored afterwards carries it",
                                short(&request.asked)
                            )
                        },
                    )
                } else {
                    // Hard where the inclusion row is Soft, and they are not
                    // the same question. Whether an obtained preimage
                    // reaches the next block is a matter of timing the spec
                    // does not fix; whether a blob that does not hash to
                    // what was asked for may be included at all is not. The
                    // GP's preimage extrinsic is keyed on the hash, so a
                    // node that included this would be putting a lookup
                    // under a key its own blob does not produce.
                    log::check_detail(
                        "n6_mismatched_preimage_not_included",
                        !ctx.included.contains(&request.asked),
                        Severity::Hard,
                        || {
                            format!(
                                "the NUT included a blob under {}, which it does not hash \
                                 to",
                                short(&request.asked)
                            )
                        },
                    )
                }
            })
            .collect()
    })
}

/// Did the node pass on a preimage it obtained, to the neighbours that
/// should hear about it?
///
/// `simple.md:712-713` is a **should** about where the announcement goes,
/// and the where is computable: two validators neighbour each other if they
/// share a row or a column of the grid (`:188-189`), which is a function of
/// the index alone. So the row names the peers it expects rather than
/// accepting any announcement as evidence -- a node that gossiped to one
/// arbitrary peer would otherwise pass.
///
/// Soft, because `:712` says *should*, and because a node that has obtained
/// the preimage but not yet gossiped it is early rather than wrong.
pub fn gossips_to_neighbours(ctx: &N6Ctx) -> Check {
    let ctx = ctx.clone();
    check("n6_gossip", Severity::Soft, move |_obs: &ObsLog| {
        let obtained: Vec<[u8; 32]> = ctx
            .requests
            .iter()
            .filter(|r| r.answered && r.served_matches_hash)
            .map(|r| r.asked)
            .collect();
        // Only neighbours the run actually emulates can hear anything, so
        // the expectation is the intersection and not the whole row and
        // column.
        let expected: Vec<u16> = grid_neighbours(ctx.nut_index, jam_types::max_val_count())
            .into_iter()
            .filter(|n| ctx.emulated_peers.contains(n))
            .collect();
        let control = Control::new(
            "n6_gossip_not_exercised",
            "a preimage the NUT obtained, and an emulated grid neighbour to hear about it",
            !obtained.is_empty() && !expected.is_empty(),
        );
        if !control.present() {
            return vec![control.absent("n6_gossip_not_exercised")];
        }
        obtained
            .iter()
            .map(|hash| {
                let heard: Vec<u16> = expected
                    .iter()
                    .copied()
                    .filter(|peer| ctx.nut_announced_to.contains(&(*peer, *hash)))
                    .collect();
                log::check_detail(
                    "n6_gossip_reaches_neighbours",
                    heard.len() == expected.len(),
                    Severity::Soft,
                    || {
                        format!(
                            "the NUT obtained {} and announced it to {:?} of its emulated \
                             grid neighbours {:?}",
                            short(hash),
                            heard,
                            expected
                        )
                    },
                )
            })
            .collect()
    })
}

/// Every N6 check.
pub fn all(ctx: &N6Ctx) -> Vec<Check> {
    vec![
        requests_announced(ctx),
        includes_obtained(ctx),
        gossips_to_neighbours(ctx),
    ]
}

/// CE 142 announcements the NUT made, by the peer that heard each one.
///
/// Shared between the emulator that records them and the runner that reads
/// them, so it is named once rather than spelled out at each end.
pub type HeardAnnouncements = std::sync::Arc<std::sync::Mutex<Vec<(u16, [u8; 32])>>>;

/// The peer index the ordinary, non-validator announcer is recorded under.
///
/// Outside the validator range and distinct from the builder's: the two are
/// different claims about what the peer is, and a lane that read one as the
/// other would grade an announcement against a builder slot.
pub const ORDINARY_PEER: u16 = 0x6E;

/// The announcer's hold, in milliseconds, for the row that has to name it.
const HOLD_MS: u64 = 10_000;

fn short(hash: &[u8; 32]) -> String {
    hash.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

/// Validators that neighbour `index` in the grid, out of `count` validators.
///
/// `simple.md:188-189`: two validators in the same epoch neighbour each
/// other if they share a row (`index / W`) or a column (`index % W`), where
/// `W = floor(sqrt(V))`. The cross-epoch rule at `:190` -- same index in
/// different epochs -- is not modelled: this harness grades one epoch's
/// set at a time, and a row that mixed the two would be asserting something
/// no single run can see.
///
/// Computed rather than assumed. An earlier note in `DESIGN.md` claimed the
/// emulated validators "are not the NUT's neighbours in every run", which
/// is not so: the grid is a function of the index alone, so who neighbours
/// the NUT is the same in every run with the same validator count.
pub fn grid_neighbours(index: u16, count: u16) -> Vec<u16> {
    // A validator outside the set has no neighbours. Without this an index
    // past the end still shares a column with somebody and the relation
    // stops being mutual, which is what the test below caught.
    if index >= count {
        return Vec::new();
    }
    let width = (f64::from(count).sqrt().floor() as u16).max(1);
    (0..count)
        .filter(|&other| other != index)
        .filter(|&other| other / width == index / width || other % width == index % width)
        .collect()
}

#[cfg(test)]
mod grid_tests {
    use super::grid_neighbours;

    /// The tiny grid `DESIGN.md` §2 names, checked against the rule rather
    /// than copied from it: V=6, W=2, rows {0,1} {2,3} {4,5} and columns
    /// {0,2,4} {1,3,5}.
    #[test]
    fn the_tiny_grid_matches_the_one_design_names() {
        assert_eq!(grid_neighbours(5, 6), vec![1, 3, 4]);
        assert_eq!(grid_neighbours(0, 6), vec![1, 2, 4]);
        assert_eq!(grid_neighbours(3, 6), vec![1, 2, 5]);
    }

    /// Nobody neighbours themselves, and every neighbourhood is mutual.
    #[test]
    fn neighbouring_is_mutual_and_never_reflexive() {
        for count in [1u16, 2, 6, 9, 16, 1023] {
            for index in [0u16, 1, count / 2, count - 1] {
                let mine = grid_neighbours(index, count);
                assert!(
                    !mine.contains(&index),
                    "a validator is not its own neighbour"
                );
                for other in mine {
                    assert!(
                        grid_neighbours(other, count).contains(&index),
                        "{index} neighbours {other} but not the other way round, with \
                         {count} validators"
                    );
                }
            }
        }
    }

    /// A one-validator set has no neighbours, and the helper does not divide
    /// by a zero width.
    #[test]
    fn a_lone_validator_has_no_neighbours() {
        assert!(grid_neighbours(0, 1).is_empty());
        assert!(grid_neighbours(0, 0).is_empty());
    }
}

#[cfg(test)]
mod row_tests {
    use super::*;
    use crate::dsl::{ObsLog, Outcome};

    const HASH: [u8; 32] = [0x11; 32];

    fn request(answered: bool, matches: bool) -> PreimageRequested {
        PreimageRequested {
            peer: ORDINARY_PEER,
            asked: HASH,
            matched_announcement: true,
            after_announcement_ms: 400,
            answered,
            served_matches_hash: matches,
        }
    }

    fn ctx(requests: Vec<PreimageRequested>, included: Vec<[u8; 32]>) -> N6Ctx {
        N6Ctx {
            announced: vec![AnnouncedPreimage {
                solicited: Solicited::OnChain,
                peer: ORDINARY_PEER,
                service_id: 0,
                hash: HASH,
                length: 26,
                at_wall_ms: 1_000,
            }],
            requests,
            solicited_on_chain: true,
            included,
            nut_announced_to: Vec::new(),
            nut_index: 5,
            emulated_peers: vec![1, 3, 4],
            authored_after_announcement: true,
        }
    }

    fn run(check: Check) -> Vec<crate::dsl::CheckResult> {
        (check.run)(&ObsLog::new())
    }

    /// Both directions of the mismatch row, from explicit contexts.
    ///
    /// Driven here rather than through the simulated node, which authors
    /// nothing: a stand-in that cannot put a preimage in a block cannot
    /// honestly be said to have failed an inclusion row, and a test that
    /// fabricated the inclusion *and* graded it would be supplying both
    /// sides of the question (`findings.md` §5).
    #[test]
    fn a_blob_that_fails_its_own_hash_must_not_be_included() {
        let refused = run(includes_obtained(&ctx(
            vec![request(true, false)],
            Vec::new(),
        )));
        assert!(
            refused
                .iter()
                .any(|r| r.name == "n6_mismatched_preimage_not_included"
                    && r.outcome == Outcome::Pass),
            "a node that left it out passes: {:?}",
            refused.iter().map(|r| r.name).collect::<Vec<_>>()
        );

        let took_it = run(includes_obtained(&ctx(
            vec![request(true, false)],
            vec![HASH],
        )));
        assert!(
            took_it
                .iter()
                .any(|r| r.name == "n6_mismatched_preimage_not_included"
                    && matches!(r.outcome, Outcome::Fail(Severity::Hard))),
            "a node that included it fails, hard: {:?}",
            took_it
                .iter()
                .map(|r| (r.name, r.outcome))
                .collect::<Vec<_>>()
        );
    }

    /// The gossip row names the neighbours it expects, and an announcement
    /// to someone else is not evidence.
    #[test]
    fn gossip_to_the_wrong_peer_is_not_gossip() {
        let mut reached = ctx(vec![request(true, true)], vec![HASH]);
        reached.nut_announced_to = vec![(1, HASH), (3, HASH), (4, HASH)];
        assert!(
            run(gossips_to_neighbours(&reached))
                .iter()
                .all(|r| r.outcome == Outcome::Pass),
            "announcing to every emulated neighbour passes"
        );

        let mut partial = ctx(vec![request(true, true)], vec![HASH]);
        partial.nut_announced_to = vec![(1, HASH)];
        assert!(
            run(gossips_to_neighbours(&partial))
                .iter()
                .any(|r| matches!(r.outcome, Outcome::Fail(_))),
            "announcing to one of three neighbours does not"
        );

        // Peer 2 is not a neighbour of validator 5 in the tiny grid, so an
        // announcement to it is not evidence of gossip at all.
        let mut stranger = ctx(vec![request(true, true)], vec![HASH]);
        stranger.nut_announced_to = vec![(2, HASH)];
        assert!(
            run(gossips_to_neighbours(&stranger))
                .iter()
                .any(|r| matches!(r.outcome, Outcome::Fail(_))),
            "an announcement to a non-neighbour is not gossip"
        );
    }

    /// Without a preimage obtained there is nothing to have gossiped.
    #[test]
    fn gossip_reports_itself_unexercised_with_nothing_obtained() {
        let rows = run(gossips_to_neighbours(&ctx(Vec::new(), Vec::new())));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "n6_gossip_not_exercised");
        assert!(rows[0].outcome != Outcome::Pass);
    }
}
