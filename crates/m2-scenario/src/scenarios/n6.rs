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
                .find(|r| r.matched_announcement && r.peer == announced.peer);
            results.push(log::check_detail(
                "n6_ce143_requested_after_announcement",
                asked.is_some(),
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
            ));
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
            })
            .collect()
    })
}

/// Every N6 check.
pub fn all(ctx: &N6Ctx) -> Vec<Check> {
    vec![requests_announced(ctx), includes_obtained(ctx)]
}

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
