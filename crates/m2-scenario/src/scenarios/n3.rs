//! N3 — guaranteeing (DESIGN.md §11 N3).
//!
//! The lane's facts are what the node did with a work package the harness
//! submitted as a builder: whether it accepted the CE 133 submission, whether
//! it opened CE 134 to both of its co-guarantors, and what it put on CE 135.
//!
//! The records here are filled by `m2_emu::report_io`; the checks read them.
//! Nothing in this module refines or signs anything — every reference value
//! is computed in `m2-reference` and injected.

use std::collections::HashSet;

use jam_types::WorkPackageHash;

use crate::dsl::{check, log, Check, Control, Severity};

/// A CE 134 sharing request the NUT opened to an emulated co-guarantor
/// (`simple.md:406-458`).
///
/// Message 1 and message 2 are separate wire values on one stream, and a node
/// can send the first and never the second, so the bundle is optional rather
/// than part of the same record. A request with `bundle: None` is a node that
/// announced a share and did not follow through.
#[derive(Debug, Clone)]
pub struct SharingSeen {
    /// The emulated validator the NUT opened the stream to.
    pub peer: u16,
    /// Core the package is being guaranteed on (`simple.md:453`).
    pub core_index: u16,
    /// Erasure-coded shard count the NUT proposes.
    pub shard_count: u16,
    /// Work-package hash to segments-root mappings (`simple.md:449`).
    pub mappings: Vec<(WorkPackageHash, [u8; 32])>,
    /// Message 2, the work-package bundle, if it arrived.
    pub bundle: Option<Vec<u8>>,
    /// Wall-clock time message 1 arrived, for the "within ~3 s" window.
    ///
    /// Wall clock rather than run-relative: the lane compares this against the
    /// submission's own wall-clock stamp, and the two have to share an origin.
    pub at_wall_ms: u64,
}

/// A deliberate defect in a CE 133 submission, as the lane sees it
/// (DESIGN §11 N3).
///
/// The lane's own copy of `m2_reference::reports::SubmissionFault`, mapped
/// in the runner. The same split the ticket faults use: a scenario lane
/// describes what was posed, the reference knows how to pose it, and neither
/// crate has to depend on the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmissionFault {
    /// Message 1 over `2 + 200 * 1024` bytes (`simple.md:362-364`).
    Oversized,
    /// Addressed to a core the NUT does not hold at the slot.
    NotAGuarantor,
    /// Built against an authorizer no core will accept.
    Unauthorized,
    /// Message 2 is not the sum of the declared extrinsic lengths.
    ExtrinsicSizeMismatch,
}

impl SubmissionFault {
    /// Whether DESIGN §11 N3 expects the node to reset the stream.
    ///
    /// Two of the four ask for a reset; the other two ask for silence. A
    /// package for a core the node does not hold is ignored, and an
    /// unauthorized one is taken onto the stream and then not shared. So
    /// "was it refused" is the wrong question for half of these.
    pub fn expects_reset(&self) -> bool {
        matches!(self, Self::Oversized | Self::ExtrinsicSizeMismatch)
    }

    pub fn describe(&self) -> &'static str {
        match self {
            Self::Oversized => "a first message over the CE 133 size cap",
            Self::NotAGuarantor => "a core the NUT does not hold",
            Self::Unauthorized => "an authorizer no core accepts",
            Self::ExtrinsicSizeMismatch => "an extrinsic message of the wrong size",
        }
    }
}

/// A CE 135 work-report distribution the NUT sent (`simple.md:460-485`).
#[derive(Debug, Clone)]
pub struct ReportSeen {
    /// The emulated validator the NUT distributed to.
    pub peer: u16,
    /// Blake2b of the encoded report, as the lane compares reports by hash.
    pub report_hash: [u8; 32],
    /// Slot the report could be included in.
    pub slot: u32,
    /// Validator index / signature pairs, in the order sent. Not sorted here:
    /// whether they *arrive* sorted is one of the lane's assertions.
    pub signatures: Vec<(u16, [u8; 64])>,
    /// The encoded report, kept so the lane can compare it byte for byte with
    /// the reference's rather than trusting the hash alone.
    pub encoded_report: Vec<u8>,
    pub at_wall_ms: u64,
}

/// A CE 133 or CE 146 submission the harness made, and what the node did
/// with it.
///
/// The counterpart of N2's `DeliveredTicket`: the refusal goes on the record
/// of the submission it answers, not into the observation log alone. A stream
/// reset carries no reason, so the log can only say that one happened; which
/// package was refused is a fact only the sender holds.
#[derive(Debug, Clone)]
pub struct SubmittedPackage {
    /// Peer index the submission was recorded under.
    ///
    /// A builder, not a validator: CE 133 is builder-to-guarantor, and the
    /// node hands out submission slots by peer role. The index sits outside
    /// the validator range so no lane reads the builder's traffic as a
    /// validator's.
    pub peer: u16,
    /// Which protocol carried it: 133 or 146.
    ///
    /// The rules are the same -- DESIGN §11 N3 grades CE 146 "as 133" -- so
    /// the two share their grading and differ only in the row names and the
    /// size cap. Reporting them under one name would let a run that
    /// exercised one claim both.
    pub protocol: u16,
    /// Core the submission was addressed to.
    pub core: u16,
    /// Slot it was submitted in.
    pub slot: u32,
    /// GP hash of the package, as the engine computes it. CE 134's mappings
    /// are keyed by this, so it is how the lane tells whether what the node
    /// shared is what it was given.
    pub package_hash: [u8; 32],
    pub sent_at_wall_ms: u64,
    /// The NUT reset the stream rather than FIN'ing it (`simple.md:374-375`).
    pub refused: bool,
    /// The application error code the reset carried, when it did.
    ///
    /// A reset is the protocol's way of saying no, and the reason lives in
    /// the code. Without it every refusal reads alike, and the difference
    /// between a package the node calls invalid and one it simply will not
    /// take right now is the difference between the node's defect and the
    /// harness aiming badly.
    pub reset_code: Option<u64>,
    /// What was deliberately wrong with this submission, if anything.
    ///
    /// `None` is the honest one. The lane asks a different question of each
    /// fault, because DESIGN §11 N3 expects a reset for two of them and
    /// silence for the other two.
    pub fault: Option<SubmissionFault>,
    /// The validators holding `core` at `slot` alongside the NUT: who the
    /// node is expected to open CE 134 to.
    ///
    /// On the submission rather than on the lane context, because the
    /// assignment is a property of this core at this slot. A run that
    /// submitted twice across a rotation boundary has two different answers,
    /// and a single per-run list would grade the second against the first.
    pub co_guarantors: Vec<u16>,
    /// The earlier package this one imports a segment from, if any, and the
    /// exports-root that package's report declared.
    ///
    /// `None` for a package that imports nothing, which is every submission
    /// but one. CE 134's mappings map the *import* list to the roots it
    /// comes from (`simple.md:449`), so this is the pair the node is
    /// expected to send -- and without it the lane has nothing to compare a
    /// mapping against.
    pub imports_from: Option<ImportedFrom>,
}

/// The package a submission imports a segment from, and the root that
/// package's report put its exports under.
///
/// Two hashes that are easy to swap, so they are named rather than paired.
/// The lane compares both against what the node mapped: a node that sent
/// the right key under the wrong root has resolved the import wrongly, and
/// one that sent the wrong key has not resolved this import at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportedFrom {
    /// GP hash of the exporting package: the key the mapping is under.
    pub package_hash: [u8; 32],
    /// Its `exports_root`, as the engine computed it: the value.
    pub exports_root: [u8; 32],
}

/// A CE 134 share the harness opened to the NUT, and the answer it gave.
///
/// The one N3 record where the node does the refining and the harness grades
/// the result, rather than the other way round.
#[derive(Debug, Clone)]
pub struct SharedToNut {
    /// The emulated validator that opened the stream.
    pub peer: u16,
    pub core: u16,
    pub slot: u32,
    /// Shard count offered in message 1.
    pub shard_count: u16,
    /// What the reference refined from the same bundle.
    pub expected_report_hash: [u8; 32],
    /// The node's reply, if it gave one: `Work-Report Hash ++ Ed25519
    /// Signature` (`simple.md:456`).
    pub reply: Option<([u8; 32], [u8; 64])>,
    /// The node reset the stream rather than answering.
    pub refused: bool,
    /// The application error code the reset carried, when it did.
    pub reset_code: Option<u64>,
    /// What was deliberately wrong with the share, if anything.
    pub fault: Option<ShareFault>,
    pub sent_at_wall_ms: u64,
}

/// A deliberate defect in a CE 134 share, as the lane sees it.
///
/// The lane's copy of `m2_reference::reports::ShareFault`, mapped in the
/// emulator, for the reason the submission faults are split the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareFault {
    /// A shard count that is not the active validator count
    /// (`simple.md:432-436`).
    WrongShardCount,
}

/// A reference-guaranteed work-report the harness distributed to the NUT,
/// for grading whether it was then included on chain.
#[derive(Debug, Clone)]
pub struct DistributedReport {
    /// The emulated validator that distributed it.
    pub peer: u16,
    /// Core it is guaranteed on: one the NUT does not hold, so every
    /// signature on it is the reference's.
    pub core: u16,
    /// Hash of the report, which is what a block's guarantees are read by.
    pub report_hash: [u8; 32],
    /// Slot it went out in. A block before this one owed nothing.
    pub sent_in_slot: u32,
    pub sent_at_wall_ms: u64,
}

/// How long the node has to open CE 134 after a package reaches it.
///
/// DESIGN §11 N3 gives "~3 s". The tilde is why the row that reads this is
/// Soft: DESIGN §5 marks timing-tolerance clauses soft, and a node that
/// shares correctly but slowly is not the same defect as one that does not
/// share at all.
pub const SHARE_WINDOW_MS: u64 = 3_000;

/// The facts the N3 lane grades, injected by the runner.
#[derive(Debug, Clone)]
pub struct N3Ctx {
    /// The node under test's validator index.
    pub nut_index: u16,
    /// CE 133 submissions the harness made.
    pub submissions: Vec<SubmittedPackage>,
    /// CE 134 shares the NUT opened to emulated co-guarantors.
    pub shares: Vec<SharingSeen>,
    /// CE 135 distributions the NUT sent.
    pub reports: Vec<ReportSeen>,
    /// Whether the harness answers CE 134 with a work-report hash and
    /// signature.
    ///
    /// While false the harness is the reason the node cannot assemble a
    /// guarantee, so the rows that depend on one say so instead of failing
    /// the node for the harness's omission.
    pub answers_sharing: bool,
    /// Hash of the report the reference refined from the submitted package.
    ///
    /// What the node's own report is compared against. `None` when no package
    /// was submitted, in which case there is nothing to compare and the row
    /// is not reported.
    pub expected_report_hash: Option<[u8; 32]>,
    /// The emulated validators a distribution should reach.
    ///
    /// Only the emulated ones: the NUT does not distribute to itself, and a
    /// validator the harness is not playing cannot be observed either way.
    pub emulated_peers: Vec<u16>,
    /// CE 134 shares the harness opened to the NUT, with its answers.
    pub shared_to_nut: Vec<SharedToNut>,
    /// Reference-guaranteed reports the harness distributed to the NUT.
    pub distributed: Vec<DistributedReport>,
    /// Report hashes the NUT's own blocks carried in their guarantees, with
    /// the slot of the block that carried each.
    ///
    /// Read out of the blocks the node announced, so a report the node
    /// included is one it actually put on chain rather than one it merely
    /// acknowledged.
    pub included: Vec<([u8; 32], u32)>,
    /// Slots the NUT authored a block in.
    pub authored_slots: Vec<u32>,
}

/// Fewest signatures a guaranteed work-report may carry (`simple.md:464-467`):
/// the guarantor's own and at least one co-guarantor's.
pub const MIN_GUARANTEE_SIGNATURES: usize = 2;

/// N3 — CE 133: a submitted package is accepted and shared with both
/// co-guarantors (`simple.md:351-376`, DESIGN §11 N3).
///
/// Gated on a submission having happened. A run that never submitted anything
/// would otherwise pass every row here without the node having been asked a
/// single question.
pub fn n3_ce133_submission(ctx: &N3Ctx) -> Check {
    submission_check(ctx, 133)
}

/// N3 — CE 146: the same package over the whole-bundle protocol
/// (`simple.md:378-404`, DESIGN §11 N3).
///
/// Graded "as 133", which is what DESIGN asks and what the rules say: a
/// guarantor that takes a package over one and not the other is a guarantor
/// with a framing defect, not a policy. The rows are named apart so that a
/// run which exercised one cannot report both as answered, and the size cap
/// differs: CE 133 caps the core index and package together, CE 146 the
/// package alone.
///
/// **The import-proof fault is not posed.** DESIGN §11 N3 asks for a bundle
/// with a bad import proof as well, and this run's package imports no
/// segments, so it carries no proofs to spoil. Breaking one would mean first
/// exporting segments from an earlier package and importing them here, which
/// is work the lane does not do yet. Said here rather than left for a reader
/// to notice the fault missing from the report.
pub fn n3_ce146_submission(ctx: &N3Ctx) -> Check {
    submission_check(ctx, 146)
}

/// The CE 134 shares that answer `submitted`, and no others.
///
/// A run submits seven packages a slot apart, over both protocols, and the
/// node sees one stream of them: a share belongs to the submission it
/// followed, not to every submission before it. Filtering by
/// `at_wall_ms >= submitted.sent_at_wall_ms` alone is how
/// `n3_ce133_unauthorized_not_shared` and `n3_ce133_not_a_guarantor_ignored`
/// came to fail a node for shares that two honest submissions later in the
/// plan had caused -- rows that could not pass whatever the node did
/// (`findings.md` §18). The positive rows had the same hole pointing the
/// other way: a node that ignored a submission could pass
/// `shares_with_both_co_guarantors` on a later one's shares.
///
/// The key is the window to the next submission, not the package. Nothing a
/// share carries names the package: `SharingContext.mappings` is keyed by
/// the work-package hash but is empty for a package that imports no
/// segments, which is every package this harness builds, and the bundle in
/// message 2 would have to be decoded by the engine to be read as one. The
/// window is sound here because the lane also grades how long the node took
/// -- `shares_within_the_window` holds it to about three seconds while
/// submissions are a whole slot apart -- so a share late enough to land in
/// the wrong window has already failed a row of its own.
///
/// Across both protocols, because the next submission is the next one the
/// *node* saw. Bounding by the next CE 133 submission alone would let the
/// CE 146 submission between them keep attributing its shares backwards.
fn shares_answering<'a>(ctx: &'a N3Ctx, submitted: &SubmittedPackage) -> Vec<&'a SharingSeen> {
    let next = ctx
        .submissions
        .iter()
        .map(|s| s.sent_at_wall_ms)
        .filter(|&at| at > submitted.sent_at_wall_ms)
        .min();
    ctx.shares
        .iter()
        .filter(|share| {
            share.at_wall_ms >= submitted.sent_at_wall_ms
                && next.is_none_or(|next| share.at_wall_ms < next)
        })
        .collect()
}

/// The shared body of the two submission checks, over one protocol's
/// submissions.
///
/// One implementation because there is one rule. Two copies would be two
/// readings of it, and the first time they drifted the report would say the
/// node handled CE 133 correctly and CE 146 wrongly when nothing about the
/// node had changed.
fn submission_check(ctx: &N3Ctx, protocol: u16) -> Check {
    let ctx = ctx.clone();
    let name = leak(format!("n3_ce{protocol}_submission"));
    let absent = leak(format!("n3_ce{protocol}_not_exercised"));
    check(name, Severity::Hard, move |_obs| {
        let mine: Vec<&SubmittedPackage> = ctx
            .submissions
            .iter()
            .filter(|s| s.protocol == protocol)
            .collect();
        let control = Control::new(
            absent,
            leak(format!(
                "a work package submitted to the NUT over CE {protocol}"
            )),
            !mine.is_empty(),
        );
        if !control.present() {
            return vec![control.absent(absent)];
        }

        let mut results = Vec::new();
        for submitted in mine {
            // A faulty submission is graded by its own rule, not by the
            // honest one's. Two of the four ask for a reset and two ask for
            // silence, so "was it accepted" is the wrong question for half.
            if let Some(fault) = submitted.fault {
                results.extend(grade_fault(&ctx, submitted, fault));
                continue;
            }
            results.push(log::check_detail(
                leak(format!("n3_ce{protocol}_accepted")),
                !submitted.refused,
                Severity::Hard,
                || {
                    format!(
                        "the NUT reset the CE {protocol} stream for the package {} on \
                         core {} with code {}",
                        short(&submitted.package_hash),
                        submitted.core,
                        submitted
                            .reset_code
                            .map(|code| format!("{code:#x}"))
                            .unwrap_or_else(|| "none".into())
                    )
                },
            ));
            // A node that refused the package owes no sharing, and grading it
            // for not sharing would report one defect twice.
            if submitted.refused {
                continue;
            }

            // Shares that answer *this* submission, and not a later one's.
            let answering = shares_answering(&ctx, submitted);
            let reached: HashSet<u16> = answering.iter().map(|share| share.peer).collect();

            for co_guarantor in &submitted.co_guarantors {
                results.push(log::check_detail(
                    leak(format!("n3_ce{protocol}_shares_with_both_co_guarantors")),
                    reached.contains(co_guarantor),
                    Severity::Hard,
                    || {
                        format!(
                            "the NUT never opened CE 134 to validator {co_guarantor}, which \
                             holds core {} with it; it reached {:?}",
                            submitted.core, reached
                        )
                    },
                ));
            }

            // Timing last, and soft: a node that shared correctly but slowly
            // is not the node that did not share.
            if let Some(first) = answering.iter().map(|s| s.at_wall_ms).min() {
                let took = first.saturating_sub(submitted.sent_at_wall_ms);
                results.push(log::check_detail(
                    leak(format!("n3_ce{protocol}_shares_within_the_window")),
                    took <= SHARE_WINDOW_MS,
                    Severity::Soft,
                    || format!("the NUT took {took} ms to open CE 134, past {SHARE_WINDOW_MS} ms"),
                ));
            }
        }
        results
    })
}

/// N3 — CE 135: the guaranteed work-report the node distributes
/// (`simple.md:460-485`, DESIGN §11 N3).
///
/// Gated on a distribution having been seen. A node that never distributed
/// anything fails the CE 133 rows, which is where that finding belongs; it
/// must not also collect passes here for a message it never sent.
pub fn n3_ce135_distribution(ctx: &N3Ctx) -> Check {
    let ctx = ctx.clone();
    check("n3_ce135_distribution", Severity::Hard, move |_obs| {
        let control = Control::new(
            "n3_ce135_not_exercised",
            "a guaranteed work-report the NUT distributed",
            !ctx.reports.is_empty(),
        );
        if !control.present() {
            return vec![control.absent("n3_ce135_not_exercised")];
        }

        // Who may sign: the validators holding the core, which is the NUT
        // and the co-guarantors the harness was told to expect. Read off the
        // submission rather than recomputed, for the reason on `N3Ctx`.
        let mut may_sign: HashSet<u16> = ctx
            .submissions
            .iter()
            .flat_map(|s| s.co_guarantors.iter().copied())
            .collect();
        may_sign.insert(ctx.nut_index);

        let mut results = Vec::new();
        for report in &ctx.reports {
            let signers: Vec<u16> = report.signatures.iter().map(|(index, _)| *index).collect();

            results.push(log::check_detail(
                "n3_ce135_has_enough_signatures",
                signers.len() >= MIN_GUARANTEE_SIGNATURES
                    && signers.len() <= jam_types::VALS_PER_CORE,
                Severity::Hard,
                || {
                    format!(
                        "the report carries {} signatures; a guarantee needs between {} and {}",
                        signers.len(),
                        MIN_GUARANTEE_SIGNATURES,
                        jam_types::VALS_PER_CORE
                    )
                },
            ));

            // Strictly ascending, which is both the stated order and the
            // absence of a validator signing twice.
            results.push(log::check_detail(
                "n3_ce135_signatures_sorted",
                signers.windows(2).all(|pair| pair[0] < pair[1]),
                Severity::Hard,
                || format!("signer indices {signers:?} are not strictly ascending"),
            ));

            // Only where the harness knows who holds the core. With no
            // submission there is no assignment to judge against, and a row
            // that passes an empty set would be true whatever the node did.
            if !may_sign.is_empty() && !ctx.submissions.is_empty() {
                let strangers: Vec<u16> = signers
                    .iter()
                    .copied()
                    .filter(|index| !may_sign.contains(index))
                    .collect();
                results.push(log::check_detail(
                    "n3_ce135_signers_hold_the_core",
                    strangers.is_empty(),
                    Severity::Hard,
                    || format!("validators {strangers:?} signed for a core they do not hold"),
                ));
            }
        }

        // The node distributed the reference's report for the honest
        // package. Once per run, not once per report: a run poses faulty
        // submissions too, and a node that refines one of those distributes
        // a report the reference never built. Grading every report against
        // the honest hash fails a node for refining exactly what it was
        // handed, which an earlier version of this row did.
        if let Some(expected) = ctx.expected_report_hash {
            let seen: Vec<String> = ctx.reports.iter().map(|r| short(&r.report_hash)).collect();
            results.push(log::check_detail(
                "n3_ce135_report_matches_the_reference",
                ctx.reports.iter().any(|r| r.report_hash == expected),
                Severity::Hard,
                || {
                    format!(
                        "no report the NUT distributed was {}, which the reference refined \
                         from the package it was submitted; it sent {seen:?}",
                        short(&expected)
                    )
                },
            ));
        }

        // Distribution reaches every validator the harness is playing
        // (`simple.md:469-471`). One row, not one per report: a node that
        // sent two reports to one peer and none to another has one defect.
        let reached: HashSet<u16> = ctx.reports.iter().map(|r| r.peer).collect();
        for peer in &ctx.emulated_peers {
            results.push(log::check_detail(
                "n3_ce135_reaches_every_validator",
                reached.contains(peer),
                Severity::Hard,
                || {
                    format!(
                        "validator {peer} was never sent the guaranteed report; {reached:?} were"
                    )
                },
            ));
        }
        results
    })
}

/// N3 — CE 135 receive: a reference-guaranteed report the harness
/// distributed is included in the NUT's next block (DESIGN §11 N3).
///
/// Gated twice. On a report having been distributed, and on the node having
/// authored a block after it went out: a node that authored nothing has not
/// failed to include anything, it has failed to author, which is N1's
/// finding and not this lane's to report a second time.
pub fn n3_ce135_inclusion(ctx: &N3Ctx) -> Check {
    let ctx = ctx.clone();
    check("n3_ce135_inclusion", Severity::Hard, move |_obs| {
        let control = Control::new(
            "n3_ce135_inclusion_not_exercised",
            "a guaranteed work-report distributed to the NUT",
            !ctx.distributed.is_empty(),
        );
        if !control.present() {
            return vec![control.absent("n3_ce135_inclusion_not_exercised")];
        }

        let mut results = Vec::new();
        for report in &ctx.distributed {
            // Only blocks the node authored *after* the report went out could
            // have carried it. Without this a run whose only block predates
            // the distribution would fail the node for a report it had not
            // yet been given.
            if !ctx.authored_after(report.sent_in_slot) {
                results.push(
                    Control::new(
                        "n3_ce135_inclusion_not_exercised",
                        "a NUT block authored after the report was distributed",
                        false,
                    )
                    .absent("n3_ce135_inclusion_not_exercised"),
                );
                continue;
            }
            results.push(log::check_detail(
                "n3_ce135_report_included",
                ctx.included
                    .iter()
                    .any(|(hash, slot)| *hash == report.report_hash && *slot > report.sent_in_slot),
                Severity::Hard,
                || {
                    format!(
                        "the report {} guaranteed on core {} and distributed in slot {} was \
                         never included; the NUT's blocks carried {:?}",
                        short(&report.report_hash),
                        report.core,
                        report.sent_in_slot,
                        ctx.included
                            .iter()
                            .map(|(hash, _)| short(hash))
                            .collect::<Vec<_>>()
                    )
                },
            ));
        }
        results
    })
}

/// Grade one deliberately faulty submission (DESIGN §11 N3).
///
/// Each fault names one rule, so each gets one row and the rows are named
/// apart: a single `fault_rejected` row would pass for the wrong reason
/// whenever a node refused for a rule other than the one being posed.
fn grade_fault(
    ctx: &N3Ctx,
    submitted: &SubmittedPackage,
    fault: SubmissionFault,
) -> Vec<crate::dsl::CheckResult> {
    let protocol = submitted.protocol;
    // Shares that answer this submission, and not one the node made for a
    // package it was handed later. The two rows below say the node shared
    // something it should not have, so a share belonging to another
    // submission is not evidence -- it is `findings.md` §18.
    let shared_after: Vec<u16> = shares_answering(ctx, submitted)
        .into_iter()
        .map(|share| share.peer)
        .collect();

    match fault {
        // `simple.md:362-364` asks for the stream to be reset: a guarantor
        // must not be made to download a huge package before it can check
        // the authorization.
        SubmissionFault::Oversized => vec![log::check_detail(
            leak(format!("n3_ce{protocol}_oversized_reset")),
            submitted.refused,
            Severity::Hard,
            || {
                // Two caps, because the two protocols put the core index in
                // different messages: CE 133 carries it with the package and
                // caps the pair, CE 146 gives the package a message of its
                // own.
                let cap = if protocol == 146 {
                    jamnp_s::codec::ce137_148::WORK_PACKAGE_MAX
                } else {
                    jamnp_s::codec::ce131_136::WORK_PACKAGE_INITIAL_MAX as usize
                };
                format!(
                    "the NUT accepted a CE {protocol} work-package message over the {cap} \
                     byte cap instead of resetting the stream"
                )
            },
        )],
        // The extrinsic message did not match the lengths the package
        // declares, which the node reads exactly and so must notice.
        SubmissionFault::ExtrinsicSizeMismatch => vec![log::check_detail(
            leak(format!("n3_ce{protocol}_extrinsic_mismatch_reset")),
            submitted.refused,
            Severity::Hard,
            || {
                "the NUT accepted an extrinsic message whose size did not equal the sum of \
                 the lengths its package declared"
                    .to_string()
            },
        )],
        // Not a reset but silence: the node is not a guarantor of that core,
        // so the package is none of its business and it must not share it.
        SubmissionFault::NotAGuarantor => vec![log::check_detail(
            leak(format!("n3_ce{protocol}_not_a_guarantor_ignored")),
            shared_after.is_empty(),
            Severity::Hard,
            || {
                format!(
                    "the NUT shared a package addressed to core {}, which it does not hold \
                     at slot {}; it reached {:?}",
                    submitted.core, submitted.slot, shared_after
                )
            },
        )],
        // Authorization is the one check `simple.md:410-415` puts before
        // sharing, so an unauthorized package must not be shared on.
        SubmissionFault::Unauthorized => vec![log::check_detail(
            leak(format!("n3_ce{protocol}_unauthorized_not_shared")),
            shared_after.is_empty(),
            Severity::Hard,
            || {
                format!(
                    "the NUT shared a package built against an authorizer no core accepts; \
                     it reached {shared_after:?}"
                )
            },
        )],
    }
}

/// Row names are `&'static str` and CE 133 and CE 146 share their rules, so
/// the shared grader builds the name per protocol.
///
/// Leaked rather than threaded through as an owned string: a check's name
/// outlives the call that produced it, and there are at most a dozen.
fn leak(name: String) -> &'static str {
    Box::leak(name.into_boxed_str())
}

/// N3 — CE 134 receive: the NUT refines a bundle it is sent and answers with
/// the report's hash and a signature over it (`simple.md:439-456`).
///
/// The one row where the node does the refining and the harness grades the
/// result. Everything else in N3 grades what the node says about work the
/// reference did.
pub fn n3_ce134_receive(ctx: &N3Ctx) -> Check {
    let ctx = ctx.clone();
    check("n3_ce134_receive", Severity::Hard, move |_obs| {
        let control = Control::new(
            "n3_ce134_receive_not_exercised",
            "a work-package bundle shared with the NUT",
            !ctx.shared_to_nut.is_empty(),
        );
        if !control.present() {
            return vec![control.absent("n3_ce134_receive_not_exercised")];
        }

        let mut results = Vec::new();
        for share in &ctx.shared_to_nut {
            match share.fault {
                // `simple.md:432-436`: acceptable means matching the active
                // validator count. With a static set that is one number, so
                // anything else must be refused.
                Some(ShareFault::WrongShardCount) => results.push(log::check_detail(
                    "n3_ce134_wrong_shard_count_refused",
                    share.reply.is_none(),
                    Severity::Hard,
                    || {
                        format!(
                            "the NUT answered a share offering {} shards, which is not the \
                             active validator count",
                            share.shard_count
                        )
                    },
                )),
                None => {
                    results.push(log::check_detail(
                        "n3_ce134_answered",
                        share.reply.is_some(),
                        Severity::Hard,
                        || {
                            if share.refused {
                                format!(
                                    "the NUT reset a well-formed share on core {} with code {}",
                                    share.core,
                                    share
                                        .reset_code
                                        .map(|c| format!("{c:#x}"))
                                        .unwrap_or_else(|| "none".into())
                                )
                            } else {
                                format!(
                                    "the NUT neither answered nor refused a well-formed share \
                                     on core {}",
                                    share.core
                                )
                            }
                        },
                    ));
                    // The hash is the whole point: it says the node refined
                    // the bundle rather than echoing something. Only where
                    // it answered at all, or the row would report one defect
                    // twice.
                    if let Some((hash, _)) = share.reply {
                        results.push(log::check_detail(
                            "n3_ce134_hash_equals_the_reference",
                            hash == share.expected_report_hash,
                            Severity::Hard,
                            || {
                                format!(
                                    "the NUT refined {} from a bundle the reference refined \
                                     {} from",
                                    short(&hash),
                                    short(&share.expected_report_hash)
                                )
                            },
                        ));
                    }
                }
            }
        }
        results
    })
}

/// N3 — CE 134: the segments-root mappings on a share
/// (`simple.md:412-415`, `simple.md:449`).
///
/// A guarantor may share a package only once "all import segments have been
/// retrieved", and the spec adds that this "will involve mapping any WP
/// hashes in the import list to segments-roots". Message 1 carries that
/// mapping to the co-guarantors, who use it to fetch the same segments and
/// to check the bundle against them.
///
/// So the mappings are about the package being *imported from*, not the
/// package being shared. The package being shared has no exports-root until
/// somebody refines it, which is the work the share is asking for. This row
/// read it the other way round for as long as it existed and could not have
/// passed a conforming node; nothing noticed, because no package the harness
/// built imported anything, so the row never ran (`findings.md` §27).
///
/// A check of its own rather than a row inside the submission check,
/// because it is gated on something no other row needs: a submission that
/// imports. Its own control says so when a run has none, instead of the row
/// quietly not appearing.
pub fn n3_ce134_mappings(ctx: &N3Ctx) -> Check {
    let ctx = ctx.clone();
    check("n3_ce134_mappings", Severity::Hard, move |_obs| {
        let importing: Vec<&SubmittedPackage> = ctx
            .submissions
            .iter()
            .filter(|s| s.imports_from.is_some() && !s.refused)
            .collect();
        let control = Control::new(
            "n3_ce134_imports_not_exercised",
            "a package the NUT took that imports a segment from an earlier one",
            !importing.is_empty(),
        );
        if !control.present() {
            return vec![control.absent("n3_ce134_maps_the_imported_package")];
        }

        let mut results = Vec::new();
        for submitted in importing {
            let from = submitted
                .imports_from
                .expect("filtered to the submissions that import");
            let answering = shares_answering(&ctx, submitted);
            // A node that shared nothing at all is graded for that by
            // `shares_with_both_co_guarantors`. Reporting it here too would
            // count one defect twice -- but a run where the importing
            // package was never shared has still not put this row to the
            // node, and saying so is the difference between "no mappings"
            // and "no question asked".
            if answering.is_empty() {
                results.push(
                    Control::new(
                        "n3_ce134_imports_not_exercised",
                        "a CE 134 share of the package that imports",
                        false,
                    )
                    .absent("n3_ce134_maps_the_imported_package"),
                );
                continue;
            }
            for share in answering {
                let mapped = share.mappings.iter().any(|(package, root)| {
                    package.0 == from.package_hash && *root == from.exports_root
                });
                results.push(log::check_detail(
                    "n3_ce134_maps_the_imported_package",
                    mapped,
                    Severity::Hard,
                    || {
                        format!(
                            "the CE 134 to validator {} maps {:?}, which does not resolve \
                             the imported package {} to its exports-root {}",
                            share.peer,
                            share
                                .mappings
                                .iter()
                                .map(|(p, root)| format!("{} -> {}", short(&p.0), short(root)))
                                .collect::<Vec<_>>(),
                            short(&from.package_hash),
                            short(&from.exports_root)
                        )
                    },
                ));
            }
        }
        results
    })
}

/// Every N3 check, in the order the lane reports them.
pub fn all(ctx: &N3Ctx) -> Vec<Check> {
    vec![
        n3_ce133_submission(ctx),
        n3_ce146_submission(ctx),
        n3_ce134_mappings(ctx),
        n3_ce134_receive(ctx),
        n3_ce135_distribution(ctx),
        n3_ce135_inclusion(ctx),
    ]
}

impl N3Ctx {
    /// Whether the NUT authored any block after `slot`.
    ///
    /// Separate from the included hashes because a block with an empty
    /// guarantees extrinsic contributes no hashes at all, and that is exactly
    /// the block a failure to include looks like.
    pub fn authored_after(&self, slot: u32) -> bool {
        self.authored_slots.iter().any(|authored| *authored > slot)
    }
}

/// First eight bytes of a hash, for finding details.
fn short(hash: &[u8; 32]) -> String {
    hash[..8].iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsl::{CheckResult, ObsLog, Outcome};

    /// The NUT in these fixtures; validators 1 and 2 hold its core with it.
    const NUT: u16 = 5;
    const CO: [u16; 2] = [1, 2];
    const CORE: u16 = 0;
    const SENT_AT: u64 = 1_000_000;
    const PACKAGE: [u8; 32] = [0x5a; 32];

    fn run(check: &Check) -> Vec<CheckResult> {
        (check.run)(&ObsLog::new())
    }
    fn failed(results: &[CheckResult], name: &str, severity: Severity) -> bool {
        results
            .iter()
            .any(|r| r.name == name && r.outcome == Outcome::Fail(severity))
    }
    fn names(results: &[CheckResult]) -> Vec<&str> {
        results.iter().map(|r| r.name).collect()
    }

    fn submission(refused: bool) -> SubmittedPackage {
        SubmittedPackage {
            peer: 1,
            protocol: 133,
            core: CORE,
            slot: 100,
            package_hash: PACKAGE,
            sent_at_wall_ms: SENT_AT,
            refused,
            reset_code: refused.then_some(0x0103),
            fault: None,
            co_guarantors: CO.to_vec(),
            imports_from: None,
        }
    }

    fn share(
        peer: u16,
        at_wall_ms: u64,
        mappings: Vec<(WorkPackageHash, [u8; 32])>,
    ) -> SharingSeen {
        SharingSeen {
            peer,
            core_index: CORE,
            shard_count: 6,
            mappings,
            bundle: Some(vec![0xab; 8]),
            at_wall_ms,
        }
    }

    fn ctx(submissions: Vec<SubmittedPackage>, shares: Vec<SharingSeen>) -> N3Ctx {
        N3Ctx {
            nut_index: NUT,
            submissions,
            shares,
            reports: Vec::new(),
            answers_sharing: true,
            expected_report_hash: None,
            emulated_peers: CO.to_vec(),
            shared_to_nut: Vec::new(),
            distributed: Vec::new(),
            included: Vec::new(),
            authored_slots: Vec::new(),
        }
    }

    const REPORT: [u8; 32] = [0x77; 32];

    fn distribution(peer: u16, signers: Vec<u16>, report_hash: [u8; 32]) -> ReportSeen {
        ReportSeen {
            peer,
            report_hash,
            slot: 100,
            signatures: signers.into_iter().map(|i| (i, [0u8; 64])).collect(),
            encoded_report: vec![0xaa; 16],
            at_wall_ms: SENT_AT + 2_000,
        }
    }

    /// A context whose node distributed `reports`, against one submission.
    fn dist_ctx(reports: Vec<ReportSeen>) -> N3Ctx {
        N3Ctx {
            reports,
            expected_report_hash: Some(REPORT),
            ..ctx(vec![submission(false)], Vec::new())
        }
    }

    /// Two signatures from holders of the core, sorted, matching the
    /// reference, to both emulated validators.
    #[test]
    fn a_well_formed_distribution_passes() {
        let results = run(&n3_ce135_distribution(&dist_ctx(vec![
            distribution(CO[0], vec![CO[0], NUT], REPORT),
            distribution(CO[1], vec![CO[0], NUT], REPORT),
        ])));
        assert!(
            results.iter().all(|r| r.outcome == Outcome::Pass),
            "expected all passes, got {:?}",
            results
                .iter()
                .filter(|r| r.outcome != Outcome::Pass)
                .map(|r| r.name)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_run_with_no_distribution_proves_nothing() {
        let results = run(&n3_ce135_distribution(&dist_ctx(Vec::new())));
        assert_eq!(names(&results), vec!["n3_ce135_not_exercised"]);
        assert!(results.iter().all(|r| r.outcome != Outcome::Pass));
    }

    /// One signature is not a guarantee: it is the guarantor attesting alone.
    #[test]
    fn a_single_signature_fails() {
        let results = run(&n3_ce135_distribution(&dist_ctx(vec![
            distribution(CO[0], vec![NUT], REPORT),
            distribution(CO[1], vec![NUT], REPORT),
        ])));
        assert!(failed(
            &results,
            "n3_ce135_has_enough_signatures",
            Severity::Hard
        ));
    }

    /// Descending order, and the duplicate that the same test catches.
    #[test]
    fn unsorted_or_repeated_signers_fail() {
        let results = run(&n3_ce135_distribution(&dist_ctx(vec![distribution(
            CO[0],
            vec![NUT, CO[0]],
            REPORT,
        )])));
        assert!(failed(
            &results,
            "n3_ce135_signatures_sorted",
            Severity::Hard
        ));

        let repeated = run(&n3_ce135_distribution(&dist_ctx(vec![distribution(
            CO[0],
            vec![CO[0], CO[0]],
            REPORT,
        )])));
        assert!(
            failed(&repeated, "n3_ce135_signatures_sorted", Severity::Hard),
            "a validator signing twice is not ascending either"
        );
    }

    #[test]
    fn a_signer_that_does_not_hold_the_core_fails() {
        let stranger = 9u16;
        let results = run(&n3_ce135_distribution(&dist_ctx(vec![distribution(
            CO[0],
            vec![CO[0], stranger],
            REPORT,
        )])));
        assert!(failed(
            &results,
            "n3_ce135_signers_hold_the_core",
            Severity::Hard
        ));
    }

    /// The node refined something other than what the reference did.
    #[test]
    fn a_report_that_differs_from_the_reference_fails() {
        let results = run(&n3_ce135_distribution(&dist_ctx(vec![distribution(
            CO[0],
            vec![CO[0], NUT],
            [0x33; 32],
        )])));
        assert!(failed(
            &results,
            "n3_ce135_report_matches_the_reference",
            Severity::Hard
        ));
    }

    /// With no reference report there is nothing to compare, and the row is
    /// absent rather than passing on a comparison never made.
    #[test]
    fn no_reference_report_means_no_comparison_row() {
        let ctx = N3Ctx {
            expected_report_hash: None,
            ..dist_ctx(vec![distribution(CO[0], vec![CO[0], NUT], REPORT)])
        };
        let results = run(&n3_ce135_distribution(&ctx));
        assert!(
            !names(&results).contains(&"n3_ce135_report_matches_the_reference"),
            "got {:?}",
            names(&results)
        );
    }

    /// Distribution must reach every validator, not just the one that
    /// answered the share.
    #[test]
    fn a_distribution_to_only_one_validator_fails() {
        let results = run(&n3_ce135_distribution(&dist_ctx(vec![distribution(
            CO[0],
            vec![CO[0], NUT],
            REPORT,
        )])));
        assert!(failed(
            &results,
            "n3_ce135_reaches_every_validator",
            Severity::Hard
        ));
    }

    fn distributed(hash: [u8; 32], slot: u32) -> DistributedReport {
        DistributedReport {
            peer: CO[0],
            core: 1,
            report_hash: hash,
            sent_in_slot: slot,
            sent_at_wall_ms: SENT_AT,
        }
    }

    /// A context whose harness distributed one report in slot 100.
    fn incl_ctx(included: Vec<([u8; 32], u32)>, authored: Vec<u32>) -> N3Ctx {
        N3Ctx {
            distributed: vec![distributed(REPORT, 100)],
            included,
            authored_slots: authored,
            ..ctx(vec![submission(false)], Vec::new())
        }
    }

    #[test]
    fn a_distributed_report_carried_in_a_later_block_passes() {
        let results = run(&n3_ce135_inclusion(&incl_ctx(
            vec![(REPORT, 101)],
            vec![101],
        )));
        assert!(
            results.iter().all(|r| r.outcome == Outcome::Pass),
            "got {:?}",
            results
                .iter()
                .filter(|r| r.outcome != Outcome::Pass)
                .map(|r| r.name)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_report_the_node_never_included_fails() {
        let results = run(&n3_ce135_inclusion(&incl_ctx(Vec::new(), vec![101, 102])));
        assert!(failed(&results, "n3_ce135_report_included", Severity::Hard));
    }

    /// A block authored *before* the report went out could not have carried
    /// it, so it does not count as the node's chance to include it.
    #[test]
    fn a_block_from_before_the_distribution_is_not_a_chance_to_include() {
        let results = run(&n3_ce135_inclusion(&incl_ctx(Vec::new(), vec![99])));
        assert_eq!(names(&results), vec!["n3_ce135_inclusion_not_exercised"]);
        assert!(results.iter().all(|r| r.outcome != Outcome::Pass));
    }

    /// A node that authored nothing has not failed to include; it has failed
    /// to author, which is N1's finding and not reported twice here.
    #[test]
    fn a_node_that_authored_nothing_is_not_graded_for_inclusion() {
        let results = run(&n3_ce135_inclusion(&incl_ctx(Vec::new(), Vec::new())));
        assert!(!failed(
            &results,
            "n3_ce135_report_included",
            Severity::Hard
        ));
    }

    /// Including the hash in a block that predates the distribution is not
    /// inclusion of our report: it would have to be a different report with
    /// the same hash, which is the node echoing something it was not given.
    #[test]
    fn inclusion_must_come_after_the_distribution() {
        let results = run(&n3_ce135_inclusion(&incl_ctx(
            vec![(REPORT, 99)],
            vec![99, 101],
        )));
        assert!(failed(&results, "n3_ce135_report_included", Severity::Hard));
    }

    #[test]
    fn a_run_that_distributed_nothing_proves_nothing() {
        let ctx = N3Ctx {
            distributed: Vec::new(),
            ..incl_ctx(Vec::new(), vec![101])
        };
        let results = run(&n3_ce135_inclusion(&ctx));
        assert_eq!(names(&results), vec!["n3_ce135_inclusion_not_exercised"]);
    }

    fn faulty(fault: SubmissionFault, refused: bool) -> SubmittedPackage {
        SubmittedPackage {
            fault: Some(fault),
            refused,
            ..submission(refused)
        }
    }

    /// A node that distributed nothing matching the reference fails, even
    /// though it distributed something.
    #[test]
    fn a_distribution_that_never_matches_the_reference_fails() {
        let results = run(&n3_ce135_distribution(&dist_ctx(vec![distribution(
            CO[0],
            vec![CO[0], NUT],
            [0x33; 32],
        )])));
        assert!(failed(
            &results,
            "n3_ce135_report_matches_the_reference",
            Severity::Hard
        ));
    }

    const SHARED: [u8; 32] = [0x6b; 32];

    fn shared(reply: Option<[u8; 32]>, refused: bool, fault: Option<ShareFault>) -> SharedToNut {
        SharedToNut {
            peer: CO[0],
            core: CORE,
            slot: 100,
            shard_count: 6,
            expected_report_hash: SHARED,
            reply: reply.map(|h| (h, [0u8; 64])),
            refused,
            reset_code: refused.then_some(0x0103),
            fault,
            sent_at_wall_ms: SENT_AT,
        }
    }

    fn share_ctx(shares: Vec<SharedToNut>) -> N3Ctx {
        N3Ctx {
            shared_to_nut: shares,
            ..ctx(Vec::new(), Vec::new())
        }
    }

    /// The node refined the bundle and answered with the same report.
    #[test]
    fn a_well_formed_share_is_answered_with_the_reference_hash() {
        let results = run(&n3_ce134_receive(&share_ctx(vec![shared(
            Some(SHARED),
            false,
            None,
        )])));
        assert!(
            results.iter().all(|r| r.outcome == Outcome::Pass),
            "got {:?}",
            names(&results)
        );
    }

    /// A different hash means the node refined something else.
    #[test]
    fn a_hash_that_differs_from_the_reference_fails() {
        let results = run(&n3_ce134_receive(&share_ctx(vec![shared(
            Some([0x11; 32]),
            false,
            None,
        )])));
        assert!(failed(
            &results,
            "n3_ce134_hash_equals_the_reference",
            Severity::Hard
        ));
    }

    /// Refusing a well-formed share is a defect, and is reported once.
    #[test]
    fn refusing_a_well_formed_share_fails_once() {
        let results = run(&n3_ce134_receive(&share_ctx(vec![shared(
            None, true, None,
        )])));
        assert!(failed(&results, "n3_ce134_answered", Severity::Hard));
        assert!(
            !names(&results).contains(&"n3_ce134_hash_equals_the_reference"),
            "a node that never answered has no hash to compare"
        );
    }

    /// An unacceptable shard count must not be answered.
    #[test]
    fn an_unacceptable_shard_count_must_be_refused() {
        let refused = run(&n3_ce134_receive(&share_ctx(vec![SharedToNut {
            shard_count: 5,
            ..shared(None, true, Some(ShareFault::WrongShardCount))
        }])));
        assert!(refused.iter().all(|r| r.outcome == Outcome::Pass));

        let answered = run(&n3_ce134_receive(&share_ctx(vec![SharedToNut {
            shard_count: 5,
            ..shared(Some(SHARED), false, Some(ShareFault::WrongShardCount))
        }])));
        assert!(failed(
            &answered,
            "n3_ce134_wrong_shard_count_refused",
            Severity::Hard
        ));
    }

    /// A run that shared nothing proves nothing.
    #[test]
    fn a_run_with_no_share_proves_nothing() {
        let results = run(&n3_ce134_receive(&share_ctx(Vec::new())));
        assert_eq!(names(&results), vec!["n3_ce134_receive_not_exercised"]);
        assert!(results.iter().all(|r| r.outcome != Outcome::Pass));
    }

    /// Each fault is graded by its own rule, not by the honest one's.
    #[test]
    fn a_faulty_submission_is_not_graded_as_an_honest_one() {
        let results = run(&n3_ce133_submission(&ctx(
            vec![faulty(SubmissionFault::Oversized, true)],
            Vec::new(),
        )));
        assert_eq!(names(&results), vec!["n3_ce133_oversized_reset"]);
        assert!(
            !names(&results).contains(&"n3_ce133_accepted"),
            "a fault must not be judged against the acceptance row"
        );
    }

    /// The two faults the spec answers with a reset.
    #[test]
    fn a_reset_is_required_for_the_oversized_and_mismatched_submissions() {
        for fault in [
            SubmissionFault::Oversized,
            SubmissionFault::ExtrinsicSizeMismatch,
        ] {
            assert!(fault.expects_reset(), "{fault:?} expects a reset");
            let accepted = run(&n3_ce133_submission(&ctx(
                vec![faulty(fault, false)],
                Vec::new(),
            )));
            assert!(
                accepted
                    .iter()
                    .any(|r| r.outcome == Outcome::Fail(Severity::Hard)),
                "{fault:?} accepted must fail"
            );
            let reset = run(&n3_ce133_submission(&ctx(
                vec![faulty(fault, true)],
                Vec::new(),
            )));
            assert!(
                reset.iter().all(|r| r.outcome == Outcome::Pass),
                "{fault:?} reset must pass"
            );
        }
    }

    /// The two the spec answers with silence. A reset is not required, so a
    /// node that quietly declines to share has done the right thing.
    #[test]
    fn silence_is_enough_for_the_ignored_and_unauthorized_submissions() {
        for fault in [
            SubmissionFault::NotAGuarantor,
            SubmissionFault::Unauthorized,
        ] {
            assert!(!fault.expects_reset(), "{fault:?} does not require a reset");
            let quiet = run(&n3_ce133_submission(&ctx(
                vec![faulty(fault, false)],
                Vec::new(),
            )));
            assert!(
                quiet.iter().all(|r| r.outcome == Outcome::Pass),
                "{fault:?} with no sharing must pass, got {:?}",
                names(&quiet)
            );

            // Sharing it is the defect.
            let shared = run(&n3_ce133_submission(&N3Ctx {
                shares: vec![share(CO[0], SENT_AT + 10, Vec::new())],
                ..ctx(vec![faulty(fault, false)], Vec::new())
            }));
            assert!(
                shared
                    .iter()
                    .any(|r| r.outcome == Outcome::Fail(Severity::Hard)),
                "{fault:?} that was shared on must fail"
            );
        }
    }

    /// A share from before the submission is not an answer to it, for the
    /// fault rows as much as the honest one.
    #[test]
    fn an_earlier_share_does_not_condemn_a_faulty_submission() {
        let results = run(&n3_ce133_submission(&N3Ctx {
            shares: vec![share(CO[0], SENT_AT - 1, Vec::new())],
            ..ctx(
                vec![faulty(SubmissionFault::Unauthorized, false)],
                Vec::new(),
            )
        }));
        assert!(
            results.iter().all(|r| r.outcome == Outcome::Pass),
            "got {:?}",
            names(&results)
        );
    }

    /// The happy path: accepted, shared with both, in time.
    #[test]
    fn a_package_shared_with_both_co_guarantors_passes() {
        let results = run(&n3_ce133_submission(&ctx(
            vec![submission(false)],
            vec![
                share(CO[0], SENT_AT + 500, Vec::new()),
                share(CO[1], SENT_AT + 900, Vec::new()),
            ],
        )));
        assert!(
            results.iter().all(|r| r.outcome == Outcome::Pass),
            "expected all passes, got {:?}",
            results
                .iter()
                .filter(|r| r.outcome != Outcome::Pass)
                .map(|r| r.name)
                .collect::<Vec<_>>()
        );
    }

    /// A run that submitted nothing reports the rule as unexercised rather
    /// than collecting passes for questions the node was never asked.
    #[test]
    fn a_run_with_no_submission_proves_nothing() {
        let results = run(&n3_ce133_submission(&ctx(Vec::new(), Vec::new())));
        assert_eq!(names(&results), vec!["n3_ce133_not_exercised"]);
        assert!(
            results.iter().all(|r| r.outcome != Outcome::Pass),
            "an unexercised rule must not report as passed"
        );
    }

    #[test]
    fn a_refused_submission_fails_the_acceptance_row() {
        let results = run(&n3_ce133_submission(&ctx(
            vec![submission(true)],
            Vec::new(),
        )));
        assert!(failed(&results, "n3_ce133_accepted", Severity::Hard));
    }

    /// A refusal is one defect, not two: the node that refused the package
    /// owes no sharing, so the sharing rows must not also fire.
    #[test]
    fn a_refused_submission_is_not_also_graded_for_not_sharing() {
        let results = run(&n3_ce133_submission(&ctx(
            vec![submission(true)],
            Vec::new(),
        )));
        assert!(
            !names(&results).contains(&"n3_ce133_shares_with_both_co_guarantors"),
            "got {:?}",
            names(&results)
        );
    }

    #[test]
    fn sharing_with_only_one_co_guarantor_fails() {
        let results = run(&n3_ce133_submission(&ctx(
            vec![submission(false)],
            vec![share(CO[0], SENT_AT + 100, Vec::new())],
        )));
        assert!(failed(
            &results,
            "n3_ce133_shares_with_both_co_guarantors",
            Severity::Hard
        ));
    }

    /// A share recorded before the package went out cannot be an answer to
    /// it. Without the ordering test a node that shared someone else's
    /// package earlier in the run would look like it had answered ours.
    #[test]
    fn a_share_from_before_the_submission_does_not_count() {
        let results = run(&n3_ce133_submission(&ctx(
            vec![submission(false)],
            vec![
                share(CO[0], SENT_AT - 1, Vec::new()),
                share(CO[1], SENT_AT + 100, Vec::new()),
            ],
        )));
        assert!(failed(
            &results,
            "n3_ce133_shares_with_both_co_guarantors",
            Severity::Hard
        ));
    }

    /// Slow is soft; DESIGN §5 marks timing-tolerance clauses soft.
    #[test]
    fn sharing_past_the_window_is_a_soft_failure() {
        let results = run(&n3_ce133_submission(&ctx(
            vec![submission(false)],
            vec![
                share(CO[0], SENT_AT + SHARE_WINDOW_MS + 1, Vec::new()),
                share(CO[1], SENT_AT + SHARE_WINDOW_MS + 2, Vec::new()),
            ],
        )));
        assert!(failed(
            &results,
            "n3_ce133_shares_within_the_window",
            Severity::Soft
        ));
        assert!(
            !failed(
                &results,
                "n3_ce133_shares_with_both_co_guarantors",
                Severity::Hard
            ),
            "slow is not the same defect as not sharing"
        );
    }

    /// The package a submission imports from, for the mapping rows.
    const EXPORTER: [u8; 32] = [0x11; 32];
    const EXPORTS_ROOT: [u8; 32] = [0x22; 32];

    fn importing() -> SubmittedPackage {
        SubmittedPackage {
            imports_from: Some(ImportedFrom {
                package_hash: EXPORTER,
                exports_root: EXPORTS_ROOT,
            }),
            ..submission(false)
        }
    }

    /// The honest mapping passes: the hash of the package imported from,
    /// under the root its exports sit at.
    ///
    /// Here because the three negatives below are only worth something
    /// against a positive that passes. The row grades the mappings of a
    /// package that *imports*, so the value it wants names the exporting
    /// package -- not the package being shared, which is what this row used
    /// to ask for and no conforming node could ever have sent
    /// (`findings.md` §27).
    #[test]
    fn the_mapping_a_conforming_node_sends_passes() {
        let results = run(&n3_ce134_mappings(&ctx(
            vec![importing()],
            vec![
                share(
                    CO[0],
                    SENT_AT + 10,
                    vec![(WorkPackageHash::from(EXPORTER), EXPORTS_ROOT)],
                ),
                share(
                    CO[1],
                    SENT_AT + 20,
                    vec![(WorkPackageHash::from(EXPORTER), EXPORTS_ROOT)],
                ),
            ],
        )));
        assert!(
            !failed(
                &results,
                "n3_ce134_maps_the_imported_package",
                Severity::Hard
            ),
            "got {:?}",
            names(&results)
        );
        assert!(names(&results).contains(&"n3_ce134_maps_the_imported_package"));
    }

    /// A mapping keyed on some other package does not resolve this import.
    #[test]
    fn mappings_that_do_not_name_the_imported_package_fail() {
        let results = run(&n3_ce134_mappings(&ctx(
            vec![importing()],
            vec![share(
                CO[0],
                SENT_AT + 10,
                vec![(WorkPackageHash::from([0x99; 32]), EXPORTS_ROOT)],
            )],
        )));
        assert!(failed(
            &results,
            "n3_ce134_maps_the_imported_package",
            Severity::Hard
        ));
    }

    /// The right package under the wrong root is a resolution that is
    /// wrong, not one that is missing -- and the row has to tell them apart,
    /// because a receiving guarantor that trusts it fetches the wrong
    /// segments.
    #[test]
    fn mappings_with_the_wrong_segments_root_fail() {
        let results = run(&n3_ce134_mappings(&ctx(
            vec![importing()],
            vec![share(
                CO[0],
                SENT_AT + 10,
                vec![(WorkPackageHash::from(EXPORTER), [0xee; 32])],
            )],
        )));
        assert!(failed(
            &results,
            "n3_ce134_maps_the_imported_package",
            Severity::Hard
        ));
    }

    /// A share with no mappings at all fails a package that imports.
    ///
    /// The row used to be gated on the mappings being non-empty, which made
    /// this exact case -- the one a node most plausibly gets wrong -- the
    /// one case it could not report.
    #[test]
    fn no_mappings_at_all_fails_a_package_that_imports() {
        let results = run(&n3_ce134_mappings(&ctx(
            vec![importing()],
            vec![share(CO[0], SENT_AT + 10, Vec::new())],
        )));
        assert!(failed(
            &results,
            "n3_ce134_maps_the_imported_package",
            Severity::Hard
        ));
    }

    /// A run where nothing imported says so, rather than leaving the row
    /// out of the report altogether.
    #[test]
    fn a_run_with_no_importing_package_reports_the_row_unexercised() {
        let results = run(&n3_ce134_mappings(&ctx(
            vec![submission(false)],
            vec![
                share(CO[0], SENT_AT + 10, Vec::new()),
                share(CO[1], SENT_AT + 20, Vec::new()),
            ],
        )));
        assert!(
            !names(&results).contains(&"n3_ce134_maps_the_imported_package"),
            "got {:?}",
            names(&results)
        );
        assert!(failed(
            &results,
            "n3_ce134_imports_not_exercised",
            Severity::Soft
        ));
    }

    /// Neither protocol can answer for the other.
    ///
    /// The two are graded by one function, so the thing worth holding is
    /// that the rows stay apart: a run that submitted only over CE 133 must
    /// leave CE 146 unexercised rather than reporting it green. That is the
    /// mistake obs code 44 was retired for, in a new place.
    #[test]
    fn one_protocol_does_not_answer_for_the_other() {
        let only_133 = ctx(
            vec![submission(false)],
            vec![
                share(CO[0], SENT_AT + 10, Vec::new()),
                share(CO[1], SENT_AT + 20, Vec::new()),
            ],
        );
        let results = run(&n3_ce133_submission(&only_133));
        let ce133 = names(&results);
        assert!(
            ce133.contains(&"n3_ce133_accepted"),
            "CE 133 was exercised: {ce133:?}"
        );
        let results = run(&n3_ce146_submission(&only_133));
        let ce146 = names(&results);
        assert_eq!(
            ce146,
            vec!["n3_ce146_not_exercised"],
            "and CE 146 was not: {ce146:?}"
        );

        // And the same the other way, under CE 146's own names.
        let only_146 = ctx(
            vec![SubmittedPackage {
                protocol: 146,
                ..submission(false)
            }],
            vec![
                share(CO[0], SENT_AT + 10, Vec::new()),
                share(CO[1], SENT_AT + 20, Vec::new()),
            ],
        );
        let results = run(&n3_ce146_submission(&only_146));
        let ce146 = names(&results);
        assert!(
            ce146.contains(&"n3_ce146_accepted")
                && ce146.contains(&"n3_ce146_shares_with_both_co_guarantors"),
            "CE 146 is graded by the same rules under its own names: {ce146:?}"
        );
        let results = run(&n3_ce133_submission(&only_146));
        assert_eq!(names(&results), vec!["n3_ce133_not_exercised"]);
    }

    /// The oversize row names the cap its own protocol sets.
    ///
    /// CE 133 counts the core index with the package and CE 146 does not, so
    /// a report that quoted one figure for both would send a reader looking
    /// for a defect at the wrong size.
    #[test]
    fn each_protocol_reports_its_own_cap() {
        for (protocol, cap) in [
            (
                133u16,
                jamnp_s::codec::ce131_136::WORK_PACKAGE_INITIAL_MAX as usize,
            ),
            (146, jamnp_s::codec::ce137_148::WORK_PACKAGE_MAX),
        ] {
            let over = ctx(
                vec![SubmittedPackage {
                    protocol,
                    fault: Some(SubmissionFault::Oversized),
                    ..submission(false)
                }],
                Vec::new(),
            );
            let check = if protocol == 133 {
                n3_ce133_submission(&over)
            } else {
                n3_ce146_submission(&over)
            };
            let results = run(&check);
            let row = results
                .iter()
                .find(|r| r.name == format!("n3_ce{protocol}_oversized_reset"))
                .unwrap_or_else(|| panic!("CE {protocol} grades its own oversize row"));
            let detail = format!("{:?}", row.detail);
            assert!(
                detail.contains(&cap.to_string()),
                "CE {protocol} must quote its own {cap} byte cap: {detail}"
            );
        }
    }
}
