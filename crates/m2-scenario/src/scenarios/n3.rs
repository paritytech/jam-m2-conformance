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

/// A CE 133 submission the harness made, and what the node did with it.
///
/// The counterpart of N2's `DeliveredTicket`: the refusal goes on the record
/// of the submission it answers, not into the observation log alone. A stream
/// reset carries no reason, so the log can only say that one happened; which
/// package was refused is a fact only the sender holds.
#[derive(Debug, Clone)]
pub struct SubmittedPackage {
    /// The emulated validator that submitted, acting as a builder.
    pub peer: u16,
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
    /// The validators holding `core` at `slot` alongside the NUT: who the
    /// node is expected to open CE 134 to.
    ///
    /// On the submission rather than on the lane context, because the
    /// assignment is a property of this core at this slot. A run that
    /// submitted twice across a rotation boundary has two different answers,
    /// and a single per-run list would grade the second against the first.
    pub co_guarantors: Vec<u16>,
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
    let ctx = ctx.clone();
    check("n3_ce133_submission", Severity::Hard, move |_obs| {
        let control = Control::new(
            "n3_ce133_not_exercised",
            "a work package submitted to the NUT",
            !ctx.submissions.is_empty(),
        );
        if !control.present() {
            return vec![control.absent("n3_ce133_not_exercised")];
        }

        let mut results = Vec::new();
        for submitted in &ctx.submissions {
            results.push(log::check_detail(
                "n3_ce133_accepted",
                !submitted.refused,
                Severity::Hard,
                || {
                    format!(
                        "the NUT reset the CE 133 stream for the package {} on core {}",
                        short(&submitted.package_hash),
                        submitted.core
                    )
                },
            ));
            // A node that refused the package owes no sharing, and grading it
            // for not sharing would report one defect twice.
            if submitted.refused {
                continue;
            }

            // Shares that answer *this* submission. A share recorded before
            // the package went out cannot be a response to it.
            let answering: Vec<&SharingSeen> = ctx
                .shares
                .iter()
                .filter(|share| share.at_wall_ms >= submitted.sent_at_wall_ms)
                .collect();
            let reached: HashSet<u16> = answering.iter().map(|share| share.peer).collect();

            for co_guarantor in &submitted.co_guarantors {
                results.push(log::check_detail(
                    "n3_ce133_shares_with_both_co_guarantors",
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

            // The share has to be of the package we sent. A node that shares
            // something else has not failed to share, it has shared the wrong
            // thing, and the two are different findings.
            //
            // Only where the node sent mappings at all. They map the *import*
            // list's package hashes to segments-roots (`simple.md:449`), so a
            // package with no imported segments correctly has none -- and a
            // row written as "names it, or there were none" would be true
            // whatever the node did, which is a check that cannot fail.
            for share in answering.iter().filter(|s| !s.mappings.is_empty()) {
                let names_it = share
                    .mappings
                    .iter()
                    .any(|(package, _)| package.0 == submitted.package_hash);
                results.push(log::check_detail(
                    "n3_ce134_shares_the_submitted_package",
                    names_it,
                    Severity::Hard,
                    || {
                        format!(
                            "the CE 134 to validator {} maps {:?}, none of which is the \
                             submitted package {}",
                            share.peer,
                            share
                                .mappings
                                .iter()
                                .map(|(p, _)| short(&p.0))
                                .collect::<Vec<_>>(),
                            short(&submitted.package_hash)
                        )
                    },
                ));
            }

            // Timing last, and soft: a node that shared correctly but slowly
            // is not the node that did not share.
            if let Some(first) = answering.iter().map(|s| s.at_wall_ms).min() {
                let took = first.saturating_sub(submitted.sent_at_wall_ms);
                results.push(log::check_detail(
                    "n3_ce133_shares_within_the_window",
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

            if let Some(expected) = ctx.expected_report_hash {
                results.push(log::check_detail(
                    "n3_ce135_report_matches_the_reference",
                    report.report_hash == expected,
                    Severity::Hard,
                    || {
                        format!(
                            "the NUT distributed report {}, the reference refined {} from the \
                             same package",
                            short(&report.report_hash),
                            short(&expected)
                        )
                    },
                ));
            }
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

/// Every N3 check, in the order the lane reports them.
pub fn all(ctx: &N3Ctx) -> Vec<Check> {
    vec![n3_ce133_submission(ctx), n3_ce135_distribution(ctx)]
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
            core: CORE,
            slot: 100,
            package_hash: PACKAGE,
            sent_at_wall_ms: SENT_AT,
            refused,
            co_guarantors: CO.to_vec(),
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

    /// Mappings that name a different package are a share of the wrong thing.
    #[test]
    fn mappings_that_do_not_name_the_submitted_package_fail() {
        let other = WorkPackageHash::from([0x11; 32]);
        let results = run(&n3_ce133_submission(&ctx(
            vec![submission(false)],
            vec![
                share(CO[0], SENT_AT + 10, vec![(other, [0x22; 32])]),
                share(CO[1], SENT_AT + 20, Vec::new()),
            ],
        )));
        assert!(failed(
            &results,
            "n3_ce134_shares_the_submitted_package",
            Severity::Hard
        ));
    }

    /// A package with no imported segments has no mappings, and the row is
    /// absent rather than passing on a condition it could never fail.
    #[test]
    fn no_mappings_means_the_mapping_row_is_not_reported() {
        let results = run(&n3_ce133_submission(&ctx(
            vec![submission(false)],
            vec![
                share(CO[0], SENT_AT + 10, Vec::new()),
                share(CO[1], SENT_AT + 20, Vec::new()),
            ],
        )));
        assert!(
            !names(&results).contains(&"n3_ce134_shares_the_submitted_package"),
            "got {:?}",
            names(&results)
        );
    }
}
