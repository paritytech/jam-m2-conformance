//! Comparing one run's rows against another's (DESIGN §11 N7, index
//! rotation).
//!
//! The row asks for "every lane re-run with `k ∈ {1..5}` to catch
//! index-dependent bugs (grid neighbours, shard index)". Re-running is the
//! easy half — `--validator-index` already does it. The half worth writing
//! down is the comparison: given the reports, which rows answered
//! differently depending on where in the validator set the node sat?
//!
//! **What a difference means is not obvious**, and the comparison is
//! deliberately conservative about it. A row that is absent from one run
//! and present in another usually says the run did not reach it, not that
//! the node behaved differently — which lane work happened to fire inside
//! the window varies run to run at a *fixed* index too. So absence is
//! reported apart from disagreement, and only a row that **passed at one
//! index and failed at another** is called out as index-dependent. That is
//! the shape a grid-neighbour or shard-index bug takes.

use std::collections::{BTreeMap, BTreeSet};

/// One run's outcome for one row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RowOutcome {
    Pass,
    Fail,
}

/// What one run produced: the validator index it ran at, and each row's
/// outcome.
///
/// A row that fired more than once in a run collapses to its worst outcome:
/// the question here is whether the node could do the thing at this index,
/// and one failure answers it.
#[derive(Debug, Clone)]
pub struct RunRows {
    pub validator_index: usize,
    pub rows: BTreeMap<String, RowOutcome>,
}

impl RunRows {
    /// Parse a `report.md`, taking the validator index from its header.
    ///
    /// The header is where the index belongs: a report that does not say
    /// which index produced it cannot be compared with another, and a
    /// caller passing the index alongside the file can pass the wrong one.
    ///
    /// `None` when the header has no index — an older report, from before
    /// it was recorded — which is reported rather than guessed at.
    pub fn from_report_file(report: &str) -> Option<Self> {
        let index = report.lines().find_map(|line| {
            line.strip_prefix("- Validator index:")?
                .trim()
                .parse::<usize>()
                .ok()
        })?;
        Some(Self::from_report(index, report))
    }

    /// Parse the `| LANE | row | severity | VERDICT |` lines of a
    /// `report.md`.
    ///
    /// Tolerant of everything else in the file: anything that is not such a
    /// line is skipped, so a report that grows new sections does not break
    /// the comparison.
    pub fn from_report(validator_index: usize, report: &str) -> Self {
        let mut rows: BTreeMap<String, RowOutcome> = BTreeMap::new();
        for line in report.lines() {
            let cells: Vec<&str> = line.split('|').map(str::trim).collect();
            // ["", lane, row, severity, verdict, ""]
            if cells.len() != 6 || cells[0] != "" {
                continue;
            }
            let (lane, row, verdict) = (cells[1], cells[2], cells[4]);
            if !lane.starts_with('N') || row.is_empty() {
                continue;
            }
            let outcome = match verdict {
                "HARD PASS" | "SOFT PASS" => RowOutcome::Pass,
                "FAIL" | "SOFT" => RowOutcome::Fail,
                _ => continue,
            };
            // Worst wins: one failure at this index is the answer.
            rows.entry(row.to_string())
                .and_modify(|seen| *seen = (*seen).max(outcome))
                .or_insert(outcome);
        }
        Self {
            validator_index,
            rows,
        }
    }
}

/// A row that did not answer the same way at every index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disagreement {
    pub row: String,
    /// Indices where it passed, and where it failed.
    pub passed_at: Vec<usize>,
    pub failed_at: Vec<usize>,
}

/// What a rotation found.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Rotation {
    /// Rows that passed at one index and failed at another. These are the
    /// point of the exercise.
    pub disagreements: Vec<Disagreement>,
    /// Rows that some runs never reported at all, with the indices that did
    /// report them. Usually the run not reaching that work rather than the
    /// node differing, which is why it is kept separate.
    pub partial: Vec<(String, Vec<usize>)>,
    pub indices: Vec<usize>,
}

/// Compare the rows of two or more runs.
///
/// Fewer than two runs is not a comparison and yields nothing — a caller
/// that rotated over one index has measured nothing and should be told so
/// by an empty result rather than by a confident "no disagreements".
pub fn compare(runs: &[RunRows]) -> Rotation {
    if runs.len() < 2 {
        return Rotation::default();
    }
    let indices: Vec<usize> = runs.iter().map(|r| r.validator_index).collect();
    let every_row: BTreeSet<&String> = runs.iter().flat_map(|r| r.rows.keys()).collect();

    let mut disagreements = Vec::new();
    let mut partial = Vec::new();
    for row in every_row {
        let mut passed_at = Vec::new();
        let mut failed_at = Vec::new();
        let mut reported_at = Vec::new();
        for run in runs {
            match run.rows.get(row) {
                Some(RowOutcome::Pass) => {
                    passed_at.push(run.validator_index);
                    reported_at.push(run.validator_index);
                }
                Some(RowOutcome::Fail) => {
                    failed_at.push(run.validator_index);
                    reported_at.push(run.validator_index);
                }
                None => {}
            }
        }
        if !passed_at.is_empty() && !failed_at.is_empty() {
            disagreements.push(Disagreement {
                row: row.clone(),
                passed_at,
                failed_at,
            });
        } else if reported_at.len() != runs.len() {
            partial.push((row.clone(), reported_at));
        }
    }
    Rotation {
        disagreements,
        partial,
        indices,
    }
}

/// Render a rotation as the lines a report or a terminal wants.
pub fn describe(rotation: &Rotation) -> String {
    if rotation.indices.len() < 2 {
        return "a rotation needs at least two indices; nothing was compared".to_string();
    }
    let mut out = format!("Compared validator indices {:?}.\n", rotation.indices);
    if rotation.disagreements.is_empty() {
        out.push_str("No row passed at one index and failed at another.\n");
    } else {
        out.push_str("\nIndex-dependent rows:\n");
        for d in &rotation.disagreements {
            out.push_str(&format!(
                "  {} — passed at {:?}, failed at {:?}\n",
                d.row, d.passed_at, d.failed_at
            ));
        }
    }
    if !rotation.partial.is_empty() {
        out.push_str(&format!(
            "\n{} row(s) were not reported by every run, which usually means the run did not \
             reach that work rather than that the node differed.\n",
            rotation.partial.len()
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPORT: &str = "\
# Report
| Lane | Check | Severity | Result |
|---|---|---|---|
| N0 | ce129_serve.ce129_boundary | hard | FAIL |
| N0 | up0_announce.up0_seen | hard | HARD PASS |
| N4 | n4_ce141_send.n4_sent | soft | SOFT PASS |
some prose that is not a row
";

    #[test]
    fn a_report_parses_into_rows() {
        let run = RunRows::from_report(5, REPORT);
        assert_eq!(run.rows.len(), 3);
        assert_eq!(run.rows["ce129_serve.ce129_boundary"], RowOutcome::Fail);
        assert_eq!(run.rows["up0_announce.up0_seen"], RowOutcome::Pass);
        assert_eq!(run.rows["n4_ce141_send.n4_sent"], RowOutcome::Pass);
    }

    /// A row that fired several times collapses to its worst outcome: the
    /// question is whether the node could do the thing at this index, and
    /// one failure answers it.
    #[test]
    fn a_row_that_fired_twice_takes_its_worst_outcome() {
        let report = "\
| N7 | n7_containment.contained | soft | SOFT PASS |
| N7 | n7_containment.contained | soft | SOFT |
";
        let run = RunRows::from_report(1, report);
        assert_eq!(run.rows["n7_containment.contained"], RowOutcome::Fail);
    }

    #[test]
    fn a_row_that_differs_by_index_is_reported() {
        let a = RunRows::from_report(1, "| N4 | shard.index_ok | hard | HARD PASS |\n");
        let b = RunRows::from_report(3, "| N4 | shard.index_ok | hard | FAIL |\n");
        let rotation = compare(&[a, b]);
        assert_eq!(
            rotation.disagreements,
            [Disagreement {
                row: "shard.index_ok".to_string(),
                passed_at: vec![1],
                failed_at: vec![3],
            }]
        );
        assert!(rotation.partial.is_empty());
    }

    /// Agreement is not a disagreement, however many indices agree and
    /// whichever way they agree.
    #[test]
    fn rows_that_agree_are_not_reported() {
        let runs: Vec<RunRows> = [1, 3, 5]
            .iter()
            .map(|k| {
                RunRows::from_report(
                    *k,
                    "| N0 | a.always_passes | hard | HARD PASS |\n\
                     | N0 | b.always_fails | hard | FAIL |\n",
                )
            })
            .collect();
        let rotation = compare(&runs);
        assert!(
            rotation.disagreements.is_empty(),
            "a row that fails everywhere is not index-dependent: {:?}",
            rotation.disagreements
        );
        assert!(rotation.partial.is_empty());
    }

    /// A row missing from one run is reported apart from disagreement.
    ///
    /// This is the distinction the module exists to keep. Which lane work
    /// fires inside a window varies run to run at a *fixed* index too, so
    /// treating absence as a difference would fill the report with noise
    /// and bury the real thing.
    #[test]
    fn a_row_missing_from_one_run_is_not_a_disagreement() {
        let a = RunRows::from_report(1, "| N3 | ce133.submitted | hard | HARD PASS |\n");
        let b = RunRows::from_report(3, "| N0 | up0.seen | hard | HARD PASS |\n");
        let rotation = compare(&[a, b]);
        assert!(rotation.disagreements.is_empty());
        assert_eq!(rotation.partial.len(), 2);
        assert!(describe(&rotation).contains("not reported by every run"));
    }

    /// One run is not a rotation, and must not read as a clean one.
    #[test]
    fn a_single_run_compares_nothing() {
        let only = RunRows::from_report(5, REPORT);
        let rotation = compare(std::slice::from_ref(&only));
        assert_eq!(rotation, Rotation::default());
        assert!(describe(&rotation).contains("at least two indices"));
        assert!(
            !describe(&rotation).contains("No row passed at one index"),
            "a single run must not report agreement it did not measure"
        );
    }

    /// The description names the row and both sets of indices, so a reader
    /// can go straight to the two sessions that disagreed.
    #[test]
    fn the_description_names_the_row_and_the_indices() {
        let a = RunRows::from_report(1, "| N4 | shard.index_ok | hard | HARD PASS |\n");
        let b = RunRows::from_report(4, "| N4 | shard.index_ok | hard | FAIL |\n");
        let text = describe(&compare(&[a, b]));
        assert!(text.contains("shard.index_ok"), "{text}");
        assert!(text.contains("[1]") && text.contains("[4]"), "{text}");
    }

    /// The index comes out of the header, so a caller cannot pair a report
    /// with the wrong one.
    #[test]
    fn the_index_is_read_from_the_report() {
        let report = "\
# M2 Conformance Report

- Run: rot-k3
- Timestamp: 1795457648 (unix seconds)
- Validator index: 3
- Checks: 28, Findings: 1

| N0 | up0.seen | hard | HARD PASS |
";
        let run = RunRows::from_report_file(report).expect("the header has an index");
        assert_eq!(run.validator_index, 3);
        assert_eq!(run.rows.len(), 1);
    }

    /// A report from before the index was recorded is refused rather than
    /// guessed at.
    #[test]
    fn a_report_without_an_index_is_refused() {
        assert!(RunRows::from_report_file(REPORT).is_none());
    }
}
