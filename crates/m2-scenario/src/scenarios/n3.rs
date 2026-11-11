//! N3 — guaranteeing (DESIGN.md §11 N3).
//!
//! The lane's facts are what the node did with a work package the harness
//! submitted as a builder: whether it accepted the CE 133 submission, whether
//! it opened CE 134 to both of its co-guarantors, and what it put on CE 135.
//!
//! The records here are filled by `m2_emu::report_io`; the checks read them.
//! Nothing in this module refines or signs anything — every reference value
//! is computed in `m2-reference` and injected.

use jam_types::WorkPackageHash;

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
}
