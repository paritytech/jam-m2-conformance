//! Reference oracle for the JAM M2 harness.
//!
//! Wraps the polkajam `hazmat` reference engine. What is implemented today:
//! the 6-validator tiny reference chain ([`chain`]), authoring blocks for the
//! emulated slots, importing NUT blocks and diffing the resulting state
//! ([`import`], [`state`]), and generating, planning and verifying Safrole
//! tickets, including the deliberately broken ones ([`tickets`]).
//!
//! `m2-emu` never executes core logic: every value and decision is computed
//! once here and injected.
//!
//! Building work packages, refining them into reports and signing guarantees
//! is [`reports`], which N3 puts on CE 133, CE 134 and CE 135.
//!
//! **Not here yet.** DESIGN §3 also describes this crate as signing
//! assurances and judgments and erasure-coding bundles. None of that exists:
//! those are N4's and N5's, and the export for bundle -> shards +
//! justifications + segment proofs is the one DESIGN §8 prerequisite still
//! outstanding.
#![deny(unsafe_code)]

pub mod chain;
pub mod import;
pub mod reports;
pub mod state;
pub mod tickets;
