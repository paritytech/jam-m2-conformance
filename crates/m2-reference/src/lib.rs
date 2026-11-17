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
//! assurances and judgments and erasure-coding bundles. None of that exists
//! yet -- those are N4's and N5's -- but nothing upstream blocks them any
//! more: the export for bundle -> shards + justifications + segment proofs
//! was the last outstanding DESIGN §8 prerequisite and the pin now carries
//! it (`hazmat::erasure`, `hazmat::availability`).
#![deny(unsafe_code)]

pub mod chain;
pub mod import;
pub mod oracle;
pub mod reports;
pub mod state;
pub mod tickets;
