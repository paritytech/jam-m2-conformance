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
//! Availability is split in two, and the split is the rule rather than an
//! accident of where things landed. Erasure coding and justification
//! checking are the engine's, so they go over the socket ([`availability`]);
//! signing and checking an assurance is `jam-std-common` code both sides
//! link, so it does not ([`assurance`]). The test before adding a message is
//! not "does the engine know how" but "is there a second implementation to
//! diverge from".
//!
//! **Not here yet.** DESIGN §3 also describes this crate as signing
//! judgments, which is N5's.
#![deny(unsafe_code)]

pub mod assurance;
pub mod availability;
pub mod chain;
pub mod import;
pub mod oracle;
pub mod reports;
pub mod state;
pub mod tickets;
