//! N1/N2/N3 detail observations the emulator emits (DESIGN.md §11).
//!
//! Like the N0 codes (`scenarios/n0.rs`), these ride the
//! [`dsl::ObsKind::Other`] extension slot. The runner wires the emulator to
//! emit them; the lane checks match on the numeric code.
//!
//! | code | meaning |
//! |------|---------|
//! | 41 | NUT received a CE 131 ticket distribution |
//! | 42 | NUT received a CE 132 ticket distribution |
//! | 43 | NUT refused a ticket the emulator sent: it reset the stream |
//! | 45 | emulator sent a ticket via CE 131 (to the NUT as proxy) |
//! | 46 | emulator sent a ticket via CE 132 (broadcast incl. the NUT) |
//! | 47 | emulator withheld a planned ticket: the NUT could not accept it |
//! | 48 | NUT sent a CE 131/132 frame that would not decode |
//! | 50 | NUT sent a CE 134 sharing stream that would not decode |
//! | 51 | NUT sent a CE 135 frame that would not decode |
//! | 52 | emulator submitted a work package over CE 133 |
//! | 53 | NUT refused a CE 133 submission: it reset the stream |
//! | 54 | emulator answered a CE 134 share with a hash and signature |
//! | 55 | emulator distributed a guaranteed work-report over CE 135 |
//! | 56 | emulator opened a CE 134 share to the NUT |
//! | 57 | NUT answered a CE 134 share with a hash and signature |
//!
//! Code 44 is retired. It meant two unrelated things -- the NUT refusing a
//! ticket, and the NUT sending a frame the harness could not decode -- and
//! because the lanes read it with an unscoped `obs.first`, any undecodable
//! frame anywhere in a run satisfied a check about a refusal. The refusal is
//! now recorded per delivery on `ctx::DeliveredTicket`, where it names which
//! ticket was refused; 48 is the encoding fault, which is the NUT's defect
//! and nothing to do with refusals. The number is not reused, so an old trace
//! cannot be read as if it meant either of them.

/// NUT received a CE 131 ticket distribution.
pub const RECV_CE131: u8 = 41;
/// NUT received a CE 132 ticket distribution.
pub const RECV_CE132: u8 = 42;
/// The NUT refused a ticket the emulator sent, by resetting its stream.
///
/// Why it refused is not inferred here: the reset carries no reason, and the
/// cause is whatever the harness deliberately put in that ticket. The lanes
/// read the refusal off the delivery record, which names the ticket; this
/// code exists so the observation log and the report show that a refusal
/// happened at all.
pub const TICKET_REFUSED: u8 = 43;
/// Emulator delivered a ticket via CE 131 (NUT as proxy).
pub const EMU_SENT_131: u8 = 45;
/// Emulator delivered a ticket via CE 132 (broadcast incl. the NUT).
pub const EMU_SENT_132: u8 = 46;
/// Emulator withheld a planned ticket because the NUT was not in a state to
/// accept it; see `ticket_io::node_can_accept_tickets`.
pub const TICKET_WITHHELD: u8 = 47;
/// The NUT sent a CE 131/132 frame the harness could not decode.
///
/// An encoding defect on the node's side. It used to share a code with the
/// refusal above, which let any such frame satisfy a check about a refused
/// ticket -- and the CE 131 decoder defect closed on 2026-10-30 was a
/// generator of exactly these.
pub const NUT_SENT_UNDECODABLE: u8 = 48;

/// The NUT sent a CE 134 sharing stream the harness could not read.
///
/// Separate from the CE 135 code below, and from N2's
/// [`NUT_SENT_UNDECODABLE`], for the reason code 44 was retired: one code
/// standing for two different defects lets a check about either be satisfied
/// by the other.
pub const NUT_SENT_BAD_SHARING: u8 = 50;
/// The NUT sent a CE 135 frame the harness could not read.
pub const NUT_SENT_BAD_REPORT: u8 = 51;

/// The emulator submitted a work package to the NUT over CE 133.
pub const EMU_SENT_133: u8 = 52;
/// The NUT refused a CE 133 submission, by resetting its stream.
///
/// As with N2's ticket refusals, why it refused is not inferred here: a reset
/// carries no reason, and the cause is whatever the harness deliberately put
/// in that submission. Which package was refused is recorded on
/// `scenarios::n3::SubmittedPackage`; this code only says one happened.
pub const PACKAGE_REFUSED: u8 = 53;

/// An emulated co-guarantor answered a CE 134 share (`simple.md:456`).
///
/// Its absence where a share was seen means the harness had no answer to
/// give -- no package of ours was in flight -- not that the node went
/// unanswered through any fault of its own.
pub const EMU_ANSWERED_134: u8 = 54;

/// The emulator distributed a reference-guaranteed work-report over CE 135.
pub const EMU_SENT_135: u8 = 55;

/// The emulator opened a CE 134 share to the NUT, as a sharing guarantor.
pub const EMU_SENT_134: u8 = 56;
/// The NUT answered a CE 134 share (`simple.md:456`).
///
/// Its absence, where the stream was not reset either, is a node that took
/// the bundle and said nothing -- neither refusing nor refining.
pub const NUT_ANSWERED_134: u8 = 57;
