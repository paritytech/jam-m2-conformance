//! Wire protocol between the conformance harness and its polkajam oracle.
//!
//! The harness compiles polkajam's node crate in-process to use as a
//! reference oracle, behind the `hazmat` feature whose own documentation
//! says its interfaces "may change at any time". This crate is the first
//! step out of that: the message set an out-of-process oracle answers, so
//! the workspace can depend on polkajam's published crates alone.
//!
//! # Framing
//!
//! Taken from polkajam's fuzz protocol unchanged: a 4-byte little-endian
//! length prefix, then a JAM-codec `#[repr(u8)]` message. Tags 0 to 5 and
//! 255 keep the meaning they have there, so a reader of one is a reader of
//! the other; M2's own messages start at 16 and the two sets cannot collide.
//!
//! # One deviation
//!
//! The fuzz protocol's `Error(255)` is the node's verdict on a block --
//! "this block is invalid" -- and its own documentation says internal
//! failures must not be signalled with it. An oracle that panics is an
//! internal failure, so M2 adds [`Message::OracleFault`] for those. Without
//! the split a report could not tell an oracle crash from a node under test
//! that was correctly rejected.
#![deny(unsafe_code)]

use codec::{Decode, Encode};

/// Version of this protocol, carried in the handshake.
///
/// Bumped whenever a message changes shape. The client refuses a mismatch
/// rather than guessing, because a silently misread response is a wrong
/// conformance verdict rather than an error.
pub const PROTOCOL_VERSION: u16 = 5;

/// Largest frame either side will read, matching the fuzz protocol's.
pub const MAX_MESSAGE_SIZE: u32 = 256 * 1024 * 1024;

/// The dev chain spec's bootstrap service, which is what every work item
/// this harness builds is addressed to.
///
/// A copy of `jam_node::DEV_BOOTSTRAP_SERVICE_ID`, kept here so that a crate
/// with no node dependency can name the service. The oracle holds both and
/// asserts they are equal, which is where a re-pin that moved it would be
/// caught -- the same arrangement as the revision pin, and for the same
/// reason: one source, one guard, no second copy to forget.
pub const DEV_BOOTSTRAP_SERVICE_ID: u32 = 0;

/// Index of the validator designated as proxy for a ticket.
///
/// polkajam's rule: the big-endian last four bytes of the ticket id, modulo
/// the validator count.
///
/// Here rather than in either crate that needs it, because both do: the
/// oracle stamps each proved ticket with its proxy, and the lanes read that
/// stamp. A second implementation of this on the oracle side folded the
/// *first* sixteen bytes instead, which is a well-formed-looking rule that
/// produces a different answer for almost every ticket -- every delivery in
/// a simulated run went to the wrong peer, and the lane reported a node that
/// had forwarded nothing.
pub fn proxy_index(ticket_id: &[u8; 32], val_count: usize) -> usize {
    let last4 = &ticket_id[28..32];
    u32::from_be_bytes([last4[0], last4[1], last4[2], last4[3]]) as usize % val_count
}

/// A chain's storage at one block: the trie root, and every key it holds.
///
/// The root travels with the pairs rather than being fetched separately.
/// They are read from one storage view in the oracle, and two round trips
/// could land either side of an import and describe different states -- a
/// root that does not belong to the keys beside it is the one failure the
/// N1 state diff cannot detect, because disagreeing is exactly what it
/// expects to find.
#[derive(Clone, Debug, Encode, Decode, PartialEq, Eq)]
pub struct WireState {
    pub root: [u8; 32],
    /// 31-byte key, value.
    pub keyvals: Vec<(Vec<u8>, Vec<u8>)>,
}

/// A work item, mirrored.
///
/// `jam_node::hazmat::BuildItem` is a hazmat type and cannot cross the wire
/// or appear in a crate that does not depend on the node. Every field is one
/// the harness already sets.
#[derive(Clone, Debug, Encode, Decode, PartialEq, Eq)]
pub struct WireItem {
    pub service: u32,
    pub payload: Vec<u8>,
    pub ref_gas: u64,
    pub acc_gas: u64,
    /// Extrinsic bodies, in the order the package will declare them.
    pub xts: Vec<Vec<u8>>,
    /// Imported segment specs, encoded as the engine encodes them.
    pub imports: Vec<Vec<u8>>,
    pub export_count: u16,
}

/// A ticket an emulated validator proved.
///
/// Mirrors `m2_reference::tickets::EmulatedTicket`, which cannot cross the
/// wire: it is built from a hazmat keystore.
#[derive(Clone, Debug, Encode, Decode, PartialEq, Eq)]
pub struct WireTicket {
    /// Ring-VRF output, which is the ticket id and its score.
    pub id: [u8; 32],
    pub author: u16,
    pub attempt: u8,
    /// Ring signature, 32 + 752 bytes.
    pub proof: Vec<u8>,
    /// Proxy index over the validator set.
    pub proxy: u16,
}

/// Which view of the core assignment a request wants.
///
/// polkajam computes it two ways and they disagree for a slot in the chain
/// head's own epoch: the storage reads an entropy entry chosen by its own
/// slot, while a guarantor choosing who to share with reads its epoch's
/// precomputed one. The harness needs both -- one to match what the node
/// does, one to match the on-chain rule -- so the request says which.
#[derive(Clone, Copy, Debug, Encode, Decode, PartialEq, Eq)]
pub enum AssignmentView {
    /// `storage.core_assignments_for(slot)`, which the on-chain rule uses.
    Storage = 0,
    /// `EpochInfo::core_assignments(slot)`, which a sharing guarantor uses.
    Epoch = 1,
}

/// A session on the oracle: one `AuthoringHarness` over one spec file.
///
/// Sessions exist because a run holds two chains at once -- the harness's own
/// and the view it hands the node -- and a single connection has to serve
/// both without their slots interleaving.
pub type SessionId = u16;

/// One request or response on the wire.
///
/// Tags 0 to 5 and 255 are the fuzz protocol's; 16 upward are M2's.
#[derive(Clone, Debug, Encode, Decode, PartialEq, Eq)]
#[repr(u8)]
#[allow(clippy::large_enum_variant)]
pub enum Message {
    /// Handshake, both directions. The response carries the oracle's
    /// protocol version and the polkajam revision it was built from.
    PeerInfo(PeerInfo) = 0,
    /// A block to import, answered with `StateRoot` or `Error`.
    ImportBlock(Vec<u8>) = 3,
    /// State at a header hash, answered with `State`.
    GetState([u8; 32]) = 4,

    /// Open a session over a genesis spec file.
    Open {
        spec_path: String,
        /// Validator indices whose secrets this session holds.
        holds: Vec<u16>,
        /// The slot to seed the session's virtual clock to.
        ///
        /// Sent rather than read, because the oracle's own wall clock is the
        /// wrong one. The harness is virtual-time and a simulation runs on
        /// an installed clock that can start anywhere; an oracle reading
        /// `SystemTime::now()` seeded a session months away from the run
        /// around it, and the ticket pool -- which files by the epoch of the
        /// session's next slot -- then filed every ticket under an epoch no
        /// block would ever ask for. The blocks still came out at the right
        /// slots and carried nothing, which is a hard thing to see.
        now_slot: u32,
    } = 16,
    /// A session was opened.
    Opened {
        session: SessionId,
        genesis_hash: [u8; 32],
        genesis_slot: u32,
    } = 17,
    /// Close a session and drop its harness.
    Close(SessionId) = 18,
    /// Author a block at a slot. `None` means the session held no key for it.
    AuthorBlock {
        session: SessionId,
        slot: u32,
    } = 19,
    /// The authored block, encoded, or nothing.
    Authored(Option<Vec<u8>>) = 20,
    /// The session's best block.
    Head(SessionId) = 21,
    /// Hash and slot of the best block.
    HeadIs {
        hash: [u8; 32],
        slot: u32,
    } = 22,
    /// Every block on the session's chain, encoded.
    ChainBlocks(SessionId) = 23,
    Blocks(Vec<Vec<u8>>) = 24,
    /// Posterior state root of a block, if the session has it.
    StateRootOf {
        session: SessionId,
        hash: [u8; 32],
    } = 25,
    /// The ring context a target epoch's tickets are proved against.
    TicketCtx(SessionId) = 34,
    /// Bandersnatch keys of the designated validators, and the entropy.
    ///
    /// Entry 2 of the buffer, which is what the reference reads. The
    /// entries differ by an epoch and the confusion between them has cost
    /// this project a session before: every emulated ticket comes back
    /// "invalid ticket signature", and it goes unnoticed because the two
    /// agree whenever an epoch boundary falls between proving and
    /// delivery.
    TicketContext {
        pks: Vec<[u8; 32]>,
        entropy: [u8; 32],
        /// The epoch whose tickets this entropy seals, read from the same
        /// storage view as the entropy itself.
        ///
        /// Sent rather than computed by the caller. A caller has only its own
        /// clock to compute it from, and the chain head is not the clock: the
        /// head lags whenever the driver has not authored the current slot,
        /// which is most of the time and all of the time once the observation
        /// window has closed. When the two sit on opposite sides of an epoch
        /// boundary, a context sealing epoch E gets filed under E+1, and
        /// every ticket checked against it fails with "did not verify against
        /// that epoch's ring" -- every attempt, of every author, for that one
        /// epoch, which is what it looked like.
        epoch: u32,
    } = 35,
    /// Prove tickets for one author, or for every author the session holds.
    ///
    /// Ring-VRF proving is the harness's single most expensive operation --
    /// five authors times four attempts runs to tens of seconds -- so the
    /// request names an author where the caller wants one, rather than
    /// paying for the whole set and discarding most of it.
    SignTickets {
        session: SessionId,
        /// `None` proves for every author the session's keystore backs.
        author: Option<u16>,
        /// Which attempts to prove; `None` is every attempt up to the
        /// per-validator cap.
        ///
        /// Named rather than implied because a fault row wants a ticket for
        /// an attempt *past* the cap, proved over that attempt. Rewriting an
        /// honest ticket's attempt afterwards will not do: the attempt is
        /// part of the signed message, so the edit breaks the proof too and
        /// the node then has two reasons to refuse it instead of the one
        /// the row is testing.
        attempts: Option<Vec<u8>>,
        pks: Vec<[u8; 32]>,
        entropy: [u8; 32],
    } = 36,
    /// The proved tickets.
    Tickets(Vec<WireTicket>) = 37,
    /// Put tickets into the session's pool, as a validator would.
    SubmitTickets {
        session: SessionId,
        /// Encoded `TicketEnvelope`s.
        envelopes: Vec<Vec<u8>>,
    } = 38,
    /// A request that needed no answer succeeded.
    ///
    /// Distinct from an empty `Error`: a caller has to be able to tell
    /// "done" from "the oracle said nothing".
    Done = 39,

    /// Import a block into `session`, answered with `Imported`.
    ///
    /// Distinct from the fuzz protocol's `ImportBlock`, which names no
    /// session and answers with a bare state root. The N1 lane compares
    /// three different roots and needs a refusal's wording, none of which
    /// fits in that answer, and it has to say which chain to import into
    /// rather than take whichever session happened to open first.
    ImportInto {
        session: SessionId,
        block: Vec<u8>,
    } = 40,
    /// What came of an import.
    ///
    /// The caller already holds the block, so the quantities it can read
    /// off the header -- the block's hash, its parent, the prior root the
    /// header declares -- are not repeated here. What it cannot compute is
    /// everything below: all of it comes from the engine.
    Imported {
        /// True when the block was accepted, which includes a block the
        /// chain already had.
        ok: bool,
        /// The block's posterior state root, when it was accepted.
        root: Option<[u8; 32]>,
        /// The reference's *own* posterior root for the block's parent,
        /// when it knows the parent at all.
        ///
        /// Not the root the header declares. The lane compares the two, and
        /// a header may declare a root for a parent this chain never had.
        parent_root: Option<[u8; 32]>,
        /// Why the block was refused, in the engine's words.
        error: Option<String>,
    } = 41,
    /// A state root the chain may or may not have, answering `StateRootOf`.
    ///
    /// `None` means the chain does not know that block. Answering `Error`
    /// for it -- as an earlier handler did -- makes "I have never seen this
    /// block" indistinguishable from "the engine failed", and a caller that
    /// cannot tell them apart treats a real failure as an absent block.
    StateRootIs(Option<[u8; 32]>) = 42,
    /// A session's full storage state at a block, answering `StateOf`.
    StateOf {
        session: SessionId,
        hash: [u8; 32],
    } = 43,
    /// The state, or `None` where the session does not have that block.
    StateIs(Option<WireState>) = 44,

    /// The dev chain spec's genesis, for a runner to patch into its own.
    ///
    /// The bootstrap-service blob that genesis state is built around lives
    /// inside the node crate, so this is the one thing a workspace without a
    /// node dependency cannot produce for itself. It is about 280 KB, once
    /// per run.
    ///
    /// Applies the tiny protocol parameters in the oracle before building,
    /// the same as `Open` with an empty path: the validator set is sized
    /// from the process-wide globals, so under the `full` default it would
    /// try to fit 1023 validators into the tiny bound of 6.
    DevSpec {
        base_port: u16,
    } = 45,
    /// The dev genesis, in the pieces a spec file is written from.
    DevSpecIs {
        /// Encoded `Header`.
        genesis_header: Vec<u8>,
        /// 31-byte key, value.
        keyvals: Vec<(Vec<u8>, Vec<u8>)>,
        /// Encoded `ProtocolParameters`, which a spec file carries so that
        /// whoever loads it is configured the way it was built.
        protocol_parameters: Vec<u8>,
    } = 46,

    /// Erasure-code a work-package bundle, as a guarantor does before
    /// serving CE 137/138.
    ///
    /// Session-free: coding is a pure function of the bytes and the shard
    /// count. What makes it the oracle's job is that the harness must get
    /// the *engine's* answer, not a second implementation of Reed-Solomon.
    CodeBundle {
        bundle: Vec<u8>,
        shard_count: u16,
    } = 47,
    /// The coded shards, with the two numbers a lane needs beside them.
    CodedBundle {
        shards: Vec<Vec<u8>>,
        /// How many shards reconstruct the bundle (`D(v)`), which for six
        /// validators is three and not two. DESIGN said two in both its
        /// parameter table and its N4 row.
        recovery_threshold: u16,
        /// The length every shard has, for a row that checks sizes without
        /// holding the shards.
        shard_len: u32,
    } = 48,

    /// Check a CE 137 or CE 138 reply the way a node checks one it was
    /// served.
    ///
    /// The whole reply travels, as the bytes that came off the wire, and the
    /// oracle does every step. Re-encoding the justification through this
    /// harness's own type would hide exactly the disagreement worth finding:
    /// if `jamnp-s` and the engine read that structure differently, the round
    /// trip would paper over it and the check would pass on bytes the node
    /// never sent.
    ///
    /// `protocol` rides along because the two differ in *where the segment
    /// root comes from*: CE 138 carries it as the last justification element,
    /// while CE 137 omits it and the reader must take the Merkle root of the
    /// segment shards instead. That is a rule both sides must apply
    /// identically, so it is applied in one place rather than by whoever
    /// happens to be calling.
    CheckServedShard {
        /// 137 or 138. Anything else is an error rather than a default.
        protocol: u16,
        erasure_root: [u8; 32],
        shard_index: u16,
        shard_count: u16,
        /// Hashed here, so the hash is the engine's own.
        bundle_shard: Vec<u8>,
        /// CE 137's segment shards, as the raw concatenation the wire
        /// carries. Empty for CE 138, which sends none.
        ///
        /// No slice length travels with them: the wire marks no boundary,
        /// but `jam_types::segment_slice_len` derives one from the shard
        /// count and both sides link it, so sending it would only create a
        /// way for the caller to disagree with the engine.
        segment_shards: Vec<u8>,
        justification: Vec<u8>,
    } = 49,
    /// Whether the justification proves that shard sits under that root.
    ///
    /// `None` where it could not be decoded at all, which is a different
    /// answer from "decoded and did not verify" and belongs in a different
    /// finding.
    ShardChecked {
        verified: Option<bool>,
        detail: Option<String>,
    } = 50,

    /// Erasure-code a work package's exported segments into per-validator
    /// segment shards, for CE 139/140.
    ///
    /// Each segment is `SEGMENT_LEN` (4104) bytes; anything else is an
    /// error rather than a truncation, because a segment of the wrong
    /// length codes into shards that are wrong in a way no later check
    /// would attribute to this.
    CodeSegments {
        segments: Vec<Vec<u8>>,
        shard_count: u16,
    } = 51,
    /// One shard per validator, each the concatenation of that validator's
    /// slice of every segment, in segment order.
    CodedSegments {
        shards: Vec<Vec<u8>>,
        /// The slice boundary within each shard: `SEGMENT_LEN / D(v)`, a
        /// property of the coding rather than a protocol constant, so it
        /// travels with the shards instead of being recomputed.
        slice_len: u32,
    } = 52,

    /// Check a CE 139/140 segment-shard justification, answered with
    /// `ShardChecked`.
    ///
    /// The justification is decoded by the engine's own
    /// `decode_segment_justification`, which needs the slice length to know
    /// where its elements end.
    CheckSegmentShard {
        erasure_root: [u8; 32],
        shard_index: u16,
        shard_count: u16,
        segment_index: u16,
        segment_count: u32,
        segment_slice: Vec<u8>,
        justification: Vec<u8>,
    } = 53,

    /// Build everything needed to *serve* a bundle's shards, the way a
    /// guarantor does once it has refined a package.
    ///
    /// The counterpart of [`Message::CheckServedShard`], and the half that
    /// was unreachable until `hazmat::merkle` was exported: `merkle_proofs`
    /// and `pack_erasure_tree_entry` are what turn coded shards into a root
    /// and per-shard proofs, and nothing outside `jam-node` could call them
    /// (findings.md §9). Without this a simulated node cannot serve CE
    /// 137/138/139/140 at all, and the rows that grade those protocols have
    /// never been shown to fail.
    MakeAvailable {
        bundle: Vec<u8>,
        /// Exported segments, `SEGMENT_LEN` bytes each.
        segments: Vec<Vec<u8>>,
        shard_count: u16,
    } = 54,
    /// One servable shard per validator, with the justifications each
    /// protocol carries.
    ///
    /// The justifications travel as the bytes the wire carries, not as a
    /// structure: their elements run back to back with no count, and a
    /// caller handed a decoded form would have to re-derive that layout to
    /// put them on a stream. Producing them here keeps the layout in the
    /// one place that already reads it.
    AvailableShards {
        erasure_root: [u8; 32],
        /// Per validator, in validator order.
        bundle_shards: Vec<Vec<u8>>,
        /// Per validator: that validator's slice of every segment,
        /// concatenated in segment order.
        segment_shards: Vec<Vec<u8>>,
        /// CE 137's justification per validator: the co-path alone, because
        /// the segment shards travel beside it and their root is theirs.
        shard_justifications: Vec<Vec<u8>>,
        /// CE 138's per validator: the same co-path with the segment root
        /// appended, which is where that protocol's reader takes it from.
        audit_justifications: Vec<Vec<u8>>,
        /// CE 140's, per validator and then per segment index.
        segment_justifications: Vec<Vec<Vec<u8>>>,
    } = 55,

    /// Put assurances into the session's pool, as a validator does with
    /// the ones its peers send it over CE 141.
    ///
    /// The counterpart of [`Message::SubmitTickets`], and the half of the
    /// assurance story that was unreachable until `submit_assurance` was
    /// exported: the engine could always sign its own assurance, and a
    /// harness could never hand it one. A node's assurances extrinsic
    /// carries what its *peers* sent it, so without this no simulated node
    /// can be shown to include a valid assurance or leave an invalid one
    /// out (findings.md §14).
    ///
    /// Taken as already verified, which is what the engine's entry point
    /// expects: the validator index is read off the connection and the
    /// signature checked before this point. Sending an assurance the caller
    /// has not checked is how a simulated node poses the fault of including
    /// one it should have refused.
    SubmitAssurances {
        session: SessionId,
        /// Encoded `AvailabilityAssurance`s.
        assurances: Vec<Vec<u8>>,
    } = 56,

    /// Build a package, optionally against an authorizer no core accepts.
    BuildPackage {
        session: SessionId,
        items: Vec<WireItem>,
        /// False builds against `Authorizer::any()`, whose code hash is
        /// zero, which is how the lane poses an unauthorized package.
        authorized: bool,
    } = 26,
    /// The package and the extrinsic bodies that go with it.
    Package {
        package: Vec<u8>,
        extrinsics: Vec<Vec<u8>>,
    } = 27,
    /// Build, refine and sign in one pass.
    GuaranteeWork {
        session: SessionId,
        items: Vec<WireItem>,
        core: u16,
    } = 28,
    /// Everything that one pass produces.
    GuaranteedWork {
        package: Vec<u8>,
        extrinsics: Vec<Vec<u8>>,
        report: Vec<u8>,
        bundle: Vec<u8>,
        guarantee: Vec<u8>,
    } = 29,
    /// The whole core-to-validators table at a slot, in one answer.
    ///
    /// One message rather than four. `guarantors_for`, `core_for` and their
    /// epoch-view counterparts are all derivable from the table, and a
    /// round trip each would put four on the slot-critical path.
    CoreAssignment {
        session: SessionId,
        slot: u32,
        view: AssignmentView,
    } = 30,
    /// Validators per core, indexed by core.
    ///
    /// `None` for a core the view cannot resolve -- which for the epoch
    /// view means the slot is outside the two epochs the chain holds, and
    /// so is every core's answer at that slot. Kept apart from `Some(vec![])`
    /// on purpose: "nobody holds this core" and "this slot is out of reach"
    /// read the same if they both arrive empty, and the caller that cannot
    /// tell them apart aims its submissions at a slot nothing will resolve
    /// and then reports the node's silence as a failure.
    Assignment(Vec<Option<Vec<u16>>>) = 31,
    /// The two epoch views and the entropy each shuffles with.
    ///
    /// Diagnostic, and the one message expected to be deleted: it exists
    /// for an open question about which assignment is authoritative.
    EpochProbe(SessionId) = 32,
    EpochProbed {
        cached_index: u32,
        head_epoch: u32,
        /// The entropy the *cached* epoch would shuffle with, which is the
        /// quantity the two views disagree about. Equal to `entropy_1` means
        /// the cache is an epoch behind; equal to neither entry means it was
        /// built from a state the chain has since moved past.
        cached_entropy: [u8; 32],
        /// Entries 1 and 2 of the best block's entropy buffer.
        entropy_1: [u8; 32],
        entropy_2: [u8; 32],
    } = 33,

    /// Posterior state root, the fuzz protocol's response to `ImportBlock`.
    StateRoot([u8; 32]) = 2,
    /// Key-value state, the response to `GetState`.
    State(Vec<(Vec<u8>, Vec<u8>)>) = 5,
    /// The oracle's verdict that something it was given was invalid.
    Error(String) = 255,
    /// The oracle itself failed: a panic, or a harness error.
    ///
    /// Separate from `Error` so a report can say "the oracle fell over"
    /// rather than attributing it to the node under test.
    OracleFault(String) = 254,
}

/// Handshake payload.
#[derive(Clone, Debug, Encode, Decode, PartialEq, Eq)]
pub struct PeerInfo {
    pub protocol_version: u16,
    /// The polkajam revision the oracle was built from, so the client can
    /// refuse an oracle that does not match the node under test.
    pub polkajam_revision: String,
    pub name: String,
}

/// Frame a message: `[len: u32 LE] ++ [body]`.
pub fn frame(message: &Message) -> Vec<u8> {
    let body = message.encode();
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("frame of {0} bytes is over the {MAX_MESSAGE_SIZE} byte limit")]
    TooLarge(u32),
    #[error("the frame is shorter than its length prefix claims")]
    Short,
    #[error("the frame body did not decode: {0}")]
    Malformed(String),
}

/// Read one framed message from the front of `input`, returning it and the
/// bytes that follow.
///
/// Strict about trailing bytes inside the frame: a body that decodes and
/// leaves bytes over is malformed, not merely longer than expected. The
/// same hole the CE 133 work-package codec had, and worth closing before
/// anything depends on it.
pub fn read_frame(input: &[u8]) -> Result<(Message, &[u8]), FrameError> {
    if input.len() < 4 {
        return Err(FrameError::Short);
    }
    let (prefix, rest) = input.split_at(4);
    let len = u32::from_le_bytes(prefix.try_into().expect("four bytes"));
    if len > MAX_MESSAGE_SIZE {
        return Err(FrameError::TooLarge(len));
    }
    let len = len as usize;
    if rest.len() < len {
        return Err(FrameError::Short);
    }
    let (body, tail) = rest.split_at(len);
    let mut cursor = body;
    let message = Message::decode(&mut cursor).map_err(|e| FrameError::Malformed(e.to_string()))?;
    if !cursor.is_empty() {
        return Err(FrameError::Malformed(
            "trailing bytes after the message".into(),
        ));
    }
    Ok((message, tail))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn every_message() -> Vec<Message> {
        let item = WireItem {
            service: 42,
            payload: vec![1, 2, 3],
            ref_gas: 1_000,
            acc_gas: 2_000,
            xts: vec![vec![0xaa], vec![]],
            imports: vec![vec![0xbb; 4]],
            export_count: 2,
        };
        vec![
            Message::PeerInfo(PeerInfo {
                protocol_version: PROTOCOL_VERSION,
                polkajam_revision: "e3d216c2".into(),
                name: "m2-oracle".into(),
            }),
            Message::ImportBlock(vec![0x01; 16]),
            Message::GetState([0x22; 32]),
            Message::Open {
                spec_path: "/tmp/spec.json".into(),
                now_slot: 10_711_224,
                holds: vec![0, 4, 5],
            },
            Message::Opened {
                session: 1,
                genesis_hash: [0x33; 32],
                genesis_slot: 9_780_000,
            },
            Message::Close(1),
            Message::AuthorBlock {
                session: 1,
                slot: 9_780_001,
            },
            Message::Authored(Some(vec![0x44; 8])),
            Message::Authored(None),
            Message::Head(1),
            Message::HeadIs {
                hash: [0x55; 32],
                slot: 9_780_002,
            },
            Message::ChainBlocks(1),
            Message::Blocks(vec![vec![0x66], vec![0x77, 0x88]]),
            Message::StateRootOf {
                session: 1,
                hash: [0x99; 32],
            },
            Message::BuildPackage {
                session: 1,
                items: vec![item.clone()],
                authorized: false,
            },
            Message::Package {
                package: vec![0xab; 48],
                extrinsics: vec![vec![1, 2], vec![3]],
            },
            Message::GuaranteeWork {
                session: 1,
                items: vec![item],
                core: 1,
            },
            Message::GuaranteedWork {
                package: vec![0xcd; 32],
                extrinsics: vec![vec![4]],
                report: vec![0xef; 16],
                bundle: vec![0x11; 64],
                guarantee: vec![0x22; 24],
            },
            Message::TicketCtx(1),
            Message::TicketContext {
                pks: vec![[0x01; 32], [0x02; 32]],
                entropy: [0x03; 32],
                epoch: 821_955,
            },
            Message::SignTickets {
                session: 1,
                author: Some(3),
                attempts: Some(vec![9]),
                pks: vec![[0x04; 32]],
                entropy: [0x05; 32],
            },
            Message::SignTickets {
                session: 1,
                author: None,
                attempts: None,
                pks: vec![[0x04; 32]],
                entropy: [0x05; 32],
            },
            Message::Tickets(vec![WireTicket {
                id: [0x06; 32],
                author: 3,
                attempt: 2,
                proof: vec![0x07; 784],
                proxy: 4,
            }]),
            Message::SubmitTickets {
                session: 1,
                envelopes: vec![vec![0x08; 16]],
            },
            Message::SubmitAssurances {
                session: 1,
                assurances: vec![vec![0x5b; 100], vec![0x5c; 100]],
            },
            Message::Done,
            Message::ImportInto {
                session: 2,
                block: vec![0x09; 32],
            },
            Message::Imported {
                ok: true,
                root: Some([0x0a; 32]),
                parent_root: Some([0x0b; 32]),
                error: None,
            },
            Message::StateRootIs(Some([0x0c; 32])),
            Message::StateOf {
                session: 3,
                hash: [0x0d; 32],
            },
            Message::StateIs(Some(WireState {
                root: [0x0e; 32],
                keyvals: vec![(vec![0x0f; 31], vec![0x10, 0x11])],
            })),
            Message::StateIs(None),
            Message::DevSpec { base_port: 40_000 },
            Message::CodeBundle {
                bundle: vec![0x17; 64],
                shard_count: 6,
            },
            Message::CodedBundle {
                shards: vec![vec![0x18; 8], vec![0x19; 8]],
                recovery_threshold: 3,
                shard_len: 8,
            },
            Message::CheckServedShard {
                protocol: 137,
                erasure_root: [0x1b; 32],
                shard_index: 2,
                shard_count: 6,
                bundle_shard: vec![0x1c; 8],
                segment_shards: vec![0x1d; 16],
                justification: vec![0x1e; 33],
            },
            Message::CheckServedShard {
                protocol: 138,
                erasure_root: [0x1b; 32],
                shard_index: 2,
                shard_count: 6,
                bundle_shard: vec![0x1c; 8],
                segment_shards: Vec::new(),
                justification: vec![0x1e; 66],
            },
            Message::ShardChecked {
                verified: Some(true),
                detail: None,
            },
            Message::CodeSegments {
                segments: vec![vec![0x1f; 4104]],
                shard_count: 6,
            },
            Message::CodedSegments {
                shards: vec![vec![0x20; 1368], vec![0x21; 1368]],
                slice_len: 1368,
            },
            Message::MakeAvailable {
                bundle: vec![0x26; 128],
                segments: vec![vec![0x27; 4104]],
                shard_count: 6,
            },
            Message::AvailableShards {
                erasure_root: [0x28; 32],
                bundle_shards: vec![vec![0x29; 8], vec![0x2a; 8]],
                segment_shards: vec![vec![0x2b; 16], vec![0x2c; 16]],
                shard_justifications: vec![vec![0x2d; 33], vec![0x2e; 33]],
                audit_justifications: vec![vec![0x2f; 66], vec![0x30; 66]],
                segment_justifications: vec![vec![vec![0x31; 34]], vec![vec![0x32; 34]]],
            },
            Message::CheckSegmentShard {
                erasure_root: [0x23; 32],
                shard_index: 1,
                shard_count: 6,
                segment_index: 0,
                segment_count: 1,
                segment_slice: vec![0x24; 1368],
                justification: vec![0x25; 34],
            },
            Message::ShardChecked {
                verified: None,
                detail: Some("the justification did not decode".into()),
            },
            Message::DevSpecIs {
                genesis_header: vec![0x12; 8],
                keyvals: vec![(vec![0x13; 31], vec![0x14, 0x15])],
                protocol_parameters: vec![0x16; 4],
            },
            Message::StateRootIs(None),
            Message::Imported {
                ok: false,
                root: None,
                parent_root: None,
                error: Some("obsolete".into()),
            },
            Message::CoreAssignment {
                session: 1,
                slot: 9_780_003,
                view: AssignmentView::Epoch,
            },
            Message::Assignment(vec![Some(vec![0, 4, 5]), Some(vec![1, 2, 3])]),
            Message::EpochProbe(1),
            Message::EpochProbed {
                cached_index: 815_083,
                head_epoch: 815_083,
                cached_entropy: [0xee; 32],
                entropy_1: [0xee; 32],
                entropy_2: [0xbb; 32],
            },
            Message::StateRoot([0x77; 32]),
            Message::State(vec![(vec![0x01; 31], vec![0xff; 4])]),
            Message::Error("block rejected".into()),
            Message::OracleFault("harness panicked".into()),
        ]
    }

    #[test]
    fn every_message_round_trips_through_a_frame() {
        for message in every_message() {
            let wire = frame(&message);
            let (decoded, rest) = read_frame(&wire).expect("the frame reads");
            assert_eq!(decoded, message, "round trip changed the message");
            assert!(rest.is_empty(), "one frame leaves nothing over");
        }
    }

    /// Frames are self-delimiting, so a reader can take them back to back.
    #[test]
    fn frames_can_be_read_back_to_back() {
        let messages = every_message();
        let mut wire = Vec::new();
        for message in &messages {
            wire.extend_from_slice(&frame(message));
        }
        let mut rest: &[u8] = &wire;
        for expected in &messages {
            let (decoded, tail) = read_frame(rest).expect("each frame reads");
            assert_eq!(&decoded, expected);
            rest = tail;
        }
        assert!(rest.is_empty());
    }

    /// The tags the fuzz protocol already defines keep their meaning, so a
    /// reader of one does not mistake a message of the other.
    #[test]
    fn the_fuzz_protocol_tags_are_unchanged() {
        for (message, tag) in [
            (
                Message::PeerInfo(PeerInfo {
                    protocol_version: 1,
                    polkajam_revision: String::new(),
                    name: String::new(),
                }),
                0u8,
            ),
            (Message::StateRoot([0; 32]), 2),
            (Message::ImportBlock(Vec::new()), 3),
            (Message::GetState([0; 32]), 4),
            (Message::State(Vec::new()), 5),
            (Message::Error(String::new()), 255),
        ] {
            assert_eq!(
                message.encode()[0],
                tag,
                "{message:?} must keep the fuzz protocol's tag"
            );
        }
    }

    /// M2's own messages start at 16, so they cannot collide with the fuzz
    /// protocol's 0 to 5 however either set grows.
    #[test]
    fn the_m2_messages_start_above_the_fuzz_ones() {
        for message in every_message() {
            let tag = message.encode()[0];
            assert!(
                tag <= 5 || tag >= 16,
                "{message:?} has tag {tag}, in the gap reserved for the fuzz protocol"
            );
        }
    }

    /// An internal failure is not the same message as a rejected block. A
    /// report that could not tell them apart would blame the node under
    /// test for the oracle falling over.
    #[test]
    fn an_oracle_fault_is_not_an_error() {
        let fault = Message::OracleFault("panicked".into());
        let error = Message::Error("panicked".into());
        assert_ne!(fault.encode()[0], error.encode()[0]);
        assert_ne!(fault, error);
    }

    #[test]
    fn a_truncated_frame_is_short_not_malformed() {
        let wire = frame(&Message::GetState([0x11; 32]));
        assert_eq!(read_frame(&wire[..3]), Err(FrameError::Short));
        assert_eq!(
            read_frame(&wire[..wire.len() - 1]),
            Err(FrameError::Short),
            "a body shorter than its prefix claims is short, not malformed"
        );
    }

    /// Trailing bytes inside a frame are malformed. `Decode` stops at the
    /// end of the value it understands, so without the check a sender could
    /// append anything and the frame would still be accepted -- the same
    /// hole the CE 133 work-package codec had.
    #[test]
    fn trailing_bytes_inside_a_frame_are_rejected() {
        let message = Message::GetState([0x11; 32]);
        let body = message.encode();
        let mut wire = ((body.len() + 1) as u32).to_le_bytes().to_vec();
        wire.extend_from_slice(&body);
        wire.push(0xff);
        assert!(matches!(read_frame(&wire), Err(FrameError::Malformed(_))));
    }

    #[test]
    fn a_frame_over_the_limit_is_refused_before_it_is_read() {
        let mut wire = (MAX_MESSAGE_SIZE + 1).to_le_bytes().to_vec();
        wire.extend_from_slice(&[0u8; 8]);
        assert_eq!(
            read_frame(&wire),
            Err(FrameError::TooLarge(MAX_MESSAGE_SIZE + 1)),
            "the length prefix alone decides, before anything is allocated"
        );
    }
}
