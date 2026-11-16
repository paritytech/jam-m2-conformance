//! P0 chain-authoring oracle: a reference chain over polkajam's authoring
//! harness, authoring blocks for every emulated validator and skipping the
//! NUT's slots.
//!
//! The harness itself runs in the oracle process (see [`crate::oracle`]).
//! This is a client of it: one session, one chain, and the same method
//! signatures the in-process version had, so a lane cannot tell the
//! difference and cannot reach past the oracle into the engine.

use std::sync::Arc;

use jam_std_common::Block;
use jam_types::Decode;
use m2_oracle_proto::{Message, SessionId};

use crate::oracle::Oracle;

/// Slot duration in seconds (tiny and full both use 6 s).
const SLOT_PERIOD_SEC: u64 = 6;

/// Errors raised by the reference-chain oracle.
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    /// The hazmat authoring harness failed.
    #[error("harness error: {0}")]
    Harness(String),
    /// The underlying reference chain rejected an operation.
    #[error("chain error: {0}")]
    Chain(String),
    /// A block could not be imported into the reference chain.
    #[error("import error: {0}")]
    Import(String),
    /// A safrole ticket operation failed.
    #[error("tickets error: {0}")]
    Tickets(String),
    /// The oracle itself failed: the socket, the handshake, or a reply that
    /// makes no sense.
    ///
    /// Kept apart from [`ChainError::Chain`], which is the engine refusing
    /// something and so an answer. A lane that could not tell them apart
    /// would read a broken oracle as a node that misbehaved.
    #[error("oracle error: {0}")]
    Oracle(String),
}

/// Current wall-clock slot (`(now - JAM_COMMON_ERA) / 6`).
///
/// "Now" is the installed clock's, not the machine's: the slot a run is in has
/// to be the same number the trace's timestamps say, or the lanes would grade
/// frames against a calendar nothing else is keeping.
pub fn wall_clock_slot() -> u32 {
    let now = jamnp_s::clock::current().wall_ms() / 1000;
    (now.saturating_sub(jam_types::JAM_COMMON_ERA) / SLOT_PERIOD_SEC) as u32
}

/// The millisecond `slot` begins, on the same calendar as [`wall_clock_slot`].
pub fn slot_start_ms(slot: u32) -> u64 {
    (jam_types::JAM_COMMON_ERA + u64::from(slot) * SLOT_PERIOD_SEC) * 1000
}

/// First slot of the current epoch.
///
/// polkajam gates ticket acceptance and authoring on the finalized block being
/// in the *current* epoch, which a genesis at slot 0 can never satisfy. See the
/// ignored `genesis_is_anchored_to_the_current_epoch` test in `m2-runner`.
pub fn current_epoch_start_slot() -> u32 {
    let now = wall_clock_slot();
    now - (now % jam_types::epoch_period())
}

/// Reference chain over the polkajam hazmat authoring harness.
///
/// Wraps a virtual-time `AuthoringHarness` that only claims slots whose author
/// key it holds. With every keyset but the NUT's loaded, the NUT's slots are
/// skipped by the harness itself and every other slot is authored.
pub struct RefChain {
    /// The connection, shared with every other chain in the run.
    ///
    /// The lock that used to sit around the harness now sits inside the
    /// connection, and for the same reason: the emulator serves CE 128/129
    /// from an `Arc<RefChain>` on several tasks at once while the slot driver
    /// authors into the same chain. Keeping it *inside* means every lock is
    /// held for one request; an `Arc<Mutex<RefChain>>` at the call sites
    /// would instead put a guard into the emulator's async serve paths, where
    /// holding one across an `.await` is a deadlock and `Send` hazard.
    oracle: Arc<Oracle>,
    /// This chain's session. Two chains share the connection and are told
    /// apart by this.
    session: SessionId,
    genesis_slot: u32,
    genesis_hash: [u8; 32],
}

impl RefChain {
    /// Build the 6-validator tiny reference chain emulating every validator
    /// except `nut_index`.
    ///
    /// Validator `i` holds `SecretKeyset::trivial(i)` (`keygen::generate`), so
    /// the session holds those keysets for every index but the NUT's. The
    /// chain spec is the dev spec with the 6-validator tiny set, genesis at
    /// slot 0, which the oracle opens when it is given no spec path.
    ///
    /// A live run uses [`RefChain::with_spec`] instead, so the reference engine
    /// and the node under test start from one and the same genesis.
    pub fn tiny(oracle: &Arc<Oracle>, nut_index: usize) -> Result<Self, ChainError> {
        Self::tiny_with(oracle, |i| i != nut_index, nut_index)
    }

    /// A chain holding **only** validator `index`'s keys: what a node holds,
    /// rather than what the harness holds.
    ///
    /// The difference is not cosmetic. An authoring harness runs the Safrole
    /// lottery for every key in its keystore and puts the results in the
    /// blocks it authors, so a chain built the other way round -- every key
    /// but one -- authors blocks carrying five validators' tickets. A node
    /// simulated on such a chain looks, to the lane grading it, like one
    /// inventing tickets nobody sent it.
    pub fn tiny_for(oracle: &Arc<Oracle>, index: usize) -> Result<Self, ChainError> {
        Self::tiny_with(oracle, |i| i == index, index)
    }

    /// Build the reference chain on the spec file at `spec_path`.
    ///
    /// The node under test is started from a spec the runner builds, carrying
    /// the real validator addresses and, for a live run, a genesis anchored to
    /// the current epoch. The reference engine has to start from that same
    /// spec: the anchor slot is part of the genesis header preimage, so a
    /// reference chain left on the slot-0 dev spec would disagree with the node
    /// about the genesis hash, and every UP 0 handshake would mismatch.
    ///
    /// A *path*, not a spec: the oracle is another process, and the one way
    /// to be sure the two start from the same genesis is for both to read the
    /// same bytes off disk. The file also carries the protocol parameters,
    /// which the oracle applies to itself as it loads it.
    pub fn with_spec(
        oracle: &Arc<Oracle>,
        nut_index: usize,
        spec_path: &std::path::Path,
    ) -> Result<Self, ChainError> {
        let validator_count = jam_types::max_val_count() as usize;
        if nut_index >= validator_count {
            return Err(ChainError::Chain(format!(
                "validator index {nut_index} is outside the {validator_count}-validator set"
            )));
        }
        let path = spec_path.to_str().ok_or_else(|| {
            ChainError::Chain(format!("spec path {} is not utf-8", spec_path.display()))
        })?;
        let holds = (0..validator_count as u16)
            .filter(|i| *i as usize != nut_index)
            .collect();
        Self::open(oracle, path, holds)
    }

    /// The tiny dev spec, holding whichever indices `holds` accepts.
    fn tiny_with(
        oracle: &Arc<Oracle>,
        holds: impl Fn(usize) -> bool,
        named_index: usize,
    ) -> Result<Self, ChainError> {
        // The client needs them too, and for its own reasons: it reads
        // `max_val_count`, `epoch_period` and the rest out of the same
        // process-wide globals. Those do not travel over the socket -- the
        // oracle applies its own copy as it opens the session -- so a client
        // left on the `full` default would plan a 1023-validator run against
        // a 6-validator chain.
        jam_types::ProtocolParameters::tiny().apply().map_err(|e| {
            ChainError::Chain(format!("failed to apply tiny protocol parameters: {e}"))
        })?;
        let validator_count = jam_types::max_val_count() as usize;
        if named_index >= validator_count {
            return Err(ChainError::Chain(format!(
                "validator index {named_index} is outside the {validator_count}-validator set"
            )));
        }
        let held = (0..validator_count as u16)
            .filter(|i| holds(*i as usize))
            .collect();
        // An empty path is the oracle's own name for the default dev spec.
        Self::open(oracle, "", held)
    }

    fn open(oracle: &Arc<Oracle>, spec_path: &str, holds: Vec<u16>) -> Result<Self, ChainError> {
        let (session, genesis_hash, genesis_slot) = oracle.open(spec_path, holds)?;
        Ok(Self {
            oracle: oracle.clone(),
            session,
            genesis_slot,
            genesis_hash,
        })
    }

    /// Send one request about this chain's session.
    pub(crate) fn ask(&self, request: Message) -> Result<Message, ChainError> {
        self.oracle.expect(request)
    }

    /// This chain's session id, for a request built elsewhere in the crate.
    pub(crate) fn session(&self) -> SessionId {
        self.session
    }

    /// The connection, for a sibling oracle that needs one of its own.
    pub fn oracle(&self) -> &Arc<Oracle> {
        &self.oracle
    }

    /// Hash of the genesis header.
    pub fn genesis_hash(&self) -> [u8; 32] {
        self.genesis_hash
    }

    /// Slot the chain's genesis is anchored to (A9), which is where authoring
    /// starts rather than slot 0.
    pub fn genesis_slot(&self) -> u32 {
        self.genesis_slot
    }

    /// Current wall-clock slot (`(now - JAM_COMMON_ERA) / 6`).
    pub fn next_slot(&self) -> u32 {
        wall_clock_slot()
    }

    /// Slot of the chain's current best block.
    ///
    /// The slot driver needs it because the chain head no longer moves only
    /// when the driver authors: a NUT block adopted into the chain can put the
    /// head at a slot the driver is about to try, and [`RefChain::author_block`]
    /// refuses to author at or behind the head.
    pub fn best_slot(&self) -> Result<u32, ChainError> {
        match self.ask(Message::Head(self.session))? {
            Message::HeadIs { slot, .. } => Ok(slot),
            other => Err(ChainError::Oracle(format!("Head answered {other:?}"))),
        }
    }

    /// Hash and slot of the chain's current best block.
    pub fn best_block(&self) -> Result<([u8; 32], u32), ChainError> {
        match self.ask(Message::Head(self.session))? {
            Message::HeadIs { hash, slot } => Ok((hash, slot)),
            other => Err(ChainError::Oracle(format!("Head answered {other:?}"))),
        }
    }

    /// Advance virtual time to `slot` and author a block there if the slot
    /// belongs to an emulated validator; `None` when the author is the NUT.
    pub fn author_block(&self, slot: u32) -> Result<Option<Block>, ChainError> {
        match self.ask(Message::AuthorBlock {
            session: self.session,
            slot,
        })? {
            Message::Authored(Some(encoded)) => Ok(Some(decode_block(&encoded)?)),
            Message::Authored(None) => Ok(None),
            other => Err(ChainError::Oracle(format!(
                "AuthorBlock answered {other:?}"
            ))),
        }
    }

    /// The reference chain (genesis + authored blocks) in order.
    pub fn chain_blocks(&self) -> Result<Vec<Block>, ChainError> {
        match self.ask(Message::ChainBlocks(self.session))? {
            Message::Blocks(blocks) => blocks.iter().map(|b| decode_block(b)).collect(),
            other => Err(ChainError::Oracle(format!(
                "ChainBlocks answered {other:?}"
            ))),
        }
    }

    /// State root for the block with the given hash, or `None` where the
    /// chain does not have that block.
    pub fn storage_root(&self, hash: &[u8; 32]) -> Result<Option<[u8; 32]>, ChainError> {
        match self.ask(Message::StateRootOf {
            session: self.session,
            hash: *hash,
        })? {
            Message::StateRootIs(root) => Ok(root),
            other => Err(ChainError::Oracle(format!(
                "StateRootOf answered {other:?}"
            ))),
        }
    }
}

impl Drop for RefChain {
    /// Close the session.
    ///
    /// A session owns an authoring harness, and that owns a database
    /// directory, so an oracle that is never told a chain is finished
    /// accumulates one per chain that ever existed. A test binary opens
    /// dozens against the one oracle it shares.
    ///
    /// The result is dropped on purpose: a chain going away while the
    /// oracle is already gone is the ordinary end of a run, not a failure
    /// to report -- and there is nowhere to report it from here anyway.
    fn drop(&mut self) {
        let _ = self.oracle.request(Message::Close(self.session));
    }
}

/// A block as it came off the wire.
///
/// Trailing bytes are a failure, not a block with something after it: the
/// oracle encodes exactly one block per answer, so anything left over means
/// the two sides disagree about the encoding and every field read out of it
/// is suspect.
pub(crate) fn decode_block(encoded: &[u8]) -> Result<Block, ChainError> {
    let mut cursor = encoded;
    let block = Block::decode(&mut cursor)
        .map_err(|e| ChainError::Oracle(format!("a block did not decode: {e}")))?;
    if !cursor.is_empty() {
        return Err(ChainError::Oracle(format!(
            "a block came back with {} trailing bytes",
            cursor.len()
        )));
    }
    Ok(block)
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::oracle::Oracle;

    use super::*;

    // The tests that exercised the engine -- that a session authors only for
    // the validators it holds, that two sessions on one spec author the same
    // blocks, that the genesis state root is the first block's declared
    // prior -- live in the oracle crate now, next to the engine they are
    // about. What is left here is this crate's own: the wall clock, and
    // refusing a validator index that is not one.

    #[test]
    fn next_slot_tracks_wall_clock() -> Result<(), ChainError> {
        let chain = RefChain::tiny(&Oracle::for_tests(), 0)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the unix epoch")
            .as_secs();
        let expected = ((now - jam_types::JAM_COMMON_ERA) / SLOT_PERIOD_SEC) as u32;
        assert!(chain.next_slot().abs_diff(expected) <= 1);
        Ok(())
    }

    #[test]
    fn nut_index_outside_the_keyset_is_rejected() {
        jam_types::ProtocolParameters::tiny()
            .apply()
            .expect("tiny parameters are valid");
        let count = jam_types::max_val_count() as usize;
        assert!(
            RefChain::tiny(&Oracle::for_tests(), count).is_err(),
            "a NUT index of {count} is outside the keyset and would leave every \
             validator keyset loaded"
        );
    }
}
