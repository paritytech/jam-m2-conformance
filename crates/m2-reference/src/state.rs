//! N1 state snapshot/diff oracle: dumps the reference chain's storage trie at
//! a block hash as a typed `State` and diffs two states key-by-key.

use std::collections::HashMap;

use m2_oracle_proto::Message;

use crate::chain::{ChainError, RefChain};

/// A single storage key-value pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyValue {
    pub key: [u8; 31],
    pub value: Vec<u8>,
}

/// Full storage snapshot (root hash + all key-value pairs) at a block hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub root: [u8; 32],
    pub keyvals: Vec<KeyValue>,
}

/// Difference of a single key between an expected and a received state.
///
/// A key missing on one side is represented by an empty `exp`/`got` slice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyValueDiff {
    pub key: [u8; 31],
    pub exp: Vec<u8>,
    pub got: Vec<u8>,
}

/// Difference between an expected and a received state: the two roots plus
/// the union of keys whose values differ.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateDiff {
    pub exp_root: [u8; 32],
    pub got_root: [u8; 32],
    pub keyvals: Vec<KeyValueDiff>,
}

impl RefChain {
    /// Snapshot the full storage state at the given block hash, or `None`
    /// where the chain does not have that block.
    ///
    /// Root and keys arrive together, from one storage view in the oracle.
    /// Asking for them separately could land either side of an import, and a
    /// root that does not belong to the keys beside it is the one failure
    /// [`diff`] cannot detect -- disagreeing is exactly what it expects to
    /// find.
    pub fn storage_state(&self, hash: &[u8; 32]) -> Result<Option<State>, ChainError> {
        let wire = match self.ask(Message::StateOf {
            session: self.session(),
            hash: *hash,
        })? {
            Message::StateIs(state) => state,
            other => return Err(ChainError::Oracle(format!("StateOf answered {other:?}"))),
        };
        let Some(wire) = wire else { return Ok(None) };
        let mut keyvals = Vec::with_capacity(wire.keyvals.len());
        for (key, value) in wire.keyvals {
            let key: [u8; 31] = key.as_slice().try_into().map_err(|_| {
                ChainError::Oracle(format!("a state key is {} bytes, not 31", key.len()))
            })?;
            keyvals.push(KeyValue { key, value });
        }
        Ok(Some(State {
            root: wire.root,
            keyvals,
        }))
    }

    /// Whether `service` is still waiting for `blob`'s preimage, read from
    /// the chain's own state at its best block.
    ///
    /// N6's announcement row needs this and nothing weaker. A node may only
    /// ask for a preimage the chain has asked for (`simple.md:705-707`), so
    /// announcing before the request exists grades the node on a request it
    /// had no reason to make. The lane used to approximate that with "a
    /// block carries the soliciting package, plus two slots" -- but a
    /// package reaches a block at *inclusion*, and the request only exists
    /// once the package has **accumulated**, which waits on availability.
    /// The gap between the two is not a constant: it moved from one slot to
    /// five across three runs that differed only in validator index, which
    /// is what made `n6_ce143_requested_after_announcement` look
    /// index-dependent (`findings.md` §41).
    ///
    /// Asking the state is not an approximation of the condition, it *is*
    /// the condition -- the same key the node reads before deciding whether
    /// to follow up.
    ///
    /// A request is keyed on `(service, hash, len)` and its value is the
    /// sequence of slots the preimage has been available over. Empty means
    /// asked for and not yet provided, which is the only state in which the
    /// node should answer an announcement. A key that is absent (never
    /// solicited) and one whose sequence is non-empty (already provided)
    /// both answer `false`, and for this lane's purpose they mean the same
    /// thing: do not announce yet.
    pub fn preimage_requested(&self, service: u32, blob: &[u8]) -> Result<bool, ChainError> {
        let (head, _) = self.best_block()?;
        let Some(state) = self.storage_state(&head)? else {
            return Ok(false);
        };
        let key: jam_std_common::StorageKey = jam_std_common::ServiceKey::Request {
            id: service,
            len: blob.len() as u32,
            hash: jam_std_common::hash_raw(blob),
        }
        .into();
        let Some(kv) = state.keyvals.iter().find(|kv| kv.key == key.0) else {
            return Ok(false);
        };
        // The bound is three slots and the encoding is a plain sequence, so
        // `Vec<u32>` decodes it. Decoded rather than compared against the
        // one byte an empty sequence encodes to: a value that does not
        // decode is a key this harness has misidentified, and that should
        // read as "not requested" rather than as "requested".
        let slots: Vec<u32> = match jam_types::Decode::decode(&mut kv.value.as_slice()) {
            Ok(slots) => slots,
            Err(_) => return Ok(false),
        };
        Ok(slots.is_empty())
    }
}

/// Diff two states: compare roots and report every key whose value differs
/// across the union of keys (missing side = empty).
pub fn diff(exp: &State, got: &State) -> StateDiff {
    let exp_vals: HashMap<[u8; 31], &[u8]> = exp
        .keyvals
        .iter()
        .map(|kv| (kv.key, kv.value.as_slice()))
        .collect();
    let got_vals: HashMap<[u8; 31], &[u8]> = got
        .keyvals
        .iter()
        .map(|kv| (kv.key, kv.value.as_slice()))
        .collect();
    let mut keys: Vec<[u8; 31]> = exp_vals.keys().chain(got_vals.keys()).copied().collect();
    keys.sort_unstable();
    keys.dedup();
    let keyvals = keys
        .into_iter()
        .filter_map(|key| {
            let exp_val = exp_vals.get(&key).copied().unwrap_or(&[]);
            let got_val = got_vals.get(&key).copied().unwrap_or(&[]);
            (exp_val != got_val).then(|| KeyValueDiff {
                key,
                exp: exp_val.to_vec(),
                got: got_val.to_vec(),
            })
        })
        .collect();
    StateDiff {
        exp_root: exp.root,
        got_root: got.root,
        keyvals,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::ChainError;
    use crate::oracle::Oracle;

    #[test]
    fn state_snapshot_root_matches_storage_root() -> Result<(), ChainError> {
        let chain = RefChain::tiny(&Oracle::for_tests(), 0)?;
        let start = chain.next_slot();
        let mut authored = 0;
        for slot in start..start + 24 {
            if chain.author_block(slot)?.is_some() {
                authored += 1;
                if authored == 2 {
                    break;
                }
            }
        }
        assert_eq!(authored, 2, "expected two emulated slots within 24 slots");

        let genesis = chain.genesis_hash();
        let genesis_state = chain.storage_state(&genesis)?.expect("genesis has state");
        assert_eq!(
            Some(genesis_state.root),
            chain.storage_root(&genesis)?,
            "the snapshot's root is the chain's own for that block"
        );
        assert!(
            !genesis_state.keyvals.is_empty(),
            "genesis state has key-value pairs"
        );

        let best = chain
            .chain_blocks()?
            .last()
            .expect("authored head block")
            .header
            .hash()
            .0;
        let best_state = chain.storage_state(&best)?.expect("head has state");
        assert_eq!(Some(best_state.root), chain.storage_root(&best)?);
        assert!(
            !best_state.keyvals.is_empty(),
            "head state has key-value pairs"
        );
        Ok(())
    }

    #[test]
    fn state_diff_reports_root_and_key_mismatch() -> Result<(), ChainError> {
        let chain = RefChain::tiny(&Oracle::for_tests(), 0)?;
        let start = chain.next_slot();
        for slot in start..start + 24 {
            if chain.author_block(slot)?.is_some() {
                break;
            }
        }
        let best = chain
            .chain_blocks()?
            .last()
            .expect("authored head block")
            .header
            .hash()
            .0;
        let state_a = chain.storage_state(&best)?.expect("head has state");
        let state_b = chain.storage_state(&best)?.expect("head has state");

        let equal = diff(&state_a, &state_b);
        assert_eq!(equal.exp_root, equal.got_root);
        assert!(
            equal.keyvals.is_empty(),
            "identical snapshots have no key diffs"
        );

        let mut corrupt = state_b.clone();
        assert!(
            !corrupt.keyvals.is_empty(),
            "snapshot has key-value pairs to corrupt"
        );
        let victim = corrupt.keyvals[0].key;
        let got_value = vec![corrupt.keyvals[0].value[0] ^ 0xff];
        corrupt.keyvals[0].value = got_value.clone();
        let unequal = diff(&state_a, &corrupt);
        assert_eq!(
            unequal.exp_root, unequal.got_root,
            "manual keyval edit leaves roots equal"
        );
        assert_eq!(unequal.keyvals.len(), 1, "exactly one key differs");
        assert_eq!(unequal.keyvals[0].key, victim);
        assert_eq!(unequal.keyvals[0].got, got_value);
        Ok(())
    }
}
