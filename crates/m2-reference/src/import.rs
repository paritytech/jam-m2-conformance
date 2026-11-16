//! N1 block-import oracle: imports a NUT-authored block into the reference
//! chain with fresh execution and reports the outcome (post-state root or
//! the rejected-import error message).

use jam_std_common::Block;
use m2_oracle_proto::Message;

use crate::chain::{ChainError, RefChain};

/// Outcome of importing a NUT block into the reference chain.
///
/// Carries both state roots the N1 lane needs, which are different quantities
/// and neither of which is the header hash: `declared_parent_root` is what the
/// block's header claims its parent's posterior root was, and
/// `reference_parent_root` is what the reference engine computed for that same
/// parent. `root` is the reference's posterior root for *this* block, which
/// only a block built on top of it can be checked against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportOutcome {
    /// Hash of the imported block's header.
    pub header_root: [u8; 32],
    /// Hash of the block's parent (`header.parent`).
    pub parent: [u8; 32],
    /// Prior state root the block's header declares (`header.parent_state_root`).
    pub declared_parent_root: [u8; 32],
    /// The reference engine's own posterior state root for the parent, when it
    /// knows the parent at all.
    pub reference_parent_root: Option<[u8; 32]>,
    /// `true` when the block was accepted (imported or already imported).
    pub ok: bool,
    /// Posterior state root of the block when accepted.
    pub root: Option<[u8; 32]>,
    /// Human-readable rejection reason when the block was refused.
    pub error: Option<String>,
}

impl RefChain {
    /// Import a NUT-authored block into the reference chain by fresh execution.
    ///
    /// On success the block joins the reference chain, and because polkajam
    /// picks its best block by highest slot it also becomes the head the
    /// reference authors on next. That is deliberate: a reference that keeps
    /// authoring on its own head instead forks away from the node at every
    /// slot the node claims, and then nothing ever builds on a NUT block, so
    /// no block's posterior state root is ever witnessed.
    ///
    /// Three of the outcome's seven fields are read off the block itself
    /// rather than asked for: the caller already holds it, and the oracle
    /// would only be decoding the same bytes.
    pub fn import_nut_block(&self, block: &Block) -> Result<ImportOutcome, ChainError> {
        let header_root = block.header.hash().0;
        let (ok, root, parent_root, error) = match self.ask(Message::ImportInto {
            session: self.session(),
            block: jam_types::Encode::encode(block),
        })? {
            Message::Imported {
                ok,
                root,
                parent_root,
                error,
            } => (ok, root, parent_root, error),
            other => return Err(ChainError::Oracle(format!("ImportInto answered {other:?}"))),
        };
        Ok(ImportOutcome {
            header_root,
            parent: block.header.parent.0,
            declared_parent_root: block.header.parent_state_root.0,
            reference_parent_root: parent_root,
            ok,
            root,
            error,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracle::Oracle;

    // What an import *does* -- accepting a block, refusing a corrupt body,
    // re-accepting one it already has -- is tested in the oracle crate,
    // against the engine. What is this crate's own is the mapping below:
    // three of `ImportOutcome`'s seven fields are read off the block here
    // rather than asked for, and reading them off the wrong thing is easy
    // and silent. A header hash and a state root are both 32 bytes.
    #[test]
    fn the_outcome_describes_the_block_it_was_given() -> Result<(), ChainError> {
        let oracle = Oracle::for_tests();
        let author = RefChain::tiny(&oracle, 0)?;
        // A session that has not seen the block, so the import is a real one
        // rather than a short-circuit on a hash the chain already holds.
        let importer = RefChain::tiny_for(&oracle, 0)?;

        let start = author.next_slot();
        let mut block = None;
        for slot in start..start + 24 {
            if let Some(authored) = author.author_block(slot)? {
                block = Some(authored);
                break;
            }
        }
        let block = block.expect("an emulated slot appears within 24 slots");

        let outcome = importer.import_nut_block(&block)?;
        assert!(outcome.ok, "a reference block imports: {:?}", outcome.error);
        assert_eq!(outcome.header_root, block.header.hash().0);
        assert_eq!(outcome.parent, block.header.parent.0);
        assert_eq!(
            outcome.declared_parent_root,
            block.header.parent_state_root.0
        );
        assert_eq!(
            outcome.reference_parent_root,
            Some(outcome.declared_parent_root),
            "a well-formed block's declared prior root is the reference's own"
        );
        assert_ne!(
            outcome.root,
            Some(outcome.header_root),
            "the posterior state root is not the header hash"
        );
        Ok(())
    }
}
