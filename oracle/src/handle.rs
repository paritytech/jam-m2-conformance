//! One handler per message, each the body of a `RefChain` method.
//!
//! Every handler is infallible from the caller's side: a failure comes back
//! as a message, never as a dropped connection. Which message it is matters
//! — `Error` is the oracle's verdict on something it was given, and
//! `OracleFault` is the oracle itself falling over. A report that could not
//! tell them apart would blame the node under test for a harness crash.

use codec::{Decode, Encode};
use m2_oracle_proto::{AssignmentView, Message, PeerInfo, PROTOCOL_VERSION};

use crate::session::Sessions;

/// The polkajam revision this binary was built from.
///
/// Set by the build so a client can refuse an oracle that does not match the
/// node under test. The same-revision rule is the whole basis for trusting
/// the oracle's answers.
pub const POLKAJAM_REVISION: &str = env!("ORACLE_POLKAJAM_REV");

/// Answer one request.
///
/// Panics are caught per request rather than per connection: a `hazmat`
/// panic is documented as possible, and taking the whole run down with it
/// would lose every lane's results rather than one message's.
pub fn answer(sessions: &mut Sessions, request: Message) -> Message {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| dispatch(sessions, request))) {
        Ok(reply) => reply,
        Err(panic) => Message::OracleFault(describe_panic(&panic)),
    }
}

fn describe_panic(panic: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = panic.downcast_ref::<&str>() {
        format!("the oracle panicked: {s}")
    } else if let Some(s) = panic.downcast_ref::<String>() {
        format!("the oracle panicked: {s}")
    } else {
        "the oracle panicked".to_string()
    }
}

fn dispatch(sessions: &mut Sessions, request: Message) -> Message {
    match request {
        Message::PeerInfo(_) => Message::PeerInfo(PeerInfo {
            protocol_version: PROTOCOL_VERSION,
            polkajam_revision: POLKAJAM_REVISION.to_string(),
            name: "m2-oracle".to_string(),
        }),

        Message::Open { spec_path, holds } => match sessions.open(&spec_path, &holds) {
            Ok(session) => {
                let opened = sessions.get_mut(session).expect("just opened");
                let (genesis_hash, genesis_slot) = (opened.genesis_hash, opened.genesis_slot);
                // Virtual time: the harness starts at the current slot, the
                // way `RefChain` seeds it, or everything it authors is
                // millions of slots in the past.
                let next = crate::wall_clock_slot();
                opened.harness.next_slot = next;
                Message::Opened {
                    session,
                    genesis_hash,
                    genesis_slot,
                }
            }
            Err(e) => Message::OracleFault(e),
        },

        Message::Close(session) => {
            sessions.close(session);
            Message::Opened {
                session,
                genesis_hash: [0; 32],
                genesis_slot: 0,
            }
        }

        Message::AuthorBlock { session, slot } => with(sessions, session, |s| {
            // Authoring past the head is the harness's own rule: the engine
            // will happily author into the past and produce a chain the node
            // cannot follow.
            let head_slot = s.harness.chain().best_block().1;
            if slot <= head_slot {
                return Message::Error(format!("slot {slot} is not past the head at {head_slot}"));
            }
            s.harness.next_slot = slot;
            match s.harness.author.author_block(slot) {
                Ok(Some(block)) => Message::Authored(Some(block.encode())),
                Ok(None) => Message::Authored(None),
                Err(e) => Message::Error(format!("authoring slot {slot}: {e}")),
            }
        }),

        Message::Head(session) => with(sessions, session, |s| {
            let (hash, slot) = s.harness.chain().best_block();
            Message::HeadIs { hash: hash.0, slot }
        }),

        Message::ChainBlocks(session) => with(sessions, session, |s| {
            // Walked parent by parent, as `RefChain::chain_blocks` does:
            // the engine has no ancestry call, and stopping at the zero
            // parent is what ends the walk at genesis.
            let chain = s.harness.chain();
            let (head, _) = chain.best_block();
            let mut blocks = Vec::new();
            let mut hash = head;
            loop {
                let Some(block) = chain.block(&hash).ok().flatten() else {
                    break;
                };
                let parent = block.header.parent;
                blocks.push(block.encode());
                if parent == jam_types::HeaderHash::zero() {
                    break;
                }
                hash = parent;
            }
            blocks.reverse();
            Message::Blocks(blocks)
        }),

        Message::StateRootOf { session, hash } => with(sessions, session, |s| {
            match s.harness.chain().state_root(&hash.into()) {
                Ok(Some(root)) => Message::StateRoot(root.0),
                Ok(None) => Message::Error(format!("no state for {}", hex8(&hash))),
                Err(e) => Message::Error(format!("state for {}: {e}", hex8(&hash))),
            }
        }),

        Message::ImportBlock(encoded) => {
            // No session: the fuzz protocol's tag, kept for compatibility,
            // acts on whichever session the connection opened first. A run
            // imports node blocks into exactly one chain.
            let Some(session) = sessions.first() else {
                return Message::OracleFault("no session is open".into());
            };
            with(sessions, session, |s| {
                let mut cursor = &encoded[..];
                let block = match jam_std_common::Block::decode(&mut cursor) {
                    Ok(block) => block,
                    Err(e) => return Message::Error(format!("the block did not decode: {e}")),
                };
                let hash = block.header.hash();
                let chain = s.harness.chain();
                match chain.import_block(block, jam_node::hazmat::ImportBlockParams::new_exec(hash))
                {
                    Ok(_) => match chain.state_root(&hash).ok().flatten() {
                        Some(root) => Message::StateRoot(root.0),
                        None => Message::Error("imported but no state root".into()),
                    },
                    Err(e) => Message::Error(format!("import rejected: {e}")),
                }
            })
        }

        Message::GetState(hash) => {
            let Some(session) = sessions.first() else {
                return Message::OracleFault("no session is open".into());
            };
            with(sessions, session, |s| {
                let chain = s.harness.chain();
                let header = jam_types::HeaderHash::from(hash);
                let Some(storage) = chain.storage(&header) else {
                    return Message::Error(format!("no state for {}", hex8(&hash)));
                };
                let pairs = storage
                    .keys()
                    .filter_map(|key| {
                        storage
                            .get(jam_std_common::StorageKey(key))
                            .map(|value| (key.to_vec(), value))
                    })
                    .collect();
                Message::State(pairs)
            })
        }

        Message::CoreAssignment {
            session,
            slot,
            view,
        } => with(sessions, session, |s| {
            let cores = jam_types::core_count();
            let table = (0..cores)
                .map(|core| match view {
                    AssignmentView::Storage => s
                        .harness
                        .storage(None)
                        .core_assignments_for(slot)
                        .ok()
                        .and_then(|a| a.core_to_vals(core))
                        .map(|v| v.to_vec())
                        .unwrap_or_default(),
                    AssignmentView::Epoch => {
                        let chain = s.harness.chain();
                        let (index, current, next) = chain.current_and_next_epochs();
                        let slot_epoch = slot / jam_types::epoch_period();
                        let info = if slot_epoch == index {
                            Some(current)
                        } else if slot_epoch == index + 1 {
                            Some(next)
                        } else {
                            None
                        };
                        info.and_then(|e| e.core_assignments(slot).core_to_vals(core))
                            .map(|v| v.to_vec())
                            .unwrap_or_default()
                    }
                })
                .collect();
            Message::Assignment(table)
        }),

        // Responses are not requests. A peer that sends one is confused, and
        // saying so beats answering it.
        other => Message::OracleFault(format!("{other:?} is not a request")),
    }
}

fn with(
    sessions: &mut Sessions,
    id: m2_oracle_proto::SessionId,
    f: impl FnOnce(&mut crate::session::Session) -> Message,
) -> Message {
    match sessions.get_mut(id) {
        Ok(session) => f(session),
        Err(e) => Message::OracleFault(e),
    }
}

fn hex8(bytes: &[u8; 32]) -> String {
    bytes[..8].iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A request the oracle has no session for is its own fault to report,
    /// not the node's.
    ///
    /// `Error` means "what you gave me is invalid" and `OracleFault` means
    /// "I fell over". A report that confused them would attribute a harness
    /// problem to the node under test, which is the failure mode this whole
    /// move exists to prevent.
    #[test]
    fn a_missing_session_is_a_fault_not_an_error() {
        let mut sessions = Sessions::default();
        let reply = answer(&mut sessions, Message::Head(7));
        assert!(
            matches!(reply, Message::OracleFault(ref m) if m.contains("no session 7")),
            "got {reply:?}"
        );
    }

    /// A response arriving where a request belongs is the peer being
    /// confused; saying so beats trying to answer it.
    #[test]
    fn a_response_is_not_a_request() {
        let mut sessions = Sessions::default();
        let reply = answer(&mut sessions, Message::StateRoot([0u8; 32]));
        assert!(matches!(reply, Message::OracleFault(_)), "got {reply:?}");
    }

    /// The handshake states the protocol version and the revision the
    /// binary was built from, so a client can refuse an oracle that does
    /// not match its node under test.
    #[test]
    fn the_handshake_names_its_revision() {
        let mut sessions = Sessions::default();
        let reply = answer(
            &mut sessions,
            Message::PeerInfo(PeerInfo {
                protocol_version: PROTOCOL_VERSION,
                polkajam_revision: String::new(),
                name: "client".into(),
            }),
        );
        match reply {
            Message::PeerInfo(info) => {
                assert_eq!(info.protocol_version, PROTOCOL_VERSION);
                assert_eq!(info.polkajam_revision, POLKAJAM_REVISION);
                assert!(
                    !info.polkajam_revision.is_empty() && info.polkajam_revision != "unknown",
                    "the build must record a real revision, got {:?}",
                    info.polkajam_revision
                );
            }
            other => panic!("expected PeerInfo, got {other:?}"),
        }
    }

    /// Opening over a spec that is not there is reported, not panicked.
    #[test]
    fn a_missing_spec_file_is_reported() {
        let mut sessions = Sessions::default();
        let reply = answer(
            &mut sessions,
            Message::Open {
                spec_path: "/nonexistent/spec.json".into(),
                holds: vec![0],
            },
        );
        assert!(matches!(reply, Message::OracleFault(_)), "got {reply:?}");
    }

    /// A panic inside a handler comes back as a fault rather than taking
    /// the process down. `hazmat`'s own documentation says it "may easily
    /// panic", so this is the expected path, not an edge case.
    #[test]
    fn a_panicking_handler_becomes_a_fault() {
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            panic!("engine exploded");
        }));
        let reply = match caught {
            Ok(()) => unreachable!("the closure panics"),
            Err(panic) => Message::OracleFault(describe_panic(&panic)),
        };
        assert!(
            matches!(reply, Message::OracleFault(ref m) if m.contains("engine exploded")),
            "the panic's message must survive into the fault, got {reply:?}"
        );
    }
}
