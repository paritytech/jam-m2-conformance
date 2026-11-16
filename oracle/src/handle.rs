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

        // Closing a session that is not open is not an error: a runner
        // tearing down after a fault should not have to know which of its
        // sessions survived.
        Message::Close(session) => {
            sessions.close(session);
            Message::Done
        }

        Message::AuthorBlock { session, slot } => with(sessions, session, |s| {
            // Authoring past the head is the harness's own rule: the engine
            // will happily author into the past and produce a chain the node
            // cannot follow.
            let head_slot = s.harness.chain().best_block().1;
            if slot <= head_slot {
                return Message::Error(format!("slot {slot} is not past the head at {head_slot}"));
            }
            let hash = match s.harness.author.author_block(slot) {
                Ok(Some(hash)) => hash,
                Ok(None) => {
                    s.harness.next_slot = slot + 1;
                    return Message::Authored(None);
                }
                Err(e) => return Message::Error(format!("authoring slot {slot}: {e}")),
            };
            // Past the slot just authored, not at it: the next call has to
            // be able to claim `slot + 1`.
            s.harness.next_slot = slot + 1;
            // `author_block` answers with the hash and keeps the block --
            // it authors *and* imports -- so the block itself comes back out
            // of the chain. Encoding the hash instead produces 32 bytes that
            // fail to decode as a header, which is a confusing way to find
            // this out.
            match s.harness.chain().block(&hash) {
                Ok(Some(block)) => Message::Authored(Some(block.encode())),
                Ok(None) => {
                    Message::Error(format!("authored {} is not in the chain", hex8(&hash.0)))
                }
                Err(e) => Message::Error(format!("reading authored {}: {e}", hex8(&hash.0))),
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

        Message::ImportInto { session, block } => with(sessions, session, |s| {
            let mut cursor = &block[..];
            let block = match jam_std_common::Block::decode(&mut cursor) {
                Ok(block) => block,
                Err(e) => return Message::Error(format!("the block did not decode: {e}")),
            };
            if !cursor.is_empty() {
                return Message::Error(format!("the block has {} trailing bytes", cursor.len()));
            }
            let hash = block.header.hash();
            let parent = block.header.parent;
            let chain = s.harness.chain();
            let outcome =
                chain.import_block(block, jam_node::hazmat::ImportBlockParams::new_exec(hash));
            // Read after the import, which does not move the parent's root
            // but does mean the chain knows the parent in the case where it
            // has just learned it.
            let parent_root = chain.state_root(&parent).ok().flatten().map(|r| r.0);
            match outcome {
                // A block the chain already had imports as `Ok`, which is
                // what the lane wants: it asked whether the block is
                // acceptable, not whether it was new.
                Ok(_) => Message::Imported {
                    ok: true,
                    root: chain.state_root(&hash).ok().flatten().map(|r| r.0),
                    parent_root,
                    error: None,
                },
                Err(e) => Message::Imported {
                    ok: false,
                    root: None,
                    parent_root,
                    error: Some(e.to_string()),
                },
            }
        }),

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
                    // The on-chain rule's own view: the assignment the
                    // storage for `slot` carries.
                    AssignmentView::Storage => s
                        .harness
                        .storage(None)
                        .core_assignments_for(slot)
                        .ok()
                        .and_then(|a| a.core_to_vals(core))
                        .map(|v| v.to_vec()),
                    // What a sharing guarantor uses. The chain holds two
                    // epochs; a slot outside both resolves to nothing, and
                    // that is an answer -- `None`, not an empty cohort.
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
                    }
                })
                .collect();
            Message::Assignment(table)
        }),

        Message::TicketCtx(session) => with(sessions, session, |s| {
            let storage = s.harness.storage(None);
            let validators = match storage.designate_validators() {
                Ok(v) => v,
                Err(e) => return Message::Error(format!("designate_validators: {e}")),
            };
            let pks = validators.iter().map(|v| v.bandersnatch.0).collect();
            // Entry 2, which is what `RefChain::ticket_ctx` reads. Writing
            // entry 1 here -- as a first pass of this handler did -- makes
            // every proved ticket come back "invalid ticket signature", and
            // does it quietly, because the two entries agree whenever an
            // epoch boundary falls between proving and delivery.
            let entropy = match storage.entropy() {
                Ok(buffer) => buffer[2].0,
                Err(e) => return Message::Error(format!("entropy: {e}")),
            };
            Message::TicketContext { pks, entropy }
        }),

        Message::SignTickets {
            session,
            author,
            attempts,
            pks,
            entropy,
        } => with(sessions, session, |s| {
            let attempts = attempts.unwrap_or_else(|| {
                (0..jam_types::tickets_per_validator(jam_types::max_val_count())).collect()
            });
            let authors: Vec<u16> = match author {
                Some(one) => vec![one],
                None => (0..pks.len() as u16).collect(),
            };
            let mut proved = Vec::new();
            for author in authors {
                match sign_for(s, &pks, entropy, author, &attempts) {
                    Ok(mut tickets) => proved.append(&mut tickets),
                    Err(e) => return Message::Error(e),
                }
            }
            Message::Tickets(proved)
        }),

        Message::SubmitTickets { session, envelopes } => with(sessions, session, |s| {
            let mut decoded = Vec::with_capacity(envelopes.len());
            for envelope in &envelopes {
                let mut cursor = &envelope[..];
                match jam_std_common::TicketEnvelope::decode(&mut cursor) {
                    Ok(ticket) => decoded.push(ticket),
                    Err(e) => return Message::Error(format!("a ticket did not decode: {e}")),
                }
            }
            s.harness.submit_tickets(&decoded);
            Message::Done
        }),

        Message::BuildPackage {
            session,
            items,
            authorized,
        } => with(sessions, session, |s| {
            let items = match items.iter().map(build_item).collect::<Result<Vec<_>, _>>() {
                Ok(items) => items,
                Err(e) => return Message::Error(e),
            };
            let (package, extrinsics) = if authorized {
                s.harness.build_package(items)
            } else {
                // `Authorizer::any()`'s code hash is zero, so no core
                // authorizes it. The package is otherwise well-formed, which
                // is what makes it a test of the authorization check rather
                // than of the decoder.
                s.harness.build_package_with_auth(
                    items,
                    jam_types::Authorizer::any(),
                    jam_node::DEV_BOOTSTRAP_SERVICE_ID,
                    jam_types::Authorization::new(),
                )
            };
            Message::Package {
                package: package.encode(),
                extrinsics: extrinsics.into_iter().collect(),
            }
        }),

        Message::GuaranteeWork {
            session,
            items,
            core,
        } => with(sessions, session, |s| {
            let items = match items.iter().map(build_item).collect::<Result<Vec<_>, _>>() {
                Ok(items) => items,
                Err(e) => return Message::Error(e),
            };
            let (package, xts) = s.harness.build_package(items);
            let wire = package.clone();
            let (report, bundle, _) = match s.harness.try_compose_report(package, &xts, core) {
                Ok(composed) => composed,
                Err(e) => return Message::Error(format!("compose report: {e}")),
            };
            let guarantee = match s.harness.try_compose_guarantee(report.clone()) {
                Ok(guarantee) => guarantee,
                Err(e) => return Message::Error(format!("compose guarantee: {e}")),
            };
            Message::GuaranteedWork {
                package: wire.encode(),
                extrinsics: xts.into_iter().collect(),
                report: report.encode(),
                bundle: bundle.to_vec(),
                guarantee: guarantee.encode(),
            }
        }),

        Message::EpochProbe(session) => with(sessions, session, |s| {
            let chain = s.harness.chain();
            let (cached_index, _, _) = chain.current_and_next_epochs();
            let head_epoch = chain.best_block().1 / jam_types::epoch_period();
            let buffer = match s.harness.storage(None).entropy() {
                Ok(buffer) => buffer,
                Err(e) => return Message::Error(format!("entropy: {e}")),
            };
            Message::EpochProbed {
                cached_index,
                head_epoch,
                entropy_1: buffer[1].0,
                entropy_2: buffer[2].0,
            }
        }),

        // Responses are not requests. A peer that sends one is confused, and
        // saying so beats answering it.
        other => Message::OracleFault(format!("{other:?} is not a request")),
    }
}

/// Prove one author's tickets, or none where the keystore has no key.
///
/// Lifted from `RefChain::sign_tickets`. It stays one function because the
/// proof is signed over the attempt: a caller that wanted a ticket for a
/// different attempt cannot rewrite an honest one without breaking it.
fn sign_for(
    session: &mut crate::session::Session,
    pks: &[[u8; 32]],
    entropy: [u8; 32],
    author: u16,
    attempts: &[u8],
) -> Result<Vec<m2_oracle_proto::WireTicket>, String> {
    use jam_node::hazmat::KeystoreSigner as _;
    use jam_std_common::{
        bandersnatch::{self, ring_vrf},
        Entropy,
    };

    let keys: Vec<bandersnatch::Public> = pks.iter().map(|p| bandersnatch::Public(*p)).collect();
    let Some(pk) = keys.get(author as usize).copied() else {
        return Ok(Vec::new());
    };
    let keystore = session.harness.keystore();
    if !keystore.has_bandersnatch(&pk) {
        // Not an error: a session holds only some validators' keys, and
        // being asked for one it does not hold is the normal case.
        return Ok(Vec::new());
    }
    let prover = ring_vrf::RingContext::prover(&keys, author as usize);
    let mut tickets = Vec::new();
    for &attempt in attempts {
        let message = bandersnatch::Message::TicketSeal(Entropy(entropy), attempt);
        let signature = keystore
            .bandersnatch_ring_sign(&pk, &message, &[], &prover)
            .map_err(|e| format!("ring sign author {author}: {e}"))?;
        let id = signature.vrf_output().0;
        tickets.push(m2_oracle_proto::WireTicket {
            id,
            author,
            attempt,
            proof: signature.0.to_vec(),
            proxy: proxy_index(&id, keys.len()),
        });
    }
    Ok(tickets)
}

/// Which validator a ticket is proxied through: its id read as a big-endian
/// number, modulo the validator count.
fn proxy_index(id: &[u8; 32], val_count: usize) -> u16 {
    let mut acc = 0u128;
    for byte in id.iter().take(16) {
        acc = (acc << 8) | u128::from(*byte);
    }
    (acc % val_count as u128) as u16
}

/// Turn a wire item back into the engine's own.
fn build_item(item: &m2_oracle_proto::WireItem) -> Result<jam_node::hazmat::BuildItem, String> {
    // `ImportSpec` has a hand-written codec -- the root is a two-case
    // enum, not a plain hash -- so the specs cross the wire encoded and
    // are decoded here rather than mirrored field by field.
    let mut imports = Vec::with_capacity(item.imports.len());
    for (i, encoded) in item.imports.iter().enumerate() {
        let mut cursor = &encoded[..];
        let spec = jam_types::ImportSpec::decode(&mut cursor)
            .map_err(|e| format!("import spec {i} did not decode: {e}"))?;
        if !cursor.is_empty() {
            return Err(format!(
                "import spec {i} has {} trailing bytes",
                cursor.len()
            ));
        }
        imports.push(spec);
    }
    Ok(jam_node::hazmat::BuildItem::new(
        item.service,
        jam_types::WorkPayload(item.payload.clone()),
        item.ref_gas,
        item.acc_gas,
        item.xts.clone(),
        imports,
        item.export_count,
    ))
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
