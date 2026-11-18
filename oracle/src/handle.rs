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

        Message::Open {
            spec_path,
            holds,
            now_slot,
        } => match sessions.open(&spec_path, &holds) {
            Ok(session) => {
                let opened = sessions.get_mut(session).expect("just opened");
                let (genesis_hash, genesis_slot) = (opened.genesis_hash, opened.genesis_slot);
                // Virtual time, seeded from the *caller's* clock. Reading
                // this process's own would be wrong twice over: a session
                // left at genesis authors millions of slots in the past, and
                // one seeded from `SystemTime::now()` lands wherever real
                // time is, which for a simulation on an installed clock is
                // nowhere near the run.
                opened.harness.next_slot = now_slot;
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
            advance_finality(s);
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
            // A block the chain does not have is `None`, not an error: the
            // caller asked whether there is a root, and there is not.
            match s.harness.chain().state_root(&hash.into()) {
                Ok(root) => Message::StateRootIs(root.map(|r| r.0)),
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
            let root = chain.state_root(&hash).ok().flatten().map(|r| r.0);
            // Only when the head actually moved: a refused block leaves the
            // chain where it was and there is nothing new to finalize.
            if outcome.is_ok() {
                advance_finality(s);
            }
            match outcome {
                // A block the chain already had imports as `Ok`, which is
                // what the lane wants: it asked whether the block is
                // acceptable, not whether it was new.
                Ok(_) => Message::Imported {
                    ok: true,
                    root,
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

        Message::StateOf { session, hash } => with(sessions, session, |s| {
            let chain = s.harness.chain();
            let header = jam_types::HeaderHash::from(hash);
            let (Some(storage), Ok(Some(root))) =
                (chain.storage(&header), chain.state_root(&header))
            else {
                // Not an error: the caller asked whether this session has
                // that block, and it does not.
                return Message::StateIs(None);
            };
            // Root and keys off one storage view, in one answer. Fetched
            // separately they could land either side of an import, and a
            // root that does not belong to the keys beside it is the one
            // failure the state diff cannot detect.
            let keyvals = storage
                .keys()
                .filter_map(|key| {
                    storage
                        .get(jam_std_common::StorageKey(key))
                        .map(|value| (key.to_vec(), value))
                })
                .collect();
            Message::StateIs(Some(m2_oracle_proto::WireState {
                root: root.0,
                keyvals,
            }))
        }),

        Message::DevSpec { base_port } => {
            // The validator set is sized from the process-wide parameters,
            // so these come first, exactly as for a dev-spec `Open`.
            if let Err(e) = jam_types::ProtocolParameters::tiny().apply() {
                return Message::Error(format!("applying the tiny parameters: {e}"));
            }
            let spec = jam_node::hazmat::dev_spec(base_port);
            let state = match spec.build_storage() {
                Ok(state) => state,
                Err(e) => return Message::Error(format!("building the dev genesis: {e}")),
            };
            // Only the keys that carry a value. A `None` is a key the
            // genesis does not set, and a spec file has no way to say so.
            let keyvals = state
                .into_iter()
                .filter_map(|(k, v)| v.map(|v| (k.to_vec(), v)))
                .collect();
            Message::DevSpecIs {
                genesis_header: spec.genesis_header.encode(),
                keyvals,
                protocol_parameters: jam_types::ProtocolParameters::get().encode(),
            }
        }

        Message::CodeBundle {
            bundle,
            shard_count,
        } => {
            let count = shard_count as usize;
            match jam_node::hazmat::erasure::erasure_shards(&bundle, count) {
                Ok(shards) => Message::CodedBundle {
                    shards,
                    recovery_threshold: jam_node::hazmat::erasure::recovery_threshold(count) as u16,
                    shard_len: jam_node::hazmat::erasure::shard_len(bundle.len(), count) as u32,
                },
                Err(e) => Message::Error(format!("coding a {} byte bundle: {e:?}", bundle.len())),
            }
        }

        Message::CheckServedShard {
            protocol,
            erasure_root,
            shard_index,
            shard_count,
            bundle_shard,
            segment_shards,
            justification,
        } => {
            if protocol != 137 && protocol != 138 {
                return Message::Error(format!(
                    "CE {protocol} does not serve bundle shards; 137 and 138 do"
                ));
            }
            // The wire carries the justification's elements back to back with
            // no count in front of them (`simple.md:546`; polkajam writes them
            // with `write_encoded_seq` and reads them back until the message
            // runs out), while the engine's type decodes as an ordinary
            // length-prefixed sequence. Walking the discriminator bytes to
            // find the boundaries is a shape fact and nothing cryptographic,
            // and it is the same walk CE 138 needs to find its segment root.
            let Some(elements) = bundle_elements(&justification) else {
                return Message::ShardChecked {
                    verified: None,
                    detail: Some(
                        "the justification is not a sequence of 0++Hash / 1++Hash++Hash elements"
                            .into(),
                    ),
                };
            };
            if elements.is_empty() {
                // polkajam calls an empty justification a misbehaviour before
                // it checks any proof, and so does this.
                return Message::ShardChecked {
                    verified: None,
                    detail: Some("the justification is empty".into()),
                };
            }

            // Where the segment root comes from is the one thing the two
            // protocols do differently, and reading it from the wrong place
            // fails an honest node rather than erroring.
            let (proof_elements, segment_root) = if protocol == 138 {
                // CE 138 appends the root as a final `0 ++ Hash`, which
                // polkajam's reader pops off before checking the proof.
                let last = elements[elements.len() - 1];
                if last.len() != 33 || last[0] != 0 {
                    return Message::ShardChecked {
                        verified: None,
                        detail: Some(
                            "the CE 138 justification does not end in a segment root".into(),
                        ),
                    };
                }
                let mut root = [0u8; 32];
                root.copy_from_slice(&last[1..]);
                (&elements[..elements.len() - 1], root)
            } else {
                // CE 137 sends the segment shards instead, and the root is
                // the Merkle root over them -- the engine's own, computed
                // here rather than by a caller.
                // The slice length is `SEGMENT_LEN / D(v)`, which the shard
                // count already fixes. Derived rather than carried, so the
                // caller has no way to disagree with the engine about it.
                let slice_len = jam_types::segment_slice_len(shard_count as usize);
                let slices = if segment_shards.is_empty() {
                    // A package that exports nothing still has a root, over
                    // no slices; the length is then immaterial, and a zero
                    // one is refused by the constructor.
                    jam_std_common::SegmentSliceVec::from_bytes(Vec::new(), 1)
                } else {
                    jam_std_common::SegmentSliceVec::from_bytes(segment_shards, slice_len)
                };
                let Some(slices) = slices else {
                    return Message::ShardChecked {
                        verified: None,
                        detail: Some(format!(
                            "the segment shards are not a whole number of {slice_len} byte slices"
                        )),
                    };
                };
                let root = jam_node::hazmat::merkle::merkle_root(&slices, slices.len());
                (&elements[..], root)
            };
            if proof_elements.is_empty() {
                return Message::ShardChecked {
                    verified: None,
                    detail: Some("the justification is empty once the segment root is off".into()),
                };
            }

            // Re-prefixed and handed to the engine's own decoder: the bytes
            // are the node's, only the count in front of them is ours.
            let mut prefixed = codec::Compact(proof_elements.len() as u32).encode();
            for element in proof_elements {
                prefixed.extend_from_slice(element);
            }
            let mut cursor = &prefixed[..];
            let decoded = match Decode::decode(&mut cursor) {
                Ok(decoded) => decoded,
                Err(e) => {
                    return Message::ShardChecked {
                        verified: None,
                        detail: Some(format!("the justification did not decode: {e}")),
                    }
                }
            };

            let verified = jam_node::hazmat::availability::check_bundle_proof(
                erasure_root.into(),
                shard_index,
                shard_count as usize,
                jam_std_common::hash_raw(&bundle_shard),
                segment_root,
                decoded,
            )
            .is_some();
            Message::ShardChecked {
                verified: Some(verified),
                detail: None,
            }
        }

        Message::CodeSegments {
            segments,
            shard_count,
        } => {
            let mut fixed = Vec::with_capacity(segments.len());
            for (i, segment) in segments.iter().enumerate() {
                // Boxed: `segments_shards` takes `impl AsRef<[u8; SEGMENT_LEN]>`,
                // which a bare array does not implement for itself but a
                // `Box` does. Built from the slice first so a wrong length
                // is an error rather than a panic.
                let Ok(array) = <[u8; jam_types::SEGMENT_LEN]>::try_from(segment.as_slice()) else {
                    return Message::Error(format!(
                        "segment {i} is {} bytes, not {}",
                        segment.len(),
                        jam_types::SEGMENT_LEN
                    ));
                };
                fixed.push(Box::new(array));
            }
            match jam_node::hazmat::erasure::segments_shards(&fixed, shard_count as usize) {
                Ok(shards) => {
                    // One slice length for the whole matrix; an empty set of
                    // segments still yields one shard per validator, so the
                    // length is read from the shards rather than guessed.
                    let slice_len = shards.first().map(|s| s.slice_len()).unwrap_or(0) as u32;
                    Message::CodedSegments {
                        shards: shards.into_iter().map(|s| s.into_inner()).collect(),
                        slice_len,
                    }
                }
                Err(e) => Message::Error(format!(
                    "coding {} segments into {shard_count} shards: {e:?}",
                    segments.len()
                )),
            }
        }

        Message::MakeAvailable {
            bundle,
            segments,
            shard_count,
        } => {
            let count = shard_count as usize;
            let bundle_shards = match jam_node::hazmat::erasure::erasure_shards(&bundle, count) {
                Ok(shards) => shards,
                Err(e) => return Message::Error(format!("coding the bundle: {e:?}")),
            };
            let mut fixed = Vec::with_capacity(segments.len());
            for (i, segment) in segments.iter().enumerate() {
                let Ok(array) = <[u8; jam_types::SEGMENT_LEN]>::try_from(segment.as_slice()) else {
                    return Message::Error(format!(
                        "segment {i} is {} bytes, not {}",
                        segment.len(),
                        jam_types::SEGMENT_LEN
                    ));
                };
                fixed.push(Box::new(array));
            }
            let segment_shards = match jam_node::hazmat::erasure::segments_shards(&fixed, count) {
                Ok(shards) => shards,
                Err(e) => return Message::Error(format!("coding the segments: {e:?}")),
            };

            // The erasure tree's leaves pair each validator's bundle-shard
            // hash with the root of its segment slices. Both halves are the
            // engine's, and the pairing is `pack_erasure_tree_entry` rather
            // than a concatenation written here: that is the step a second
            // implementation would get subtly wrong.
            let segment_roots: Vec<_> = segment_shards
                .iter()
                .map(|slices| jam_node::hazmat::merkle::merkle_root(slices, slices.len()))
                .collect();
            let bundle_hashes: Vec<_> = bundle_shards
                .iter()
                .map(|shard| jam_std_common::hash_raw(shard))
                .collect();
            let entries: Vec<_> = bundle_hashes
                .iter()
                .zip(segment_roots.iter())
                .map(|(hash, root)| {
                    jam_node::hazmat::merkle::pack_erasure_tree_entry(hash, root)
                })
                .collect();
            let (erasure_root, shard_proofs) =
                jam_node::hazmat::merkle::merkle_proofs(&entries[..], entries.len());

            let mut shard_justifications = Vec::with_capacity(count);
            let mut audit_justifications = Vec::with_capacity(count);
            let mut segment_justifications = Vec::with_capacity(count);
            for (index, proof) in shard_proofs.iter().enumerate() {
                let elements = jam_node::hazmat::availability::bundle_justification(proof);
                let co_path = encode_elements(&elements);
                // CE 138 appends the segment root as a final `0 ++ Hash`.
                // Appended as bytes rather than as the element type, which
                // `hazmat` does not export: that is the derived encoding of
                // the enum's first variant, and the same layout this
                // oracle's `bundle_elements` reads back.
                let mut with_root = co_path.clone();
                with_root.push(0);
                with_root.extend_from_slice(segment_roots[index].as_ref());
                shard_justifications.push(co_path);
                audit_justifications.push(with_root);

                // One justification per segment: the bundle co-path, the
                // bundle-shard hash, then the path down this validator's own
                // segment tree.
                let slices = &segment_shards[index];
                let (_, segment_proofs) =
                    jam_node::hazmat::merkle::merkle_proofs(slices, slices.len());
                segment_justifications.push(
                    segment_proofs
                        .iter()
                        .map(|segment_proof| {
                            encode_elements(&jam_node::hazmat::availability::segment_justification(
                                proof,
                                bundle_hashes[index],
                                segment_proof,
                            ))
                        })
                        .collect(),
                );
            }

            Message::AvailableShards {
                erasure_root,
                bundle_shards,
                segment_shards: segment_shards
                    .into_iter()
                    .map(|slices| slices.into_inner())
                    .collect(),
                shard_justifications,
                audit_justifications,
                segment_justifications,
            }
        }

        Message::CheckSegmentShard {
            erasure_root,
            shard_index,
            shard_count,
            segment_index,
            segment_count,
            segment_slice,
            justification,
        } => {
            // The engine's own decoder, which needs the slice length to know
            // where each element ends.
            let Some(decoded) = jam_node::hazmat::availability::decode_segment_justification(
                &justification,
                segment_slice.len(),
            ) else {
                return Message::ShardChecked {
                    verified: None,
                    detail: Some(format!(
                        "the justification did not decode against a {} byte slice",
                        segment_slice.len()
                    )),
                };
            };
            let verified = jam_node::hazmat::availability::check_segment_proof(
                erasure_root.into(),
                shard_index,
                shard_count as usize,
                segment_index,
                segment_count as usize,
                &segment_slice,
                &decoded,
            );
            Message::ShardChecked {
                verified: Some(verified),
                detail: None,
            }
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
            // The epoch this entropy seals, from the same session and the
            // same moment. Entry 2 at a head in epoch E is what a ticket for
            // E + 1 is checked against, so that is what this reports; a
            // caller computing it from its own clock gets the answer wrong
            // whenever the head and the clock straddle a boundary.
            let head_epoch = s.harness.chain().best_block().1 / jam_types::epoch_period();
            Message::TicketContext {
                pks,
                entropy,
                epoch: head_epoch + 1,
            }
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

        Message::SubmitAssurances {
            session,
            assurances,
        } => with(sessions, session, |s| {
            let mut decoded = Vec::with_capacity(assurances.len());
            for bytes in &assurances {
                let mut cursor = &bytes[..];
                match jam_std_common::AvailabilityAssurance::decode(&mut cursor) {
                    // Trailing bytes mean the caller and the engine disagree
                    // about the shape, which is the disagreement worth
                    // finding rather than ignoring.
                    Ok(_) if !cursor.is_empty() => {
                        return Message::Error(
                            "an assurance decoded and left bytes over".to_string(),
                        )
                    }
                    Ok(assurance) => decoded.push(assurance),
                    Err(e) => return Message::Error(format!("an assurance did not decode: {e}")),
                }
            }
            for assurance in &decoded {
                s.harness.submit_assurance(assurance);
            }
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
            let (cached_index, current, _) = chain.current_and_next_epochs();
            let cached_entropy = current.core_assignment_entropy.0;
            let head_epoch = chain.best_block().1 / jam_types::epoch_period();
            let buffer = match s.harness.storage(None).entropy() {
                Ok(buffer) => buffer,
                Err(e) => return Message::Error(format!("entropy: {e}")),
            };
            Message::EpochProbed {
                cached_index,
                head_epoch,
                cached_entropy,
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
            proxy: m2_oracle_proto::proxy_index(&id, keys.len()) as u16,
        });
    }
    Ok(tickets)
}

/// Turn a wire item back into the engine's own.
/// Advance finality just far enough to keep the cached epoch view on the
/// head's epoch.
///
/// Without this a session never finalizes anything past genesis, because
/// `AuthoringHarness` builds a `JamChain` and nothing else: the worker that
/// drives finality (`finality::dummy_run`) belongs to the node. And
/// `current_and_next_epochs` is only ever written in the finalization path,
/// so the cached epoch view froze at genesis and stayed there for a whole
/// run while the head walked away from it. Every lane asking which
/// validators hold a core then got an answer computed from genesis entropy,
/// or no answer at all once the head was more than one epoch out -- which is
/// what left the N3 lane reporting every row unexercised. See findings.md §1.
///
/// **Not** `dummy_run`'s rule of one slot behind the head. The harness is
/// asked to import blocks a node announced late, and a block older than the
/// finalized head cannot be imported at all; at a one-slot lag a block two
/// slots late is already refused, which turns a node's late announcement
/// into a harness-side failure on a row about whether the block is
/// well-formed. So this finalizes the *earliest* block still in the head's
/// epoch, which is the least that moves the epoch index, and leaves the rest
/// of the epoch open to import.
fn advance_finality(session: &mut crate::session::Session) {
    let chain = session.harness.chain();
    let (best_hash, current_slot) = chain.best_block();
    let epoch_start = (current_slot / jam_types::epoch_period()) * jam_types::epoch_period();
    let (_, finalized_slot) = chain.finalized_block();
    if finalized_slot >= epoch_start {
        // The view already names the head's epoch; finalizing more would
        // only cost import headroom.
        return;
    }
    // Walk back to the oldest block of this epoch that is not the head.
    // Keeping the head unfinalized matters just after a boundary, when it is
    // the only block of its epoch: finalizing it would leave no headroom at
    // all, and the view naming the previous epoch for a slot or two is what
    // a node's own view does.
    let mut parent = best_hash;
    let mut earliest = None;
    while let Ok(Some(header)) = chain.header(&parent) {
        if header.slot < epoch_start || header.slot <= finalized_slot {
            break;
        }
        if header.hash() != best_hash {
            earliest = Some(header.hash());
        }
        parent = header.parent;
    }
    if let Some(hash) = earliest {
        // A failure is not fatal: the head stays unfinalized and the next
        // call tries again from further along.
        let _ = chain.finalize_block(&hash, None);
    }
}

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

/// Concatenate a justification's elements the way the wire carries them.
///
/// Back to back with no count in front of them, which is what
/// `write_encoded_seq` does and what the reader reads back until the message
/// runs out. The element types are not exported from `hazmat`, so they are
/// encoded through the trait rather than named.
fn encode_elements<T: Encode>(elements: &[T]) -> Vec<u8> {
    let mut out = Vec::new();
    for element in elements {
        element.encode_to(&mut out);
    }
    out
}

/// Split a CE 137/138 justification into its elements, without decoding them.
///
/// The wire writes them concatenated and unprefixed, so the only thing that
/// says where one ends is its discriminator: `0` is a hash, `1` is a pair of
/// them. That is the shape of the message rather than a rule about the proof,
/// which is why it is read here and the elements themselves are still handed
/// to the engine's decoder.
///
/// `None` when the bytes are not a whole sequence of elements, which is a
/// disagreement about the structure and not a proof that failed.
fn bundle_elements(justification: &[u8]) -> Option<Vec<&[u8]>> {
    let mut elements = Vec::new();
    let mut rest = justification;
    while let Some((discriminator, body)) = rest.split_first() {
        let len = match discriminator {
            0 => 32,
            1 => 64,
            _ => return None,
        };
        if body.len() < len {
            return None;
        }
        let (element, remainder) = rest.split_at(1 + len);
        elements.push(element);
        rest = remainder;
    }
    Some(elements)
}

#[cfg(test)]
mod tests {

    /// The protocol crate carries its own copy of the bootstrap service id
    /// so that a crate without a node dependency can name it. This is the
    /// one place both are in scope, so it is the only place the copy can be
    /// checked. A re-pin that moved the id would otherwise address every
    /// work item in the run to a service that is not there.
    #[test]
    fn the_protocols_bootstrap_service_id_is_the_nodes() {
        assert_eq!(
            m2_oracle_proto::DEV_BOOTSTRAP_SERVICE_ID,
            jam_node::DEV_BOOTSTRAP_SERVICE_ID
        );
    }
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
                now_slot: 10_711_224,
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

#[cfg(test)]
mod n4_reachability {
    /// What the merged hazmat export can and cannot do, checked by the
    /// compiler rather than by reading.
    #[test]
    fn erasure_coding_is_callable() {
        let bundle = vec![0xab_u8; 4096];
        let shards = jam_node::hazmat::erasure::erasure_shards(&bundle, 6).expect("coded");
        assert_eq!(shards.len(), 6);
        // Three of six, not two. DESIGN said two in both its tiny-parameter
        // table and its N4 row; polkajam computes `val_count / VALS_PER_CORE
        // + 1`, reduced until `SEGMENT_LEN` divides `POINT_LEN * d`, and has
        // its own `erasure_recovery_count_matches_gp` pinning 6 -> 3. A lane
        // written from DESIGN would have asked the node to reconstruct from
        // one shard too few.
        assert_eq!(
            jam_node::hazmat::erasure::recovery_threshold(6),
            3,
            "three of six shards recover a bundle under tiny"
        );
        let _ = jam_node::hazmat::erasure::shard_len(bundle.len(), 6);
    }
}
