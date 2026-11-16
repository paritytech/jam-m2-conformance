//! A session over a real socket, which is Phase 2's exit criterion.
//!
//! The handler tests prove the answers; this proves the wire — binding,
//! framing, back-to-back requests on one connection, and the process
//! surviving a client that goes away.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use m2_oracle_proto::{
    frame, read_frame, AssignmentView, Message, PeerInfo, WireItem, PROTOCOL_VERSION,
};

/// A running oracle, killed when the test drops it.
///
/// A guard rather than a kill at the end of each test: a test that panics
/// never reaches its last line, and an orphaned oracle holds the socket and
/// fails the next run with something that looks nothing like the cause.
struct Oracle {
    child: std::process::Child,
    path: String,
}

impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Start the oracle on a socket of this test's own.
fn start(name: &str) -> Oracle {
    let path = std::env::temp_dir()
        .join(format!("m2-oracle-{name}-{}.sock", std::process::id()))
        .to_string_lossy()
        .into_owned();
    let _ = std::fs::remove_file(&path);
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_m2-oracle"))
        .arg(&path)
        .spawn()
        .expect("the oracle starts");
    let _ = &mut child;

    // Bind is the first thing it does, but it is still a race.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if UnixStream::connect(&path).is_ok() {
            return Oracle { child, path };
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("the oracle never bound {path}");
}

fn ask(stream: &mut UnixStream, request: Message) -> Message {
    stream
        .write_all(&frame(&request))
        .expect("the request goes");
    let mut buffered = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        if let Ok((reply, _)) = read_frame(&buffered) {
            return reply;
        }
        let n = stream.read(&mut chunk).expect("the oracle answers");
        assert!(n > 0, "the oracle closed the connection");
        buffered.extend_from_slice(&chunk[..n]);
    }
}

#[test]
fn a_session_runs_over_the_socket() {
    let oracle = start("session");
    let mut stream = UnixStream::connect(&oracle.path).expect("connect");

    // Handshake.
    let reply = ask(
        &mut stream,
        Message::PeerInfo(PeerInfo {
            protocol_version: PROTOCOL_VERSION,
            polkajam_revision: String::new(),
            name: "test".into(),
        }),
    );
    match reply {
        Message::PeerInfo(info) => {
            assert_eq!(info.protocol_version, PROTOCOL_VERSION);
            assert!(!info.polkajam_revision.is_empty());
        }
        other => panic!("expected PeerInfo, got {other:?}"),
    }

    // Several requests on one connection, to prove the frames are
    // self-delimiting in practice and not only in the proto crate's tests.
    for session in [9u16, 10, 11] {
        let reply = ask(&mut stream, Message::Head(session));
        assert!(
            matches!(reply, Message::OracleFault(ref m) if m.contains("no session")),
            "got {reply:?}"
        );
    }

    // A spec that is not there is reported, and the oracle stays up: the
    // next request still gets an answer.
    let reply = ask(
        &mut stream,
        Message::Open {
            spec_path: "/nonexistent/spec.json".into(),
            holds: vec![0, 1],
        },
    );
    assert!(matches!(reply, Message::OracleFault(_)), "got {reply:?}");
    let still_alive = ask(&mut stream, Message::Head(0));
    assert!(matches!(still_alive, Message::OracleFault(_)));
}

/// A client that goes away does not take the oracle with it: the next run's
/// connection is served.
#[test]
fn the_oracle_survives_a_dropped_connection() {
    let oracle = start("dropped");
    {
        let mut first = UnixStream::connect(&oracle.path).expect("connect");
        let _ = ask(&mut first, Message::Head(0));
    }
    let mut second = UnixStream::connect(&oracle.path).expect("reconnect");
    let reply = ask(&mut second, Message::Head(0));
    assert!(matches!(reply, Message::OracleFault(_)), "got {reply:?}");
}

/// Phase 2's exit criterion: a real session, end to end over the socket.
///
/// Two sessions, in the shape a live run uses: the first is the chain the
/// node's blocks are imported into, and a second holds the keys and
/// authors. `ImportBlock` carries no session -- it is the fuzz protocol's
/// tag -- so it lands on the first one opened, which is what makes the
/// order here load-bearing.
///
/// Nothing in it is a stub: the oracle builds an `AuthoringHarness` per
/// session, runs the Safrole lottery over the keysets each was told it
/// holds, and executes the block on import. If any of that is wrong the
/// reply is an `Error` naming the step.
#[test]
fn a_real_session_authors_imports_and_reads_state() {
    let oracle = start("real");
    let mut stream = UnixStream::connect(&oracle.path).expect("connect");

    // An empty spec path is the default dev spec under the tiny parameters.
    // A live run names a file the runner wrote and the node under test also
    // loads; here there is no node, so there is nothing to agree with.
    let open = |stream: &mut UnixStream, holds: Vec<u16>| match ask(
        stream,
        Message::Open {
            spec_path: String::new(),
            holds,
        },
    ) {
        Message::Opened {
            session,
            genesis_hash,
            genesis_slot,
        } => (session, genesis_hash, genesis_slot),
        other => panic!("expected Opened, got {other:?}"),
    };

    // Holds nothing, so it never authors: it only receives.
    let (importer, genesis_hash, genesis_slot) = open(&mut stream, vec![]);
    // Holds every key, so some slot in the first epoch is its to claim.
    let (author, author_genesis, _) = open(&mut stream, (0..6).collect());
    assert_eq!(
        author_genesis, genesis_hash,
        "two sessions on one spec share a genesis"
    );
    assert!(importer < author, "the importer was opened first");

    // Both heads start at genesis.
    for session in [importer, author] {
        match ask(&mut stream, Message::Head(session)) {
            Message::HeadIs { hash, slot } => {
                assert_eq!(hash, genesis_hash, "head is genesis");
                assert_eq!(slot, genesis_slot);
            }
            other => panic!("expected HeadIs, got {other:?}"),
        }
    }

    // Which slot wins the lottery is not this test's business: it holds
    // every key, so some slot is authorable, and `Authored(None)` for a
    // given one is an answer rather than a failure.
    let mut authored = None;
    for slot in genesis_slot + 1..genesis_slot + 13 {
        match ask(
            &mut stream,
            Message::AuthorBlock {
                session: author,
                slot,
            },
        ) {
            Message::Authored(Some(block)) => {
                authored = Some(block);
                break;
            }
            Message::Authored(None) => continue,
            other => panic!("authoring slot {slot}: {other:?}"),
        }
    }
    let block = authored.expect("some slot in the first epoch is authorable with every key held");

    // Authoring imports into the authoring chain, so that head has moved.
    let authored_hash = match ask(&mut stream, Message::Head(author)) {
        Message::HeadIs { hash, slot } => {
            assert!(slot > genesis_slot, "the authoring head advanced");
            assert_ne!(hash, genesis_hash);
            hash
        }
        other => panic!("expected HeadIs, got {other:?}"),
    };

    // The importer has not seen it yet.
    match ask(&mut stream, Message::Head(importer)) {
        Message::HeadIs { hash, .. } => assert_eq!(hash, genesis_hash, "still at genesis"),
        other => panic!("expected HeadIs, got {other:?}"),
    }

    // This is the live path: a block from elsewhere, executed on import.
    let root = match ask(&mut stream, Message::ImportBlock(block)) {
        Message::StateRoot(root) => root,
        other => panic!("expected StateRoot, got {other:?}"),
    };
    assert_ne!(root, [0u8; 32], "an imported block has a state root");

    match ask(&mut stream, Message::Head(importer)) {
        Message::HeadIs { hash, slot } => {
            assert_eq!(hash, authored_hash, "the importer adopted the block");
            assert!(slot > genesis_slot);
        }
        other => panic!("expected HeadIs, got {other:?}"),
    }

    // The same block, reached two ways: the authoring session computed this
    // root, the importing one re-executed for it. They agree or the two
    // chains have diverged.
    match ask(
        &mut stream,
        Message::StateRootOf {
            session: author,
            hash: authored_hash,
        },
    ) {
        Message::StateRoot(theirs) => assert_eq!(theirs, root, "the two chains agree"),
        other => panic!("expected StateRoot, got {other:?}"),
    }

    // State at the new head: non-empty, and every key the right width.
    match ask(&mut stream, Message::GetState(authored_hash)) {
        Message::State(pairs) => {
            assert!(!pairs.is_empty(), "the state has entries");
            for (key, _) in &pairs {
                assert_eq!(key.len(), 31, "a state key is 31 bytes");
            }
        }
        other => panic!("expected State, got {other:?}"),
    }

    // And the chain reads back genesis plus the one block, in that order.
    match ask(&mut stream, Message::ChainBlocks(importer)) {
        Message::Blocks(blocks) => assert_eq!(blocks.len(), 2, "genesis and one block"),
        other => panic!("expected Blocks, got {other:?}"),
    }

    for session in [importer, author] {
        match ask(&mut stream, Message::Close(session)) {
            Message::Done => {}
            other => panic!("expected Done, got {other:?}"),
        }
        match ask(&mut stream, Message::Head(session)) {
            Message::OracleFault(m) => assert!(m.contains("no session"), "{m}"),
            other => panic!("a closed session is gone, got {other:?}"),
        }
    }
}

/// The ticket path, against a real keystore.
///
/// Ring-VRF proving is the harness's one expensive operation, so this asks
/// for one author and two attempts rather than the whole set. What it is
/// really checking is that the proofs come back signed over the entropy
/// `TicketCtx` handed out and over the attempt that was asked for -- the
/// two things that go wrong silently, because a ticket proved over the
/// wrong entropy is a well-formed ticket that simply never verifies.
#[test]
fn tickets_are_proved_over_the_context_the_oracle_gave() {
    let oracle = start("tickets");
    let mut stream = UnixStream::connect(&oracle.path).expect("connect");

    let session = match ask(
        &mut stream,
        Message::Open {
            spec_path: String::new(),
            holds: (0..6).collect(),
        },
    ) {
        Message::Opened { session, .. } => session,
        other => panic!("expected Opened, got {other:?}"),
    };

    let (pks, entropy) = match ask(&mut stream, Message::TicketCtx(session)) {
        Message::TicketContext { pks, entropy } => (pks, entropy),
        other => panic!("expected TicketContext, got {other:?}"),
    };
    assert_eq!(pks.len(), 6, "the tiny validator set");
    assert_ne!(entropy, [0u8; 32], "genesis entropy is not zero");

    let tickets = match ask(
        &mut stream,
        Message::SignTickets {
            session,
            author: Some(1),
            // One past the per-validator cap among them: the fault rows need
            // a proof genuinely signed over an attempt the node must refuse.
            attempts: Some(vec![0, 99]),
            pks: pks.clone(),
            entropy,
        },
    ) {
        Message::Tickets(tickets) => tickets,
        other => panic!("expected Tickets, got {other:?}"),
    };
    assert_eq!(tickets.len(), 2, "one per attempt asked for");
    assert_eq!(tickets[0].attempt, 0);
    assert_eq!(tickets[1].attempt, 99);
    assert_ne!(
        tickets[0].id, tickets[1].id,
        "the attempt is part of the signed message, so it changes the id"
    );
    for t in &tickets {
        assert_eq!(t.author, 1);
        assert_eq!(t.proof.len(), 784, "32 + 752");
        assert!((t.proxy as usize) < pks.len(), "proxy is an index");
    }

    // Submitting them is a request that answers `Done` rather than a value.
    // The pool files by epoch and drops duplicates, so this says the oracle
    // took them, not that a block will carry them.
    let envelopes = tickets
        .iter()
        .map(|t| {
            let mut bytes = vec![t.attempt];
            bytes.extend_from_slice(&t.proof);
            bytes
        })
        .collect();
    match ask(&mut stream, Message::SubmitTickets { session, envelopes }) {
        Message::Done => {}
        other => panic!("expected Done, got {other:?}"),
    }

    // A session that does not hold the key proves nothing, and says so by
    // answering with no tickets rather than by failing: a session holds only
    // some validators, and being asked for one it does not hold is ordinary.
    let narrow = match ask(
        &mut stream,
        Message::Open {
            spec_path: String::new(),
            holds: vec![0],
        },
    ) {
        Message::Opened { session, .. } => session,
        other => panic!("expected Opened, got {other:?}"),
    };
    match ask(
        &mut stream,
        Message::SignTickets {
            session: narrow,
            author: Some(1),
            attempts: Some(vec![0]),
            pks,
            entropy,
        },
    ) {
        Message::Tickets(none) => assert!(none.is_empty(), "no key, no tickets"),
        other => panic!("expected Tickets, got {other:?}"),
    }
}

/// Building a package, and guaranteeing one.
///
/// `BuildPackage`'s `authorized` flag is the interesting part: both arms
/// produce a well-formed package, and the unauthorized one differs only in
/// carrying `Authorizer::any()`, whose code hash is zero so that no core
/// authorizes it. A row built on it tests the node's authorization check
/// rather than its decoder, which is only true if the two packages are
/// otherwise alike -- so this asserts they are both decodable and that they
/// differ.
#[test]
fn packages_are_built_authorized_and_not() {
    let oracle = start("packages");
    let mut stream = UnixStream::connect(&oracle.path).expect("connect");

    let (session, genesis_slot) = match ask(
        &mut stream,
        Message::Open {
            spec_path: String::new(),
            holds: (0..6).collect(),
        },
    ) {
        Message::Opened {
            session,
            genesis_slot,
            ..
        } => (session, genesis_slot),
        other => panic!("expected Opened, got {other:?}"),
    };

    let item = WireItem {
        service: 0,
        payload: vec![1, 2, 3, 4],
        ref_gas: 10_000_000,
        acc_gas: 10_000_000,
        xts: vec![vec![0xab; 8]],
        imports: vec![],
        export_count: 0,
    };

    let build = |stream: &mut UnixStream, authorized: bool| match ask(
        stream,
        Message::BuildPackage {
            session,
            items: vec![item.clone()],
            authorized,
        },
    ) {
        Message::Package {
            package,
            extrinsics,
        } => (package, extrinsics),
        other => panic!("expected Package, got {other:?}"),
    };

    let (authorized, xts) = build(&mut stream, true);
    assert!(!authorized.is_empty(), "a package has bytes");
    assert_eq!(xts, vec![vec![0xab; 8]], "the item's extrinsic comes back");

    let (unauthorized, other_xts) = build(&mut stream, false);
    assert_eq!(other_xts, xts, "only the authorizer differs");
    assert_ne!(
        authorized, unauthorized,
        "the unauthorized package carries a different authorizer"
    );

    // Guaranteeing needs a chain under it. Composing a report picks a
    // lookup anchor out of recent history, and a chain still at genesis has
    // nothing recent to pick -- "lookup anchor too old", in the engine's
    // words. It also needs virtual time in the chain's epoch: a session
    // opens with its clock at the wall-clock slot, which is what makes a
    // live run author in real time, and the dev spec's genesis sits at slot
    // 0 some 800,000 slots behind it. Authoring forward from genesis fixes
    // both at once, because each authored slot also moves the clock to the
    // slot after it.
    //
    // A live run meets neither problem: the runner anchors its spec's
    // genesis to the current epoch, and by the time anything is guaranteed
    // the chain has been authoring for a while.
    let mut authored = 0;
    for slot in genesis_slot + 1..genesis_slot + 13 {
        match ask(&mut stream, Message::AuthorBlock { session, slot }) {
            Message::Authored(Some(_)) => authored += 1,
            Message::Authored(None) => continue,
            other => panic!("authoring slot {slot}: {other:?}"),
        }
    }
    assert!(authored >= 6, "holding every key, most slots are claimable");

    // Guaranteeing is the whole N3 front half in one request: build, compose
    // a report over a core, and sign a guarantee for it.
    match ask(
        &mut stream,
        Message::GuaranteeWork {
            session,
            items: vec![item],
            core: 0,
        },
    ) {
        Message::GuaranteedWork {
            package,
            extrinsics,
            report,
            bundle,
            guarantee,
        } => {
            assert!(!package.is_empty());
            assert_eq!(extrinsics, xts);
            assert!(!report.is_empty(), "a report was composed");
            assert!(
                bundle.len() > package.len(),
                "the bundle carries the package and its extrinsics"
            );
            assert!(!guarantee.is_empty(), "the guarantee was signed");
        }
        other => panic!("expected GuaranteedWork, got {other:?}"),
    }
}

/// The two core-assignment views, and the epoch probe.
///
/// The views exist because they disagree. `storage.core_assignments_for`
/// reads the entropy entry its own epoch relation picks; the cached
/// `EpochInfo` reads entry 1. Which one a caller wants depends on what it
/// is about to do -- sign a guarantee, or check one it received -- and the
/// run that mixed them up spent a session being told "Wrong core
/// assignment" by a node that was right.
///
/// This does not assert they differ, which depends on where the chain is.
/// It asserts both answer, that an out-of-reach slot is `None` rather than
/// an empty cohort, and that the probe reports both entropy entries.
#[test]
fn both_assignment_views_answer_and_say_when_they_cannot() {
    // The oracle applies the tiny parameters when it opens a dev-spec
    // session; this process has to apply them too, or `core_count()` here
    // is the full 341 against the oracle's 2. The parameters are
    // process-wide globals, so they do not travel over the socket.
    jam_types::ProtocolParameters::tiny()
        .apply()
        .expect("the tiny parameters apply");

    let oracle = start("assignment");
    let mut stream = UnixStream::connect(&oracle.path).expect("connect");

    let (session, genesis_slot) = match ask(
        &mut stream,
        Message::Open {
            spec_path: String::new(),
            holds: (0..6).collect(),
        },
    ) {
        Message::Opened {
            session,
            genesis_slot,
            ..
        } => (session, genesis_slot),
        other => panic!("expected Opened, got {other:?}"),
    };

    let table = |stream: &mut UnixStream, slot: u32, view| match ask(
        stream,
        Message::CoreAssignment {
            session,
            slot,
            view,
        },
    ) {
        Message::Assignment(table) => table,
        other => panic!("expected Assignment, got {other:?}"),
    };

    let cores = jam_types::core_count() as usize;
    for view in [AssignmentView::Storage, AssignmentView::Epoch] {
        let assignment = table(&mut stream, genesis_slot, view);
        assert_eq!(assignment.len(), cores, "one entry per core");
        let holders: Vec<u16> = assignment.iter().flatten().flatten().copied().collect();
        assert!(!holders.is_empty(), "{view:?} resolves at genesis");
        for v in &holders {
            assert!((*v as usize) < 6, "a validator index");
        }
    }

    // A slot many epochs away is outside the two epochs the chain holds, so
    // the epoch view cannot resolve it. Answering `None` is the point: an
    // empty cohort would read as "nobody holds this core".
    let far = genesis_slot + jam_types::epoch_period() * 50;
    let unreachable = table(&mut stream, far, AssignmentView::Epoch);
    assert!(
        unreachable.iter().all(|core| core.is_none()),
        "an out-of-reach slot resolves to nothing, not to an empty cohort: {unreachable:?}"
    );

    // The probe reads both entropy entries, which is the whole reason it
    // exists: the cached epoch's assignment is built from entry 1 and the
    // storage view's from entry 2, and seeing both is how a run tells which
    // of them a node agreed with.
    match ask(&mut stream, Message::EpochProbe(session)) {
        Message::EpochProbed {
            cached_index,
            head_epoch,
            entropy_1,
            entropy_2,
        } => {
            assert_eq!(head_epoch, genesis_slot / jam_types::epoch_period());
            assert_eq!(cached_index, head_epoch, "at genesis the two agree");
            assert_ne!(entropy_1, [0u8; 32], "genesis entropy is not zero");
            assert_ne!(entropy_2, [0u8; 32]);
        }
        other => panic!("expected EpochProbed, got {other:?}"),
    }
}

/// Author one block per authorable slot in `slots`, returning them encoded.
fn author_over(stream: &mut UnixStream, session: u16, slots: std::ops::Range<u32>) -> Vec<Vec<u8>> {
    let mut blocks = Vec::new();
    for slot in slots {
        match ask(stream, Message::AuthorBlock { session, slot }) {
            Message::Authored(Some(block)) => blocks.push(block),
            Message::Authored(None) => {}
            other => panic!("authoring slot {slot}: {other:?}"),
        }
    }
    blocks
}

fn decode(block: &[u8]) -> jam_std_common::Block {
    use jam_types::Decode;
    let mut cursor = block;
    let decoded = jam_std_common::Block::decode(&mut cursor).expect("the block decodes");
    assert!(cursor.is_empty(), "the block has trailing bytes");
    decoded
}

/// A session never authors for a validator it was not given.
///
/// This is the one property the whole arrangement rests on. A session that
/// signs for a validator the run is emulating elsewhere -- the node under
/// test, most of all -- produces blocks that prove something nobody did,
/// and the lane grading them has no way to tell. So: six sessions, each
/// missing a different validator, and no block from any of them carries the
/// index that session was not given.
#[test]
fn a_session_authors_only_for_the_validators_it_holds() {
    let oracle = start("holds");
    let mut stream = UnixStream::connect(&oracle.path).expect("connect");

    for excluded in 0u16..6 {
        let holds: Vec<u16> = (0..6).filter(|v| *v != excluded).collect();
        let (session, genesis_slot) = match ask(
            &mut stream,
            Message::Open {
                spec_path: String::new(),
                holds,
            },
        ) {
            Message::Opened {
                session,
                genesis_slot,
                ..
            } => (session, genesis_slot),
            other => panic!("expected Opened, got {other:?}"),
        };

        let blocks = author_over(&mut stream, session, genesis_slot + 1..genesis_slot + 13);
        assert!(
            !blocks.is_empty(),
            "excluding {excluded}: nothing was authored in 12 slots, so the \
             assertion below proves nothing"
        );
        for encoded in &blocks {
            let block = decode(encoded);
            assert_ne!(
                block.header.author_index, excluded,
                "a session without validator {excluded}'s key authored as it"
            );
        }

        match ask(&mut stream, Message::Close(session)) {
            Message::Done => {}
            other => panic!("expected Done, got {other:?}"),
        }
    }
}

/// Two sessions over one spec author the same blocks.
///
/// The engine holds the only randomness in a run, and the oracle serves
/// requests serially, so a seed-determined run has to stay seed-determined
/// across the socket. If it does not, two runs of the same seed grade
/// differently and no verdict means anything.
#[test]
fn two_sessions_on_one_spec_author_the_same_blocks() {
    let oracle = start("deterministic");
    let mut stream = UnixStream::connect(&oracle.path).expect("connect");

    let open = |stream: &mut UnixStream| match ask(
        stream,
        Message::Open {
            spec_path: String::new(),
            holds: (0..6).collect(),
        },
    ) {
        Message::Opened {
            session,
            genesis_slot,
            ..
        } => (session, genesis_slot),
        other => panic!("expected Opened, got {other:?}"),
    };

    let (a, genesis_slot) = open(&mut stream);
    let (b, _) = open(&mut stream);
    let slots = genesis_slot + 1..genesis_slot + 9;

    let from_a = author_over(&mut stream, a, slots.clone());
    let from_b = author_over(&mut stream, b, slots);
    assert!(!from_a.is_empty(), "something was authored");
    assert_eq!(from_a, from_b, "the same spec authors the same blocks");
}

/// The genesis state root is what the first block declares as its prior.
///
/// Two different quantities that are easy to confuse -- a header hash and a
/// state root are both 32 bytes -- and the N1 lane compares them for a
/// living. This pins the relation at the one place it is knowable without
/// trusting either side: the first block's parent is genesis, so its
/// `parent_state_root` *is* the genesis state root.
#[test]
fn the_genesis_state_root_is_the_first_blocks_declared_prior() {
    let oracle = start("roots");
    let mut stream = UnixStream::connect(&oracle.path).expect("connect");

    let (session, genesis_hash, genesis_slot) = match ask(
        &mut stream,
        Message::Open {
            spec_path: String::new(),
            holds: (0..6).collect(),
        },
    ) {
        Message::Opened {
            session,
            genesis_hash,
            genesis_slot,
        } => (session, genesis_hash, genesis_slot),
        other => panic!("expected Opened, got {other:?}"),
    };

    let genesis_root = match ask(
        &mut stream,
        Message::StateRootOf {
            session,
            hash: genesis_hash,
        },
    ) {
        Message::StateRoot(root) => root,
        other => panic!("expected StateRoot, got {other:?}"),
    };
    assert_ne!(
        genesis_root, genesis_hash,
        "the state root is not the header hash"
    );

    let blocks = author_over(&mut stream, session, genesis_slot + 1..genesis_slot + 13);
    let first = decode(blocks.first().expect("a slot is authorable"));
    assert_eq!(first.header.parent.0, genesis_hash);
    assert_eq!(first.header.parent_state_root.0, genesis_root);
}

/// What an import says when it refuses, and when it has seen the block.
///
/// The lane reads three roots off an import and the engine's own wording
/// for a refusal, which is why `ImportInto` answers with all of it rather
/// than the fuzz protocol's bare state root.
#[test]
fn an_import_reports_its_roots_and_its_refusals() {
    use jam_types::Encode;

    let oracle = start("import");
    let mut stream = UnixStream::connect(&oracle.path).expect("connect");

    let open = |stream: &mut UnixStream| match ask(
        stream,
        Message::Open {
            spec_path: String::new(),
            holds: (0..6).collect(),
        },
    ) {
        Message::Opened {
            session,
            genesis_slot,
            ..
        } => (session, genesis_slot),
        other => panic!("expected Opened, got {other:?}"),
    };
    // Authored in one session, imported into another that has never seen
    // it: a block already in a chain short-circuits to "already imported"
    // before any verification runs, so a corrupt one has to arrive
    // somewhere fresh to be judged at all.
    let (author, genesis_slot) = open(&mut stream);
    let (importer, _) = open(&mut stream);

    let blocks = author_over(&mut stream, author, genesis_slot + 1..genesis_slot + 13);
    let encoded = blocks.first().expect("a slot is authorable").clone();
    let block = decode(&encoded);

    let import = |stream: &mut UnixStream, session: u16, block: Vec<u8>| match ask(
        stream,
        Message::ImportInto { session, block },
    ) {
        Message::Imported {
            ok,
            root,
            parent_root,
            error,
        } => (ok, root, parent_root, error),
        other => panic!("expected Imported, got {other:?}"),
    };

    let (ok, root, parent_root, error) = import(&mut stream, importer, encoded.clone());
    assert!(ok, "a well-formed block imports: {error:?}");
    assert_eq!(error, None);
    assert_eq!(
        parent_root,
        Some(block.header.parent_state_root.0),
        "a well-formed block's declared prior root is the reference's own"
    );
    assert_ne!(
        root,
        Some(block.header.hash().0),
        "the posterior state root is not the header hash"
    );

    // Importing it again is accepted, not refused: the question the lane
    // asks is whether the block is acceptable, not whether it is new.
    let (again, again_root, _, again_error) = import(&mut stream, importer, encoded);
    assert!(again, "a known block re-imports: {again_error:?}");
    assert_eq!(again_error, None);
    assert_eq!(again_root, root);

    // A body that does not match the header's extrinsic hash is refused,
    // and the refusal carries the engine's own words. It needs a session
    // that has never seen this header: corrupting the body leaves the
    // header hash alone, and a chain that already holds that hash
    // short-circuits to "already imported" without verifying anything --
    // which is what the two imports above just did to `importer`.
    let mut corrupt = block;
    let mut bogus = jam_std_common::Extrinsic::default();
    bogus
        .tickets
        .try_push(jam_std_common::TicketEnvelope {
            attempt: 0,
            // 32 + 752, the same number `WireTicket::proof` carries.
            signature: jam_std_common::bandersnatch::ring_vrf::Signature([0xab; 784]),
        })
        .expect("the tiny spec allows tickets in a block");
    corrupt.extrinsic = std::sync::Arc::new(bogus);

    let (fresh, _) = open(&mut stream);
    let (ok, root, _, error) = import(&mut stream, fresh, corrupt.encode());
    assert!(!ok, "a corrupt body is refused");
    assert!(error.is_some(), "a refusal says why");
    assert_eq!(root, None);
}
