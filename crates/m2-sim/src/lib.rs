//! A node-shaped stand-in the harness can grade, honest or broken one named
//! way at a time.
//!
//! A check is an assertion about a node, and until a node makes the mistake it
//! describes nobody knows whether it can fail. Every run this harness had done
//! was against polkajam, which does not make those mistakes -- which is how
//! two harness defects survived for weeks. [`SimFault`] is the answer: a check
//! that fails against the broken node and passes against the honest one has
//! been shown to work.
//!
//! [`SimNode`] speaks UP 0, CE 128/129 and CE 131/132 over whatever
//! [`jamnp_s::transport`] it is handed, authors its own slots and runs the
//! Safrole lottery.
//!
//! **A stand-in, not a node**: it keeps no state machine and serves from the
//! reference chain. The honest variant passing a check means the check is
//! satisfiable, not that polkajam would satisfy it; the evidence runs the
//! other way, from the faults.

#![deny(unsafe_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_consensus::SigningKey;
use jam_std_common::{
    bandersnatch::ring_vrf, Block, Extrinsic, ReportGuarantee, TicketEnvelope, ValSignature,
    WorkReport,
};
use jam_types::{Decode, Encode, HeaderHash, WorkPackageHash};
use jamnp_s::clock;
use jamnp_s::codec::ce128_129::{
    BlockRequest, BlockResponse, BoundaryNode, Direction, KeyValue, StateRequest, StateResponse,
};
use jamnp_s::codec::ce131_136::{self, GuaranteedWorkReport, Ticket, TicketDistribution};
use jamnp_s::codec::ce137_148;
use jamnp_s::codec::ce141_145::{Assurance, PreimageAnnouncement, PreimageRequest};
use jamnp_s::codec::up0::{Announcement, Final, Handshake};
use jamnp_s::endpoint::{EndpointConfig, EndpointError};
use jamnp_s::framing::{
    frame, frame_message, FrameReader, CE128, CE129, CE131, CE132, CE133, CE134, CE135, CE137,
    CE138, CE139, CE140, CE141, CE142, CE143, CE146, CE148, UP,
};
use jamnp_s::transport::{Conn, RecvHalf, SendHalf, Transport};
use m2_reference::chain::RefChain;
use m2_reference::tickets::{proxy_index, ticket_id, verify_ticket};
use tokio::sync::broadcast;

/// What this node gets wrong: one at a time, each the smallest deviation that
/// should cost one named row. A fault breaking two things leaves it unclear
/// which check caught which.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SimFault {
    /// Behave.
    #[default]
    None,
    /// Never answer UP 0. The stream stays open and nothing is said on it.
    SilentOnUp0,
    /// Answer UP 0 naming a finalized head that is not genesis.
    FinalIsNotGenesis,
    /// Never re-announce a block the peer announced.
    NeverReannounces,
    /// Answer an ascending CE 128 walk newest-first.
    Ce128Descending,
    /// Never answer CE 128.
    Ce128Silent,
    /// Announce an authored block two slots late. The block is untouched:
    /// forging the header would break the seal and fail several rows at once.
    AnnouncesLate,
    /// Name the epoch after the one the ticket was proved for.
    TicketWrongEpoch,
    /// Claim an attempt index at the per-validator cap, which is one past the
    /// last legal one.
    TicketAttemptOverCap,
    /// Send a ticket to a validator that is not its designated proxy.
    TicketWrongProxy,
    /// Distribute at phase 0, the epoch boundary itself, where the entropy a
    /// ticket is sealed against has only just rotated.
    TicketAtEpochStart,
    /// Broadcast a self-proxied ticket to every validator but one.
    SelfProxyMissesAPeer,
    /// Distribute no tickets at all.
    SendsNoTickets,
    /// Send a CE 131 ticket whose ring proof does not verify.
    TicketBadProof,
    /// Broadcast a CE 132 ticket whose ring proof does not verify.
    SelfProxyBadProof,
    /// Send one ticket to its designated proxy *and* to the next validator
    /// along, so two validators hold a ticket only one of them proxies.
    TicketToTwoProxies,
    /// Accept a ticket proxied to it and never pass it on.
    NeverForwards,
    /// Accept a ticket whose ring proof does not verify, instead of refusing
    /// it by resetting the stream it arrived on.
    AcceptsBadProof,
    /// Answer an assurance it will not pool by closing the whole connection,
    /// where refusing costs the stream it arrived on and nothing else
    /// (`simple.md:115-120`). Every other protocol with that validator goes
    /// with it (`findings.md` §30).
    ClosesOnBadAssurance,
    /// Refuse an over-cap work-package submission by closing the whole
    /// connection rather than resetting the stream.
    ///
    /// What polkajam does: `read_exact` makes a size mismatch a
    /// `Misbehaviour`, and a misbehaviour closes the connection
    /// (`findings.md` §8). The node *is* enforcing the rule, which is why
    /// the N3 row must read this as a refusal and not as acceptance.
    ClosesOnOversizedPackage,
    /// Read a CE 142 announcement and never follow it up over CE 143,
    /// where `simple.md:705-707` expects a node that can use the preimage
    /// to ask for it.
    IgnoresPreimageAnnouncement,
    /// Follow up an announcement by asking for a different hash.
    ///
    /// Not a plausible node, and that is the point: it separates "the node
    /// opened CE 143" from "the node asked for what it was told about",
    /// which one row each.
    AsksForAnotherPreimage,
    /// Follow up *every* announcement, including one for a preimage no
    /// service solicited.
    ///
    /// The stand-in has no chain and so asks for everything by default;
    /// this variant is what the honest one is *not*, and the honest one
    /// declines an unsolicited announcement so the lane's negative row has
    /// a node that passes it.
    AsksForUnsolicitedPreimages,
    /// Accept a ticket for an epoch past its horizon, instead of resetting
    /// the stream (`simple.md:335-337`).
    AcceptsUnknownEpoch,
    /// Forward every proxied ticket twice, a slot apart, both while the
    /// lottery is still open.
    ///
    /// Not itself a defect -- the stopping rule bounds forwarding *after*
    /// finality, not repetition before it -- but it is what gives that rule
    /// something to bound. Against a node that forwards each ticket once the
    /// rule holds however it is written, and the row reports itself
    /// unexercised.
    RepeatsForwards,
    /// Forward a ticket again after a block of this node's own carried it and
    /// was announced as final.
    ReForwardsAfterFinality,
    /// Return more blocks than the request's `max_blocks` allows.
    Ce128OverMax,
    /// Finish the CE 128 stream in the middle of a frame.
    ///
    /// Not "never FIN": the probe has no timeout, so a node that holds the
    /// stream open produces no probe at all and the row is never reported. A
    /// dirty close is the reachable defect -- the complete response still
    /// decodes, and only the end of the stream is wrong.
    Ce128DirtyClose,
    /// Dial nobody, including the peers this node is preferred initiator for.
    NeverDials,
    /// Dial every peer, including the ones that should dial this node.
    DialsEveryone,
    /// Return CE 129 keys out of ascending order.
    Ce129UnsortedKeys,
    /// Return boundary nodes with a child before its parent.
    Ce129ChildBeforeParent,
    /// Return more key/value bytes than the request's `max_size` allows.
    Ce129OverSize,
    /// Refuse a CE 129 request by resetting its stream.
    Ce129Refuses,
    /// Serve a block whose extrinsic carries the same ticket twice.
    ///
    /// The body is rewritten after authoring, so the header -- and therefore
    /// the hash the harness fetches by -- is untouched and only the extrinsic
    /// disagrees with it. That is the one way to produce an extrinsic the
    /// authoring engine will not: its pool rejects duplicates and orders by
    /// id. The same rewrite necessarily fails N1's seal row, because the body
    /// no longer matches the header's extrinsic hash; these rows cannot be
    /// reached without that.
    ServesDuplicateTicket,
    /// Serve a block authored in the epoch tail with a ticket in it.
    ///
    /// Rewritten the same way and for the same reason: past
    /// `epoch_tail_start` the provisioner offers no tickets at all, so a tail
    /// block the engine authored is always empty.
    ServesTicketsInTail,
    /// Hold a proxied ticket until the lottery has shut, then forward it.
    ///
    /// The forward itself is well formed and goes to every validator; only
    /// its slot is wrong. Nothing can act on a ticket distributed past
    /// `epoch_tail_start`, so passing it on then is the proxy doing its duty
    /// too late to be a duty.
    ForwardsInTail,
    /// Take delivery of a ticket and never offer it to its own pool, so the
    /// block it authors leaves it out. Seals just as validly.
    OmitsDeliveredTickets,

    // --- N4: availability ------------------------------------------------
    /// Reset a CE 137/138 bundle-shard request instead of serving it.
    ShardRefused,
    /// Serve the *next* validator's bundle shard with this one's
    /// justification.
    ///
    /// Both halves are genuine and neither is the pair the root commits to,
    /// so the justification is the only thing that can catch it. A random
    /// shard would also fail a length check and leave it unclear which rule
    /// did the work.
    ShardWrongBytes,
    /// Serve the right shard with a justification whose co-path has been
    /// altered.
    ///
    /// A byte inside an element rather than its discriminator: the message
    /// still decodes as a sequence of elements, so the proof is what fails
    /// and not the structure.
    ShardBadJustification,
    /// Stop a CE 137 reply after two messages, which is what CE 138 owes and
    /// one short of CE 137's.
    ///
    /// The segment shards are the message left out. Nothing in a reply says
    /// how long it is, so a node that stops early looks exactly like one
    /// that finished -- which is the row's whole reason for counting.
    ShardReplyShort,
    /// Serve CE 139/140 slices one byte short of a whole number of them.
    SegmentShardsRagged,
    /// Serve fewer slices than the request asked for.
    SegmentShardsShort,
    /// Reset every CE 148 segment request.
    ///
    /// Not a breach on its own: a requester is meant to fall back to CE
    /// 139/140 (`simple.md:663`), which is why the row that catches this is
    /// Soft. It is here so that the row has been seen to move at all.
    SegmentsRefused,
    /// Serve CE 148 segments one byte short of a whole number of them.
    SegmentsRagged,
    /// Serve fewer whole segments than the request asked for.
    SegmentsShort,
    /// Stop a CE 148 reply after the segments, with no proof message.
    SegmentsReplyShort,
    /// Serve CE 148 segments with an import proof that does not prove them.
    SegmentProofBad,
    /// Serve CE 140 slices with justifications that do not prove them.
    SegmentJustificationBad,
    /// Assure a block that was never authored.
    ///
    /// Signed genuinely, so only the anchor is wrong.
    AssuranceWrongAnchor,
    /// Sign an assurance with another validator's key.
    AssuranceBadSignature,
    /// Set a bit for a core that carried no report.
    AssuranceEmptyCore,
    /// Send the assurance after its slot has begun rather than before it.
    AssuranceLate,
    /// Reset every CE 133 and CE 146 submission stream.
    ///
    /// A guarantor that takes no work at all. The shape of a node that is
    /// wrong about which core it holds, without posing that as the fault.
    RefusesPackages,
    /// Take a work-package over its protocol's size cap.
    ///
    /// The rule the cap exists for is that a guarantor must not be made to
    /// download a huge package before it can check the authorization
    /// (`simple.md:362-364`, `simple.md:381-384`), so accepting one is the
    /// whole defect -- the node need do nothing else wrong.
    AcceptsOversizedPackage,
    /// Share a taken package with one co-guarantor instead of both.
    SharesWithOneCoGuarantor,
    /// Share a package that imports segments with no mappings at all.
    ///
    /// The plausible defect: a node that fetched its own import segments
    /// and never passed the resolution on. The co-guarantor it shared with
    /// has the bundle and no way to check the segments in it against the
    /// package they came from (`simple.md:412-415`).
    SharesNoMapping,
    /// Map some other package's hash, leaving this import unresolved.
    SharesForeignMapping,
    /// Map the right package to the wrong segments-root.
    ///
    /// Worse than sending nothing: a co-guarantor that trusts it fetches
    /// the wrong segments and refines something else. `simple.md:444-446`
    /// lets it trust them blindly, which is what makes a wrong one a
    /// defect rather than a nuisance.
    SharesWrongSegmentsRoot,
    /// Carry an assurance that should have been refused.
    ///
    /// About assurances the node *receives*, where the four above are about
    /// the one it sends. Posed by rewriting the authored body rather than by
    /// pooling the assurance, because the pool will not take it: an
    /// assurances extrinsic with a bad signature or a bit for an unengaged
    /// core makes the block invalid, and the authoring engine refuses to
    /// produce one. That is the fact underneath the row -- a node that
    /// includes an invalid assurance authors an invalid block -- so this
    /// fault fails N1's import rows in company, and the test says so.
    AssuranceIncludesInvalid,
    /// Pool nothing, so no assurance a peer sends is ever carried.
    AssuranceOmitsValid,
    /// Distribute a guarantee carrying one signature.
    ///
    /// Below the quorum a guarantee needs, and the shape of a guarantor that
    /// distributed before its co-guarantors had answered rather than after.
    ReportUnderSigned,
    /// Distribute the signatures out of order.
    ///
    /// Strictly ascending is both the stated order (`simple.md:478`) and
    /// what makes a validator signing twice impossible to express, so a
    /// node that sorts by arrival rather than by index breaks both at once.
    ReportSignaturesUnsorted,
    /// Have a validator that does not hold the core sign the guarantee.
    ///
    /// The signature is real -- the trivial keys are everyone's -- so
    /// nothing but the assignment says it does not belong, which is the
    /// point of the row.
    ReportStrangerSigns,
    /// Distribute a report refined from something other than the package
    /// the node was given.
    ///
    /// Not a corruption: a second, well-formed report over different items,
    /// which is what a node that refined the wrong bundle would produce. A
    /// report mangled in place would fail to decode and be caught a step
    /// earlier, by the row that says the distribution was well formed.
    ReportIsNotTheReference,
    /// Distribute to one validator instead of all of them.
    ReportReachesOnePeer,
    /// Pool no guarantee, so a report distributed to this node is never
    /// included in a block it authors.
    ReportNotIncluded,
    /// Reset a well-formed CE 134 share instead of answering it.
    ///
    /// A guarantor that will not refine for its co-guarantors. The share is
    /// sound, so nothing but the refusal is wrong with the exchange.
    ShareRefused,
    /// Answer a CE 134 share with a report hash that is not the one the
    /// bundle refines to.
    ///
    /// The signature is genuine and over the hash sent, so the reply is
    /// well formed and simply names the wrong report -- a node that refined
    /// something other than what it was given.
    ShareWrongHash,
    /// Answer a share offering a shard count that is not the active
    /// validator count (`simple.md:432-437`).
    ///
    /// The one rule a guarantor applies to a share before refining it, so
    /// taking the bundle anyway is the whole defect.
    ShareAcceptsBadShardCount,
    /// Share a package addressed to a core this node does not hold.
    ///
    /// The package is none of its business (`simple.md:410-415`), so the
    /// honest answer is to take the stream and do nothing with it. Sharing
    /// it is the defect `n3_ce133_not_a_guarantor_ignored` names.
    SharesForeignCore,
    /// Answer a stream it will not serve by closing the whole QUIC
    /// connection, the way polkajam does (`findings.md` §30).
    ///
    /// The close carries a code and a reason, because the N7 row is required
    /// to quote them: a row that says the node closed the connection without
    /// saying what it said about it is what made §29 take two rounds.
    ClosesConnectionOnUnknownKind,
    /// Take a stream it will not serve and then say nothing at all, holding
    /// it open until the other side gives up.
    ///
    /// Distinct from dropping it: a dropped stream ends, and the initiator
    /// learns the request is over. This one never answers and never ends,
    /// which is the outcome N7 grades as a hang.
    HangsOnUnknownKind,
    /// Never reclaim a stream that was opened and then went silent.
    ///
    /// The slow-loris defect. By default this stand-in gives up on a stream
    /// whose first message never arrives, which is what a node with a
    /// protocol timeout does; with this fault it waits for one forever, so
    /// a peer can hold streams open for nothing.
    HoldsIdleStreams,
    /// Stop serving everyone once enough streams have been opened.
    ///
    /// The flood defect, and the shape that matters: not that the flooding
    /// peer is refused -- throttling an abusive peer is correct -- but that
    /// one peer's load silences the node for every other connection too.
    /// After [`FLOOD_TOLERANCE`] streams this stand-in answers nobody.
    StopsServingUnderLoad,
}

/// Application error code the node resets a refused ticket stream with.
const TICKET_REFUSED_CODE: u32 = 1;

/// Application error code for an availability request naming a root this
/// node does not hold.
const NO_DATA_CODE: u32 = 2;

/// How many streams [`SimFault::StopsServingUnderLoad`] tolerates before it
/// stops answering anyone.
///
/// Low, because the point is to cross it quickly in a test rather than to
/// model any real node's capacity.
const FLOOD_TOLERANCE: u64 = 32;

/// How long this stand-in waits for a stream's first message before
/// reclaiming it.
///
/// Generous: every lane's emulator sends its opening frame immediately, so
/// nothing legitimate comes near this, and a bound short enough to be
/// convenient would start failing lanes for scheduling noise.
const IDLE_STREAM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Byte to flip to break a proof without moving the ticket.
///
/// Past the first 32: those are the VRF output, which *is* the id, and the id
/// picks the proxy. Corrupting them would fail the routing rows too.
const PROOF_TAIL_BYTE: usize = 100;

/// Errors starting the simulated node.
#[derive(Debug, thiserror::Error)]
pub enum SimError {
    /// The transport refused to bind.
    #[error("endpoint error: {0}")]
    Endpoint(#[from] EndpointError),
}

/// How many slots late [`SimFault::AnnouncesLate`] is.
const LATE_BY_SLOTS: u64 = 2;

/// Milliseconds of slot left when [`SimFault::AssuranceLate`] sends.
///
/// Well under the two seconds `simple.md:682-683` asks for, and well above
/// zero: the assurance is late, not sent into the following slot, so only
/// the timing row has anything to say about it.
const LATE_ASSURANCE_MARGIN_MS: u64 = 500;

/// A node-shaped peer the harness can grade.
pub struct SimNode {
    chain: Arc<RefChain>,
    genesis_hash: [u8; 32],
    fault: SimFault,
    /// Streams accepted over this node's life, for
    /// [`SimFault::StopsServingUnderLoad`].
    streams_seen: std::sync::atomic::AtomicU64,
    /// Announcements for every live UP 0 stream. Fan-out rather than a held
    /// send half, which is not clonable.
    announce: broadcast::Sender<Vec<u8>>,
    /// This node's validator index.
    index: usize,
    /// Emulated validators this node dialled, keyed by index: a ticket goes to
    /// the proxy its id names, not to whoever happens to be connected.
    peers: Mutex<Vec<(u16, Conn)>>,
    /// Blocks this node authored. Not in the harness's reference chain, so
    /// only this node can serve them when it fetches by hash over CE 128.
    own_blocks: Mutex<Vec<Block>>,
    /// Tickets this node forwarded as proxy, by id, so it can forward one
    /// again once a block of its own carries it.
    forwarded: Mutex<Vec<([u8; 32], TicketDistribution)>>,
    /// The bundle this node is a guarantor of, coded into servable shards.
    ///
    /// `None` until a test hands it one. A node that holds nothing answers
    /// every availability request the way a real one does when it has no
    /// such root: by refusing.
    available: Mutex<Option<Available>>,
    /// Validators this node opens CE 134 to when it takes a package.
    ///
    /// Injected, like everything else here: which validators hold a core
    /// with it is a fact about the chain, and a stand-in that worked it out
    /// would be grading the harness against its own arithmetic.
    sharing_peers: Mutex<Vec<u16>>,
    /// Assurances this node checked and refused, kept for the one fault
    /// that carries them anyway.
    refused_assurances: Mutex<Vec<jam_std_common::AvailabilityAssurance>>,
    /// Cores this node believes carry a report pending availability.
    ///
    /// Empty unless a test says otherwise, which is the truthful answer for
    /// a chain nothing has been guaranteed on. An assurance claiming a core
    /// outside this set is claiming one with nothing on it, and a real node
    /// refuses it -- so does this one, unless it is posing
    /// [`SimFault::AssuranceIncludesInvalid`].
    reported_cores: Mutex<Vec<u16>>,
    /// The guarantee this node distributes over CE 135 once it has taken a
    /// package, and the pieces the faults need.
    ///
    /// `None` until a test hands it one, and a node with nothing to
    /// guarantee distributes nothing -- which is what a node that was never
    /// given a package does.
    guarantee: Mutex<Option<GuaranteeOffer>>,
    /// The report hash this node answers a CE 134 share with.
    ///
    /// Injected like the guarantee it distributes, and for the same reason:
    /// the stand-in does not refine. What the rows grade is whether it
    /// answers at all, whether it refuses a share it should, and whether
    /// the hash it names is the one the reference refined -- none of which
    /// needs the refining itself to happen here.
    refines_to: Mutex<Option<[u8; 32]>>,
    /// The core this node holds, when a test has told it.
    ///
    /// `None` is a node that does not check which core a submission names,
    /// which is what every test but the not-a-guarantor one wants: there is
    /// one core in play and every package belongs to it.
    own_core: Mutex<Option<u16>>,
    /// The segments-root mapping this node puts on a CE 134 share.
    ///
    /// A real guarantor derives this: it reads the import list, resolves
    /// each work-package hash against its own chain state, and shares the
    /// answer (`simple.md:412-415`). The stand-in has no chain state to
    /// resolve against, so the test tells it -- the same bargain as
    /// [`SimNode::refines_to`], and sound for the same reason. The row
    /// grades whether the share carries the right pair, not how a node
    /// arrived at it.
    maps: Mutex<Option<(WorkPackageHash, [u8; 32])>>,
}

/// What a simulated guarantor distributes, and what it would take to get it
/// wrong.
///
/// The reports are refined through the oracle by the test rather than here.
/// Refining is the most expensive thing in a run, it happens once per
/// report rather than once per submission, and a node that refined inside
/// its own submission handler would make every test that takes a package
/// pay for it.
pub struct GuaranteeOffer {
    /// The report this node refined from the package it took.
    pub report: WorkReport,
    /// A second well-formed report, over different items, for
    /// [`SimFault::ReportIsNotTheReference`].
    ///
    /// `None` leaves that fault with nothing to pose, and the node
    /// distributes its own report as usual.
    pub other: Option<WorkReport>,
    /// Validators holding the core with this node, which is who may sign.
    ///
    /// Injected for the same reason as [`SimNode::shares_with`]: the
    /// assignment is a fact about the chain, and a stand-in that worked it
    /// out would be grading the harness against its own arithmetic.
    pub cohort: Vec<u16>,
    /// A validator that does not hold the core, for
    /// [`SimFault::ReportStrangerSigns`].
    pub stranger: u16,
    /// Slot the guarantee is stamped with.
    pub slot: u32,
}

/// A bundle this node can serve shards of.
pub struct Available {
    shards: m2_reference::availability::AvailableShards,
    /// How many segments were coded, which is what fixes the slice
    /// boundaries inside each row.
    segment_count: usize,
    /// The segments themselves, kept whole for CE 148.
    ///
    /// CE 139/140 serve erasure-coded *slices* of these and CE 148 serves
    /// the segments outright, so a node that holds only the coded form can
    /// answer the first two and not the third.
    segments: Vec<Vec<u8>>,
    /// The root those segments sit under, with one import proof each.
    tree: m2_reference::availability::SegmentTree,
}

impl SimNode {
    /// A node that serves `chain` and gets `fault` wrong.
    pub fn new(chain: Arc<RefChain>, fault: SimFault) -> Self {
        Self::at_index(chain, fault, 0)
    }

    /// A node that is validator `index` of the set.
    pub fn at_index(chain: Arc<RefChain>, fault: SimFault, index: usize) -> Self {
        let genesis_hash = chain.genesis_hash();
        Self {
            chain,
            genesis_hash,
            fault,
            streams_seen: std::sync::atomic::AtomicU64::new(0),
            index,
            peers: Mutex::new(Vec::new()),
            announce: broadcast::Sender::new(16),
            own_blocks: Mutex::new(Vec::new()),
            forwarded: Mutex::new(Vec::new()),
            available: Mutex::new(None),
            sharing_peers: Mutex::new(Vec::new()),
            refused_assurances: Mutex::new(Vec::new()),
            reported_cores: Mutex::new(Vec::new()),
            guarantee: Mutex::new(None),
            own_core: Mutex::new(None),
            refines_to: Mutex::new(None),
            maps: Mutex::new(None),
        }
    }

    /// Say what this node guarantees and distributes once it takes a
    /// package.
    pub fn guarantees(&self, offer: GuaranteeOffer) {
        *self.guarantee.lock().expect("sim guarantee") = Some(offer);
    }

    /// Say which validators hold a core with this node, so a package it
    /// takes is shared with them over CE 134.
    pub fn shares_with(&self, peers: &[u16]) {
        *self.sharing_peers.lock().expect("sim sharing peers") = peers.to_vec();
    }

    /// Say which report hash this node answers a CE 134 share with.
    pub fn refines_to(&self, report_hash: [u8; 32]) {
        *self.refines_to.lock().expect("sim refines to") = Some(report_hash);
    }

    /// Say which work-package hash this node resolves, and to which
    /// segments-root, when it shares a package that imports.
    ///
    /// Unset -- the default -- is a node that shares no mappings at all,
    /// which is what every test that submits a package importing nothing
    /// wants, and is also the honest answer for one.
    pub fn maps(&self, package: WorkPackageHash, segments_root: [u8; 32]) {
        *self.maps.lock().expect("sim maps") = Some((package, segments_root));
    }

    /// Say which core this node guarantees on, so it can tell a package
    /// that is its business from one that is not.
    ///
    /// Injected like the rest of the assignment. `None` -- the default --
    /// is a node that does not check, which takes and shares whatever it is
    /// sent.
    pub fn guards_core(&self, core: u16) {
        *self.own_core.lock().expect("sim own core") = Some(core);
    }

    /// Say which cores this node has a report pending availability on.
    ///
    /// What a real node reads out of its own state. Injected here for the
    /// same reason everything else in this stand-in is: it has no state
    /// machine, and a value it invented would be this harness agreeing with
    /// itself.
    pub fn reports_on_cores(&self, cores: &[u16]) {
        *self.reported_cores.lock().expect("sim reported cores") = cores.to_vec();
    }

    /// Code `bundle` and `segments` into shards this node will serve.
    ///
    /// The coding and the justifications are the engine's, through the
    /// oracle: a stand-in that built its own would be proving the harness
    /// agrees with itself rather than that it agrees with a node.
    pub fn hold_available(
        &self,
        bundle: Vec<u8>,
        segments: Vec<Vec<u8>>,
        shard_count: u16,
    ) -> Result<([u8; 32], [u8; 32]), m2_reference::chain::ChainError> {
        let segment_count = segments.len();
        let shards = m2_reference::availability::make_available(
            self.chain.oracle(),
            bundle,
            segments.clone(),
            shard_count,
        )?;
        // The segments root is a second tree over the same segments, and a
        // different question from the erasure root: one commits to the
        // coded shards, the other to the segments themselves. A guarantor
        // publishes both on its report, and CE 148 asks by the second.
        let tree =
            m2_reference::availability::make_segments(self.chain.oracle(), segments.clone())?;
        let roots = (shards.erasure_root, tree.segments_root);
        *self.available.lock().expect("sim available") = Some(Available {
            shards,
            segment_count,
            segments,
            tree,
        });
        Ok(roots)
    }

    /// Announce a block this node authored, and keep it to serve.
    ///
    /// Stored before announced: the harness fetches by hash the moment it
    /// hears the announcement.
    pub fn publish(self: &Arc<Self>, block: Block) {
        // A simulated node that cannot reach the oracle has nothing to
        // announce. Saying so beats announcing nothing quietly, which the
        // lane would read as the node staying silent.
        let wire = match m2_emu::emu::announcement_wire(&block, &self.chain) {
            Ok(wire) => wire,
            Err(e) => {
                eprintln!("[sim] could not build an announcement: {e}");
                return;
            }
        };
        let block = self.rewrite_body(block);
        if self.fault == SimFault::ReForwardsAfterFinality {
            // Announcing this block names it final, so anything it carries is
            // finalized-included from here. Forwarding one again a slot later
            // is what the stopping rule forbids.
            let carried: Vec<[u8; 32]> = block.extrinsic.tickets.iter().map(|t| t.id().0).collect();
            let again: Vec<TicketDistribution> = self
                .forwarded
                .lock()
                .expect("sim forwards")
                .iter()
                .filter(|(id, _)| carried.contains(id))
                .map(|(_, d)| *d)
                .collect();
            if !again.is_empty() {
                let node = Arc::clone(self);
                tokio::spawn(async move {
                    clock::current()
                        .sleep(Duration::from_millis(jam_types::slot_period_sec() * 1000))
                        .await;
                    for distribution in again {
                        node.broadcast_ticket(&distribution).await;
                    }
                });
            }
        }
        self.own_blocks.lock().expect("sim blocks").push(block);
        if self.fault == SimFault::AnnouncesLate {
            let node = Arc::clone(self);
            tokio::spawn(async move {
                let slot_ms = jam_types::slot_period_sec() * 1000;
                clock::current()
                    .sleep(Duration::from_millis(LATE_BY_SLOTS * slot_ms))
                    .await;
                let _ = node.announce.send(wire);
            });
            return;
        }
        let _ = self.announce.send(wire);
    }

    /// The state slice this node answers CE 129 with.
    ///
    /// The reference chain exports no state, so an honest answer is empty --
    /// and an empty answer satisfies every content rule vacuously. These
    /// faults supply content that breaks exactly one of them.
    fn state_response(&self, request: &StateRequest) -> StateResponse {
        let in_range = |n: u8| {
            let mut key = request.start;
            key[30] = key[30].saturating_add(n);
            key
        };
        match self.fault {
            SimFault::Ce129UnsortedKeys => StateResponse {
                boundary_nodes: vec![],
                entries: vec![
                    KeyValue {
                        key: in_range(2),
                        value: vec![1],
                    },
                    KeyValue {
                        key: in_range(1),
                        value: vec![2],
                    },
                ],
            },
            SimFault::Ce129ChildBeforeParent => {
                // A parent refers to a child by blake2b-256 of its 64 bytes
                // with the top bit cleared -- that bit is the branch/leaf
                // discriminator, not part of the hash. So the parent has to be
                // built from the child's hash, and listed after it.
                let child = [0x11u8; 64];
                let digest = blake2b_simd::Params::new().hash_length(32).hash(&child);
                let mut parent = [0u8; 64];
                parent[..32].copy_from_slice(digest.as_bytes());
                parent[0] &= 0b0111_1111;
                StateResponse {
                    boundary_nodes: vec![BoundaryNode(child), BoundaryNode(parent)],
                    entries: vec![],
                }
            }
            SimFault::Ce129OverSize => StateResponse {
                boundary_nodes: vec![],
                entries: (0..3)
                    .map(|i| KeyValue {
                        key: in_range(i),
                        value: vec![0u8; request.max_size as usize],
                    })
                    .collect(),
            },
            _ => m2_emu::emu::serve_ce129(request),
        }
    }

    /// Rewrite a block's extrinsic, for the two faults that need a body the
    /// authoring engine will not produce.
    ///
    /// Only the body: the header is left as authored, so the block keeps the
    /// hash it was announced under and the harness can still fetch it.
    fn rewrite_body(&self, block: Block) -> Block {
        if self.fault == SimFault::AssuranceIncludesInvalid {
            return self.carry_refused_assurances(block);
        }
        let tail = block.header.slot % jam_types::epoch_period() >= jam_types::epoch_tail_start();
        let seed = match self.fault {
            SimFault::ServesDuplicateTicket if !tail => block.extrinsic.tickets.first().cloned(),
            SimFault::ServesTicketsInTail if tail => self
                .own_blocks
                .lock()
                .expect("sim blocks")
                .iter()
                .find_map(|b| b.extrinsic.tickets.first().cloned()),
            _ => None,
        };
        let Some(ticket) = seed else {
            return block;
        };
        let mut extrinsic = Extrinsic::default();
        let repeats = if self.fault == SimFault::ServesDuplicateTicket {
            2
        } else {
            1
        };
        for _ in 0..repeats {
            if extrinsic.tickets.try_push(ticket.clone()).is_err() {
                break;
            }
        }
        let mut block = block;
        block.extrinsic = Arc::new(extrinsic);
        block
    }

    /// Add the refused assurances this block's parent was assured by.
    ///
    /// Only the ones anchored at the parent. An assurance naming any other
    /// block cannot be carried here at all -- the on-chain rule refuses an
    /// assurances extrinsic whose anchor is not the block's parent -- so the
    /// wrong-anchor fault stays out even on a node checking nothing, and it
    /// is the other two that make the row fail.
    fn carry_refused_assurances(&self, block: Block) -> Block {
        let parent = block.header.parent;
        let refused: Vec<jam_std_common::AvailabilityAssurance> = self
            .refused_assurances
            .lock()
            .expect("sim refused assurances")
            .iter()
            .filter(|a| a.statement.anchor == parent)
            .cloned()
            .collect();
        if refused.is_empty() {
            return block;
        }
        let mut extrinsic = (*block.extrinsic).clone();
        for assurance in refused {
            // Sorted by validator index, which is what the extrinsic's own
            // rule asks for. A node this careless about the assurances would
            // plausibly be careless about the order too, but an unsorted
            // extrinsic is a *second* defect and the row would no longer say
            // which one it caught.
            let at = extrinsic
                .assurances
                .iter()
                .position(|a| a.signature.val_index > assurance.signature.val_index)
                .unwrap_or(extrinsic.assurances.len());
            if extrinsic.assurances.try_insert(at, assurance).is_err() {
                break;
            }
        }
        let mut block = block;
        block.extrinsic = Arc::new(extrinsic);
        block
    }

    /// Dial the emulated validators, keyed by index. A peer that cannot be
    /// reached is skipped: the duty to the others stands.
    pub async fn connect_to(
        self: &Arc<Self>,
        transport: &Arc<dyn Transport>,
        secret: SigningKey,
        peers: &[(u16, SocketAddr, String)],
    ) {
        for (index, addr, san) in peers {
            let config = EndpointConfig {
                genesis_hash: self.genesis_hash,
                builder: false,
            };
            if let Ok(conn) = transport
                .connect(config, secret.clone(), san.clone(), *addr)
                .await
            {
                self.peers
                    .lock()
                    .expect("sim peers")
                    .push((*index, Arc::clone(&conn)));
                // Serve it too: the peer sends tickets on whichever
                // connection it has, so a node that served only inbound ones
                // silently ignores every ticket proxied over an outbound.
                tokio::spawn(Arc::clone(self).serve_connection(conn, Some(*index)));
            }
        }
    }

    /// Dial only the peers this node is the preferred initiator for
    /// (`simple.md:70-80`), and wait to be dialled by the rest.
    ///
    /// Separate from [`SimNode::connect_to`], which dials everything it is
    /// given: the ticket lanes need a path to every validator for CE 132, and
    /// in a live run the node has one either way because the peers dial it.
    /// Here the point is *who opened the connection*, so the split has to be
    /// the node's own decision.
    pub async fn dial_preferred(
        self: &Arc<Self>,
        transport: &Arc<dyn Transport>,
        secret: SigningKey,
        peers: &[(u16, SocketAddr, String)],
    ) {
        if self.fault == SimFault::NeverDials {
            return;
        }
        let mine = validator_key(self.index);
        let chosen: Vec<(u16, SocketAddr, String)> = peers
            .iter()
            .filter(|(index, _, _)| {
                self.fault == SimFault::DialsEveryone
                    || jamnp_s::preferred::preferred_initiator(
                        &mine,
                        &validator_key(usize::from(*index)),
                    )
            })
            .cloned()
            .collect();
        self.connect_to(transport, secret, &chosen).await;
    }

    /// Run the Safrole lottery for `target_epoch` and distribute it: CE 132
    /// to every validator for a ticket it proxies itself, CE 131 to the
    /// designated proxy alone otherwise (`simple.md:305-349`).
    pub async fn run_lottery(self: &Arc<Self>, target_epoch: u32) {
        if self.fault == SimFault::SendsNoTickets {
            return;
        }
        if self.fault != SimFault::TicketAtEpochStart {
            // Phase 0 is the boundary itself, where the entropy a ticket is
            // sealed against has only just rotated.
            let period = u64::from(jam_types::epoch_period());
            let slot = u64::from(m2_reference::chain::wall_clock_slot());
            if slot % period == 0 {
                let ms = jam_types::slot_period_sec() * 1000;
                clock::current().sleep(Duration::from_millis(ms)).await;
            }
        }
        let Ok(ctx) = self.chain.ticket_ctx() else {
            return;
        };
        // Its own only: proving the other five would cost five times the
        // ring-VRF work for nothing.
        let Ok(mut tickets) = self.chain.generate_tickets_for(&ctx, self.index) else {
            return;
        };
        if self.fault == SimFault::TicketAttemptOverCap {
            // Its last honest attempt swapped for one at the cap, signed over
            // that attempt: the count stays within the cap and the proof
            // verifies, so the attempt row is the only one broken.
            let cap = jam_types::tickets_per_validator(jam_types::max_val_count());
            let Ok(Some(over)) = self.chain.generate_ticket_at(&ctx, self.index, cap) else {
                return;
            };
            tickets.pop();
            tickets.push(over);
        }
        let val_count = usize::from(jam_types::max_val_count());
        for ticket in tickets.iter() {
            let attempt = ticket.attempt;
            let epoch = if self.fault == SimFault::TicketWrongEpoch {
                target_epoch.saturating_add(1)
            } else {
                target_epoch
            };
            let self_proxied = ticket.proxy == self.index;
            let mut proof = ticket.proof;
            let break_proof = match self.fault {
                SimFault::TicketBadProof => !self_proxied,
                SimFault::SelfProxyBadProof => self_proxied,
                _ => false,
            };
            if break_proof {
                proof[PROOF_TAIL_BYTE] ^= 0xff;
            }
            let wire = TicketDistribution {
                epoch_index: epoch,
                ticket: Ticket { attempt, proof },
            };
            if self_proxied {
                self.broadcast_ticket(&wire).await;
            } else {
                let proxy = if self.fault == SimFault::TicketWrongProxy {
                    // The next validator along that is not us, which is a
                    // peer the rule did not name. Landing on ourselves would
                    // send nothing at all.
                    let next = (ticket.proxy + 1) % val_count;
                    if next == self.index {
                        (next + 1) % val_count
                    } else {
                        next
                    }
                } else {
                    ticket.proxy
                };
                self.send_ticket(CE131, proxy as u16, &wire).await;
                if self.fault == SimFault::TicketToTwoProxies {
                    let second = (proxy + 1) % val_count;
                    if second != self.index {
                        self.send_ticket(CE131, second as u16, &wire).await;
                    }
                }
            }
        }
    }

    /// Wait until the lottery has shut for this epoch, or the next one if it
    /// already has.
    async fn sleep_until_tail(&self) {
        let period = jam_types::epoch_period();
        let now = m2_reference::chain::wall_clock_slot();
        let tail = now - now % period + jam_types::epoch_tail_start();
        let tail = if tail <= now { tail + period } else { tail };
        let target = m2_reference::chain::slot_start_ms(tail);
        if let Some(wait) = target.checked_sub(clock::current().wall_ms()) {
            clock::current().sleep(Duration::from_millis(wait)).await;
        }
    }

    /// CE 132: a self-proxied ticket goes to every current validator.
    async fn broadcast_ticket(self: &Arc<Self>, wire: &TicketDistribution) {
        let targets: Vec<u16> = {
            let peers = self.peers.lock().expect("sim peers");
            peers.iter().map(|(index, _)| *index).collect()
        };
        let skip = (self.fault == SimFault::SelfProxyMissesAPeer)
            .then(|| targets.last().copied())
            .flatten();
        for index in targets {
            if Some(index) == skip {
                continue;
            }
            self.send_ticket(CE132, index, wire).await;
        }
    }

    /// One ticket, one stream, as a node distributes them.
    async fn send_ticket(self: &Arc<Self>, kind: u8, peer: u16, wire: &TicketDistribution) {
        let conn = {
            let peers = self.peers.lock().expect("sim peers");
            peers
                .iter()
                .find(|(index, _)| *index == peer)
                .map(|(_, conn)| Arc::clone(conn))
        };
        let Some(conn) = conn else { return };
        let Ok((mut send, _recv)) = conn.open_bi().await else {
            return;
        };
        if send.write_all(&frame(kind, &wire.encode())).await.is_ok() {
            send.finish();
        }
    }

    /// Bind on `transport` at `addr` and serve until the returned task is
    /// dropped or aborted.
    ///
    /// The bound address is returned alongside, since a transport is free to
    /// assign the port.
    /// `Arc<Self>` because the node outlives the call: the serving task holds
    /// it, as does anything that goes on to [`SimNode::publish`].
    pub async fn listen(
        self: Arc<Self>,
        transport: Arc<dyn Transport>,
        secret: SigningKey,
        addr: SocketAddr,
    ) -> Result<(SocketAddr, tokio::task::JoinHandle<()>), SimError> {
        let listener = transport
            .listen(
                EndpointConfig {
                    genesis_hash: self.genesis_hash,
                    builder: false,
                },
                secret,
                addr,
            )
            .await?;
        let bound = listener.local_addr();
        let node = self;
        let task = tokio::spawn(async move {
            while let Some(incoming) = listener.accept().await {
                let Ok(connection) = incoming.established().await else {
                    continue;
                };
                let node = Arc::clone(&node);
                tokio::spawn(node.serve_connection(connection, None));
            }
        });
        Ok((bound, task))
    }

    /// One task per stream, for as long as the peer keeps the connection.
    ///
    /// `peer` is which validator is on the other end, where this node knows:
    /// it dialled them, so it chose the index. On a connection it accepted
    /// it is `None`, because this transport carries no peer identity and
    /// guessing one would file an assurance under a validator that never
    /// sent it.
    async fn serve_connection(self: Arc<Self>, connection: Conn, peer: Option<u16>) {
        while let Ok((send, recv)) = connection.accept_bi().await {
            let node = Arc::clone(&self);
            let connection = Arc::clone(&connection);
            tokio::spawn(node.serve_stream(connection, send, recv, peer));
        }
    }

    /// Dispatch one accepted stream on the kind byte its opening frame
    /// carries (`simple.md:122-124`).
    async fn serve_stream(
        self: Arc<Self>,
        connection: Conn,
        mut send: SendHalf,
        recv: RecvHalf,
        peer: Option<u16>,
    ) {
        // Count every accepted stream, and once a flooded node is past its
        // tolerance refuse *everyone* -- which is the defect N7's flood row
        // looks for. Refusing only the flooder would be correct behaviour
        // and would prove nothing.
        if self.fault == SimFault::StopsServingUnderLoad {
            let seen = self
                .streams_seen
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if seen >= FLOOD_TOLERANCE {
                send.reset(NO_DATA_CODE);
                return;
            }
        }
        let mut reader = StreamReader::new(recv);
        // A stream whose first message never arrives. A real node has a
        // protocol timeout for this; without one, a peer that opens streams
        // and goes silent costs the node a stream apiece for as long as it
        // likes (N7's slow-loris row). The bound is only on the *first*
        // message, so nothing mid-protocol is cut short, and every lane
        // here sends its first frame immediately.
        let first = tokio::time::timeout(IDLE_STREAM_TIMEOUT, reader.next()).await;
        let first = match first {
            Ok(first) => first,
            Err(_) => {
                if self.fault == SimFault::HoldsIdleStreams {
                    std::future::pending::<()>().await;
                }
                send.reset(NO_DATA_CODE);
                return;
            }
        };
        let Some((kind, content)) = first else {
            // No complete message arrived. A stream opened with a kind this
            // node does not serve is the N7 provocation and never carries
            // one: there is no message to send on a protocol nobody
            // defines, so the kind byte is the whole of it.
            if let Some(opened) = reader.opened_kind() {
                self.unserved_kind(&connection, opened).await;
            }
            return;
        };
        match kind {
            UP => self.serve_up0(&mut send, &mut reader, &content).await,
            CE128 => self.serve_ce128(&mut send, &content).await,
            CE129 => self.serve_ce129(&mut send, &content).await,
            CE131 | CE132 => self.receive_ticket(&mut send, kind, &content).await,
            CE137 | CE138 => self.serve_bundle_shard(&mut send, kind, &content).await,
            CE139 | CE140 => self.serve_segment_shards(&mut send, kind, &content).await,
            CE148 => self.serve_segments(&mut send, &content).await,
            CE133 | CE146 => {
                self.receive_package(&connection, &mut send, kind, &mut reader, &content)
                    .await
            }
            CE134 => self.receive_share(&mut send, &mut reader, &content).await,
            CE135 => self.receive_report(&content).await,
            CE141 => self.receive_assurance(&connection, &content, peer).await,
            CE142 => {
                self.receive_preimage_announcement(&connection, &content)
                    .await
            }
            _ => self.unserved_kind(&connection, kind).await,
        }
    }

    /// What this node does with a stream whose kind it does not serve.
    ///
    /// By default it drops the stream, which ends it — the quiet disposal
    /// N7 grades as contained. The two faults pose the other answers a real
    /// node can give, and `findings.md` §30 says polkajam gives the first.
    async fn unserved_kind(&self, connection: &Conn, _kind: u8) {
        match self.fault {
            SimFault::ClosesConnectionOnUnknownKind => {
                connection.close(257, "Unknown stream kind");
            }
            // Hold the stream forever. Returning would drop both halves and
            // end it, which is the opposite of the fault being posed.
            SimFault::HangsOnUnknownKind => std::future::pending::<()>().await,
            _ => {}
        }
    }

    /// Receive a CE 142 announcement and follow it up over CE 143
    /// (`simple.md:700-744`).
    ///
    /// The follow-up goes back on the *same* connection, which is what makes
    /// this exchange worth simulating: a node that answered on a fresh
    /// connection, or not at all, looks identical to one that never read
    /// the announcement, and only the announcer can tell the difference.
    ///
    /// The stand-in has no chain, so it cannot check whether the preimage
    /// was requested on chain -- it asks for whatever it is told about. The
    /// lane's own gate covers that condition; this covers the wire.
    async fn receive_preimage_announcement(&self, connection: &Conn, content: &[u8]) {
        if self.fault == SimFault::IgnoresPreimageAnnouncement {
            return;
        }
        let Ok(announcement) = PreimageAnnouncement::decode(&mut &content[..]) else {
            return;
        };
        // The stand-in has no chain, so "solicited" is modelled by the blob
        // itself: it follows up the one the lane solicits and declines the
        // one it never does. Crude, and enough -- the row under test is
        // whether a node *can* decline, and a node that asks for everything
        // must fail it.
        let solicited =
            announcement.hash == jam_std_common::hash_raw(&m2_reference::reports::n6_preimage());
        if !solicited && self.fault != SimFault::AsksForUnsolicitedPreimages {
            return;
        }
        let asked = if self.fault == SimFault::AsksForAnotherPreimage {
            // A hash it was never told about: the row must not credit this
            // as having followed up the announcement.
            [0xab; 32]
        } else {
            announcement.hash
        };
        let Ok((mut send, recv)) = connection.open_bi().await else {
            return;
        };
        let request = frame(CE143, &PreimageRequest { hash: asked }.encode());
        if send.write_all(&request).await.is_err() {
            return;
        }
        send.finish();
        // Read the answer so the exchange completes the way a real one does;
        // what the node then does with the blob is the inclusion row's
        // business and this stand-in authors nothing.
        let mut reader = FrameReader::with_kind(CE143);
        let mut buf = [0u8; 4096];
        let mut recv = recv;
        for _ in 0..4 {
            match recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    reader.push(&buf[..n]);
                    if matches!(reader.next_frame(), Ok(Some(_))) {
                        break;
                    }
                }
                _ => break,
            }
        }
    }

    /// Receive a work-package submission over CE 133 or CE 146
    /// (`simple.md:351-376`, `simple.md:378-404`).
    ///
    /// Two messages on CE 133, five on CE 146, then the node either FINs to
    /// take the package or resets to refuse it. The one rule applied here is
    /// the size cap, because it is the one a guarantor must apply *before*
    /// reading the rest -- that is what the message split is for.
    ///
    /// Where the cap falls is the whole difference between the protocols:
    /// CE 133 carries the core index with the package and caps the pair,
    /// CE 146 gives the package a message of its own and caps it alone. A
    /// node reading either as one value gets both wrong.
    async fn receive_package(
        &self,
        connection: &Conn,
        send: &mut SendHalf,
        kind: u8,
        reader: &mut StreamReader,
        first: &[u8],
    ) {
        // The rest of the stream is read even when the package will be
        // refused: a node that resets without draining looks, to a sender
        // mid-write, exactly like one whose connection died.
        let owed = if kind == CE146 { 5 } else { 2 };
        let mut messages = vec![first.to_vec()];
        while messages.len() < owed {
            let Some((_, content)) = reader.next().await else {
                break;
            };
            messages.push(content);
        }

        let over_cap = if kind == CE146 {
            // Message 2 is the work-package and nothing else.
            messages
                .get(1)
                .is_some_and(|package| package.len() > ce137_148::WORK_PACKAGE_MAX)
        } else {
            first.len() > ce131_136::WORK_PACKAGE_INITIAL_MAX as usize
        };
        let refuse = self.fault == SimFault::RefusesPackages
            || (over_cap && self.fault != SimFault::AcceptsOversizedPackage);
        if refuse {
            // The escalating node refuses at the connection, in polkajam's
            // own words and code, so the row is read against the shape of a
            // real close rather than an invented one.
            if over_cap && self.fault == SimFault::ClosesOnOversizedPackage {
                connection.close(
                    257,
                    &format!("Message size {} outside expected range", first.len()),
                );
                return;
            }
            send.reset(NO_DATA_CODE);
            return;
        }
        send.finish();

        // A package for a core this node does not hold is none of its
        // business: it takes the stream -- the sender is owed an answer --
        // and goes no further (`simple.md:410-415`). Not a reset, which is
        // what the lane expects for a malformed submission and not for a
        // misaddressed one.
        if !self.holds_core_of(kind, &messages) && self.fault != SimFault::SharesForeignCore {
            return;
        }
        self.share_package().await;
        self.distribute_report().await;
    }

    /// Whether this node holds the core the submission names.
    ///
    /// True when no core was injected, which is the honest answer for a
    /// test with one core in play: a stand-in that invented an assignment
    /// would be grading the harness against its own arithmetic.
    fn holds_core_of(&self, kind: u8, messages: &[Vec<u8>]) -> bool {
        let Some(mine) = *self.own_core.lock().expect("sim own core") else {
            return true;
        };
        let Some(first) = messages.first() else {
            return true;
        };
        let addressed = if kind == CE146 {
            ce137_148::BundleSubmission::decode_initial(&mut &first[..]).map(|(core, _)| core)
        } else {
            ce131_136::WorkPackageSubmission::decode_initial(&mut &first[..]).map(|(core, _)| core)
        };
        // An undecodable first message is not a question about the core.
        // The node took it, and the rows that grade its shape are elsewhere.
        addressed.map(|core| core == mine).unwrap_or(true)
    }

    /// Distribute the guaranteed work-report over CE 135
    /// (`simple.md:460-485`).
    ///
    /// What a guarantor does once its co-guarantors have answered the share:
    /// `Work-Report ++ Slot ++ len++[Validator Index ++ Ed25519 Signature]`,
    /// to every validator, one stream each.
    ///
    /// The signatures are built by
    /// [`m2_reference::reports::guarantee_signatures`] rather than here,
    /// because the harness signs the same hash the same way when it answers
    /// a CE 134 share. Two copies of that rule could drift, and a drift
    /// would read as a node signing wrongly.
    async fn distribute_report(&self) {
        let (report, mut signers, slot, stranger) = {
            let held = self.guarantee.lock().expect("sim guarantee");
            let Some(offer) = held.as_ref() else {
                return;
            };
            // A report refined from other items: well formed, signed by the
            // right cohort, and simply not the one the node was asked for.
            let report = match (self.fault, offer.other.as_ref()) {
                (SimFault::ReportIsNotTheReference, Some(other)) => other.clone(),
                _ => offer.report.clone(),
            };
            let mut cohort = offer.cohort.clone();
            cohort.sort_unstable();
            cohort.dedup();
            (report, cohort, offer.slot, offer.stranger)
        };
        if self.fault == SimFault::ReportStrangerSigns {
            // Replace rather than append: appending would push the count
            // past `VALS_PER_CORE` and fail the quorum row as well, and a
            // fault that trips two rows cannot say which one caught it.
            if let Some(last) = signers.last_mut() {
                *last = stranger;
            }
        }
        let mut signatures = m2_reference::reports::guarantee_signatures(report.hash(), &signers);
        match self.fault {
            // One signature, which is below the quorum a guarantee needs.
            SimFault::ReportUnderSigned => signatures.truncate(1),
            // Descending, so the order is wrong without any signature being.
            SimFault::ReportSignaturesUnsorted => signatures.reverse(),
            _ => {}
        }
        let wire = frame(
            CE135,
            &GuaranteedWorkReport {
                report,
                slot,
                signatures,
            }
            .encode(),
        );

        let mut peers: Vec<Conn> = {
            let held = self.peers.lock().expect("sim peers");
            held.iter().map(|(_, conn)| conn.clone()).collect()
        };
        if self.fault == SimFault::ReportReachesOnePeer {
            peers.truncate(1);
        }
        for conn in peers {
            let Ok((mut send, _recv)) = conn.open_bi().await else {
                continue;
            };
            if send.write_all(&wire).await.is_ok() {
                send.finish();
            }
        }
    }

    /// Receive a CE 134 share: refine the bundle and answer with the
    /// report's hash and a signature over it (`simple.md:439-456`).
    ///
    /// Two messages in, one out. The one rule applied before refining is
    /// the shard count, which must be the active validator count
    /// (`simple.md:432-437`) -- a guarantor that refines a bundle coded for
    /// a different set has agreed to something it cannot assure.
    ///
    /// The hash is injected rather than computed, because the stand-in does
    /// not refine. That does not weaken the rows: what they ask is whether
    /// the node answered, whether it refused a share it should have, and
    /// whether the hash it named is the reference's. The faults move each
    /// of those without touching the others.
    async fn receive_share(&self, send: &mut SendHalf, reader: &mut StreamReader, first: &[u8]) {
        // Drained whether or not the share will be refused: a reset without
        // reading looks, to a sender mid-write, like a connection that died.
        let Ok(context) = ce131_136::SharingContext::decode(&mut &first[..]) else {
            return;
        };
        let _bundle = reader.next().await;

        let acceptable = context.shard_count == jam_types::max_val_count();
        let refuse = self.fault == SimFault::ShareRefused
            || (!acceptable && self.fault != SimFault::ShareAcceptsBadShardCount);
        if refuse {
            send.reset(NO_DATA_CODE);
            return;
        }
        // Nothing to answer with. A node that was never told what the
        // bundle refines to has not refused it -- it has nothing to say,
        // and the lane reports that apart from a refusal.
        let Some(mut report_hash) = *self.refines_to.lock().expect("sim refines to") else {
            send.finish();
            return;
        };
        if self.fault == SimFault::ShareWrongHash {
            report_hash[0] ^= 0xff;
        }
        // Signed over whatever hash is being sent, so the reply is well
        // formed either way and only the hash is wrong. The signing rule is
        // the harness's own, for the reason on `guarantee_signatures`.
        let signature = m2_reference::reports::guarantee_signatures(
            jam_types::WorkReportHash::from(report_hash),
            &[self.index as u16],
        )
        .first()
        .map(|(_, signature)| *signature)
        .unwrap_or([0u8; 64]);
        let reply = ce131_136::SharingReply {
            report_hash: jam_types::WorkReportHash::from(report_hash),
            signature,
        };
        let _ = send.write_all(&frame_message(&reply.encode())).await;
        send.finish();
    }

    /// Receive a CE 135 distribution and pool it, so the next block this
    /// node authors carries it.
    ///
    /// The guarantee is taken as it arrives. A real node checks the
    /// signatures against the core's assignment first and this stand-in
    /// does not, which is survivable here in a way the assurance path is
    /// not: `note_guarantee` takes a guarantee unchecked, but block
    /// composition re-checks every one it holds and skips those that do not
    /// hold up (`guarantors/table.rs`, `context.check(guarantee)` ->
    /// `continue`). So a node that pools rubbish authors a valid block
    /// without it, where a node that pools a bad *assurance* cannot author
    /// at all.
    ///
    /// That is what makes a future "the node left the bad guarantee out"
    /// row posable through the pool, and it is not posed yet. What is posed
    /// is the other direction: a node that pools nothing.
    async fn receive_report(&self, content: &[u8]) {
        if self.fault == SimFault::ReportNotIncluded {
            return;
        }
        let mut input = content;
        let Ok(distribution) = GuaranteedWorkReport::decode(&mut input) else {
            return;
        };
        if !input.is_empty() {
            return;
        }
        let signatures: Vec<ValSignature> = distribution
            .signatures
            .into_iter()
            .map(|(val_index, signature)| ValSignature {
                val_index,
                signature: jam_std_common::ed25519::Signature(signature.into()),
            })
            .collect();
        let Ok(signatures) = signatures.try_into() else {
            // More signatures than a core has validators. The engine's
            // bounded vector refuses it, and so does a node.
            return;
        };
        let guarantee = ReportGuarantee {
            report: distribution.report,
            slot: distribution.slot,
            signatures,
        };
        if let Err(e) = self.chain.submit_guarantee(&guarantee) {
            eprintln!("[sim] could not pool a distributed guarantee: {e}");
        }
    }

    /// Open CE 134 to the co-guarantors, as a guarantor does once it has
    /// taken a package (`simple.md:406-458`).
    ///
    /// The mappings carry whatever [`SimNode::maps`] was told, which is
    /// nothing unless a test said otherwise: they map the *import* list to
    /// the roots it comes from, so a package importing nothing correctly
    /// maps nothing. The two mapping faults move that pair, one in its key
    /// and one in its value.
    async fn share_package(&self) {
        let mut peers: Vec<u16> = self
            .sharing_peers
            .lock()
            .expect("sim sharing peers")
            .clone();
        if self.fault == SimFault::SharesWithOneCoGuarantor {
            peers.truncate(1);
        }
        let mappings = match (*self.maps.lock().expect("sim maps"), self.fault) {
            (_, SimFault::SharesNoMapping) | (None, _) => Vec::new(),
            // A mapping for some other package: this import is left
            // unresolved, and a co-guarantor that trusted it would have
            // nothing to fetch.
            (Some((_, root)), SimFault::SharesForeignMapping) => {
                vec![(WorkPackageHash::from([0x9e; 32]), root)]
            }
            // The right package under the wrong root, which is worse than
            // no mapping: a co-guarantor that trusts it fetches the wrong
            // segments and refines something else.
            (Some((package, _)), SimFault::SharesWrongSegmentsRoot) => {
                vec![(package, [0x9f; 32])]
            }
            (Some(pair), _) => vec![pair],
        };
        let context = ce131_136::SharingContext {
            core_index: 0,
            shard_count: jam_types::max_val_count(),
            mappings,
        };
        let first = frame(CE134, &context.encode());
        let second = frame_message(
            &ce131_136::SharingBundle {
                bundle: vec![0xab; 32],
            }
            .encode(),
        );
        let connections: Vec<Conn> = {
            let held = self.peers.lock().expect("sim peers");
            peers
                .iter()
                .filter_map(|want| {
                    held.iter()
                        .find(|(index, _)| index == want)
                        .map(|(_, conn)| conn.clone())
                })
                .collect()
        };
        for conn in connections {
            let Ok((mut send, _recv)) = conn.open_bi().await else {
                continue;
            };
            if send.write_all(&first).await.is_ok() && send.write_all(&second).await.is_ok() {
                send.finish();
            }
        }
    }

    /// Receive a CE 141 assurance: check it, and pool it if it holds up.
    ///
    /// The whole of what `n4_ce141_inclusion` grades happens here and in the
    /// block the node goes on to author. A node carries the valid assurances
    /// its peers sent it and leaves the rest out, so the two rows are one
    /// decision seen from the block: whether these bytes reached the pool.
    ///
    /// The check is the harness's own [`m2_reference::assurance`], which is
    /// what a stand-in is for -- the independence that matters is between
    /// the node and the *grading*, and the grading reads the block. What
    /// makes the rows provable is that the two faults move this decision
    /// without touching anything else.
    async fn receive_assurance(&self, connection: &Conn, content: &[u8], peer: Option<u16>) {
        let Ok(assurance) = Assurance::decode(&mut &content[..]) else {
            return;
        };
        // A real node reads the sender's index off the connection's
        // certificate. This transport carries no peer identity, so that
        // works only for connections this node opened -- and once the
        // emulator started driving availability on both sides
        // (`findings.md` §25), a validator's assurance could arrive on one
        // it merely accepted.
        //
        // Recovered from the signature instead, which answers the same
        // question from what is on the wire: CE 141 carries no index, but
        // exactly one validator's key verifies it.
        let peer = match peer {
            Some(peer) => peer,
            None => {
                let anchor = assurance.anchor.0;
                match (0..jam_types::max_val_count()).find(|&index| {
                    m2_reference::assurance::check_assurance(&assurance, index, &[anchor]).is_ok()
                }) {
                    Some(peer) => peer,
                    // No key verifies it, so there is nobody to attribute
                    // it to and nothing to pool. A node that cannot say who
                    // sent an assurance cannot carry it.
                    None => return,
                }
            }
        };
        if self.fault == SimFault::AssuranceOmitsValid {
            return;
        }
        let received = m2_reference::assurance::as_received(&assurance, peer);
        if self.assurance_holds(&assurance, peer) {
            let _ = self.chain.submit_assurances(&[received]);
            return;
        }
        // The defect this fault poses: answer the refusal at the connection
        // rather than at the stream. The code and wording are the ones
        // polkajam sends (`findings.md` §30), so the row is read against the
        // shape of a real close.
        if self.fault == SimFault::ClosesOnBadAssurance {
            connection.close(257, "Bad assurance: Invalid message");
            return;
        }
        // Refused, and remembered only by the node that carries what it
        // refused. The pool is not where that fault can be posed: an
        // assurance it should have turned away is one the block would be
        // invalid for carrying, and the engine will not author such a block.
        if self.fault == SimFault::AssuranceIncludesInvalid {
            self.refused_assurances
                .lock()
                .expect("sim refused assurances")
                .push(received);
        }
    }

    /// Everything a node checks before pooling an assurance.
    ///
    /// Three questions, and the lane grades the answers separately because a
    /// node that gets one wrong is not the same node as one that gets
    /// another wrong (`simple.md:678-698`): is it shaped right and signed by
    /// the validator it came from, does it name a block this node has, and
    /// does every core it claims carry a report.
    fn assurance_holds(&self, assurance: &Assurance, peer: u16) -> bool {
        // Asked of the chain rather than remembered: the anchor must be a
        // block this node has, and the chain is the only thing that knows
        // which those are.
        let anchor = assurance.anchor.0;
        if !matches!(self.chain.storage_root(&anchor), Ok(Some(_))) {
            return false;
        }
        if m2_reference::assurance::check_assurance(assurance, peer, &[anchor]).is_err() {
            return false;
        }
        let reported = self.reported_cores.lock().expect("sim reported cores");
        m2_reference::assurance::assured_cores(assurance)
            .iter()
            .all(|core| reported.contains(core))
    }

    /// Serve CE 148: the whole segments asked for, then one import proof
    /// each (`simple.md:653-676`).
    ///
    /// Two messages, and neither says how long it is -- the frame does. The
    /// segments go out concatenated because every one is `SEGMENT_LEN`
    /// bytes, and the proofs run back to back because each carries its own
    /// count.
    ///
    /// Matched by root, not merely answered: a guarantor serves the
    /// segments of bundles it holds, and one asked for a root it never
    /// exported says so by resetting, the same as for an unknown erasure
    /// root.
    async fn serve_segments(&self, send: &mut SendHalf, content: &[u8]) {
        if self.fault == SimFault::SegmentsRefused {
            send.reset(NO_DATA_CODE);
            return;
        }
        let Ok(request) = ce137_148::SegmentRequest::decode(&mut &content[..]) else {
            return;
        };
        // Everything out of the lock before the first await: a guard held
        // across one makes the task unsendable.
        let reply = {
            let held = self.available.lock().expect("sim available");
            let Some(held) = held.as_ref() else {
                send.reset(NO_DATA_CODE);
                return;
            };
            if held.tree.segments_root != request.segments_root {
                send.reset(NO_DATA_CODE);
                return;
            }
            let mut indices = request.segment_indices.clone();
            if self.fault == SimFault::SegmentsShort {
                indices.pop();
            }
            let mut segments = Vec::with_capacity(indices.len());
            let mut proofs = Vec::with_capacity(indices.len());
            for index in &indices {
                let Some(segment) = held.segments.get(*index as usize) else {
                    send.reset(NO_DATA_CODE);
                    return;
                };
                segments.push(segment.clone());
                proofs.push(held.tree.proofs[*index as usize].clone());
            }
            if self.fault == SimFault::SegmentProofBad {
                // One hash of one proof, so the message still reads as a
                // run of proofs and only the walk fails. Altering the count
                // instead would make this a structure defect, which is a
                // different row.
                if let Some(first) = proofs.first_mut().and_then(|p| p.first_mut()) {
                    first[0] ^= 0xff;
                }
            }
            ce137_148::SegmentResponse {
                segments,
                import_proofs: proofs,
            }
        };

        let mut data = reply.encode_segments();
        if self.fault == SimFault::SegmentsRagged {
            data.pop();
        }
        if send.write_all(&frame_message(&data)).await.is_err() {
            return;
        }
        if self.fault == SimFault::SegmentsReplyShort {
            // The segments and nothing else. Nothing in the first message
            // says a second is coming, so this looks exactly like a reply
            // that finished -- which is why the lane counts messages.
            send.finish();
            return;
        }
        let proofs = reply.encode_import_proofs();
        if send.write_all(&frame_message(&proofs)).await.is_ok() {
            send.finish();
        }
    }

    /// Serve CE 137 or CE 138: the bundle shard, CE 137's segment shards,
    /// and a justification, each as its own framed message.
    ///
    /// Three messages for CE 137 and two for CE 138, because nothing in the
    /// reply says how long any of it is -- the frame does
    /// (`simple.md:552-554`, `simple.md:580-581`).
    async fn serve_bundle_shard(&self, send: &mut SendHalf, kind: u8, content: &[u8]) {
        if self.fault == SimFault::ShardRefused {
            // A reset, not a clean close: a node with no such root says so
            // by killing the stream.
            send.reset(NO_DATA_CODE);
            return;
        }
        let Ok(request) = jamnp_s::codec::ce137_148::ShardRequest::decode(&mut &content[..]) else {
            return;
        };
        // Everything taken out of the lock before the first await: a guard
        // held across one makes the whole task unsendable, and the shards
        // are a handful of kilobytes.
        let parts = {
            let held = self.available.lock().expect("sim available");
            let Some(held) = held.as_ref() else {
                send.reset(NO_DATA_CODE);
                return;
            };
            if request.erasure_root != held.shards.erasure_root {
                send.reset(NO_DATA_CODE);
                return;
            }
            let index = request.shard_index as usize;
            if index >= held.shards.bundle_shards.len() {
                send.reset(NO_DATA_CODE);
                return;
            }
            let bundle_shard = if self.fault == SimFault::ShardWrongBytes {
                // The next validator's shard, which is a genuine shard of
                // the same length under the same root -- so only the proof
                // can tell them apart.
                let other = (index + 1) % held.shards.bundle_shards.len();
                held.shards.bundle_shards[other].clone()
            } else {
                held.shards.bundle_shards[index].clone()
            };
            let mut justification = if kind == CE137 {
                held.shards.shard_justifications[index].clone()
            } else {
                held.shards.audit_justifications[index].clone()
            };
            if self.fault == SimFault::ShardBadJustification && justification.len() > 1 {
                // A byte inside the first element's hash, not its
                // discriminator: the message still parses as a sequence of
                // elements, so the proof is what fails.
                justification[1] ^= 0xff;
            }
            (
                bundle_shard,
                held.shards.segment_shards[index].clone(),
                justification,
            )
        };
        let (bundle_shard, segment_row, justification) = parts;

        if send.write_all(&frame_message(&bundle_shard)).await.is_err() {
            return;
        }
        if kind == CE137 {
            if self.fault == SimFault::ShardReplyShort {
                // Stop after one message. CE 138 owes two and CE 137 three,
                // so a reply that ends here is complete for neither.
                send.finish();
                return;
            }
            if send.write_all(&frame_message(&segment_row)).await.is_err() {
                return;
            }
        }
        let _ = send.write_all(&frame_message(&justification)).await;
        send.finish();
    }

    /// Serve CE 139 or CE 140: one message of slices, then CE 140's
    /// justification per requested index (`simple.md:600-651`).
    async fn serve_segment_shards(&self, send: &mut SendHalf, kind: u8, content: &[u8]) {
        let Ok(request) = jamnp_s::codec::ce137_148::SegmentShardRequest::decode(&mut &content[..])
        else {
            return;
        };
        // As above: nothing of the lock survives into an await.
        let parts = {
            let held = self.available.lock().expect("sim available");
            let Some(held) = held.as_ref() else {
                send.reset(NO_DATA_CODE);
                return;
            };
            if request.erasure_root != held.shards.erasure_root {
                send.reset(NO_DATA_CODE);
                return;
            }
            let index = request.shard_index as usize;
            let Some(row) = held.shards.segment_shards.get(index) else {
                send.reset(NO_DATA_CODE);
                return;
            };
            let slice_len = row.len() / held.segment_count.max(1);

            let mut asked: Vec<u16> = request.segment_indices.clone();
            if self.fault == SimFault::SegmentShardsShort && asked.len() > 1 {
                asked.pop();
            }
            let mut slices = Vec::new();
            for segment in &asked {
                let at = *segment as usize * slice_len;
                let Some(slice) = row.get(at..at + slice_len) else {
                    send.reset(NO_DATA_CODE);
                    return;
                };
                slices.extend_from_slice(slice);
            }
            if self.fault == SimFault::SegmentShardsRagged {
                // One byte past a whole number of slices, so the two sides
                // disagree about the width rather than about the count.
                slices.push(0);
            }
            let justifications: Vec<Vec<u8>> = if kind == CE140 {
                asked
                    .iter()
                    .map(|segment| {
                        let mut justification = held.shards.segment_justifications[index]
                            .get(*segment as usize)
                            .cloned()
                            .unwrap_or_default();
                        if self.fault == SimFault::SegmentJustificationBad
                            && justification.len() > 1
                        {
                            justification[1] ^= 0xff;
                        }
                        justification
                    })
                    .collect()
            } else {
                Vec::new()
            };
            (slices, justifications)
        };
        let (slices, justifications) = parts;

        if send.write_all(&frame_message(&slices)).await.is_err() {
            return;
        }
        for justification in &justifications {
            if send.write_all(&frame_message(justification)).await.is_err() {
                return;
            }
        }
        send.finish();
    }

    /// Broadcast a CE 141 assurance to every peer this node has dialled.
    ///
    /// `cores` is what an honest assurance claims; the faults are posed on
    /// top of it, each at the level it belongs to.
    pub async fn send_assurance(&self, anchor: [u8; 32], cores: &[u16]) {
        if self.fault == SimFault::AssuranceLate {
            // Held until the slot has nearly run out, so it arrives with a
            // fraction of a second of lead instead of the two seconds
            // `simple.md:682-683` asks for. Sleeping a whole slot period
            // would not do it: that lands at the same phase of the next
            // slot and reads exactly as punctual.
            let now = clock::current().wall_ms();
            let next = m2_reference::chain::slot_start_ms(m2_reference::chain::slot_of_ms(now) + 1);
            if let Some(wait) = next
                .saturating_sub(LATE_ASSURANCE_MARGIN_MS)
                .checked_sub(now)
            {
                clock::current().sleep(Duration::from_millis(wait)).await;
            }
        }
        let index = self.index as u16;
        let assurance = match self.fault {
            SimFault::AssuranceWrongAnchor => {
                let mut absent = anchor;
                absent[0] ^= 0xff;
                m2_reference::assurance::sign_assurance(index, absent, cores)
            }
            // CE 141 carries no validator index -- the reader takes it from
            // the connection -- so another validator's key is the whole of
            // the fault.
            SimFault::AssuranceBadSignature => {
                m2_reference::assurance::sign_assurance(index.wrapping_add(1), anchor, cores)
            }
            SimFault::AssuranceEmptyCore => {
                let Some(empty) = (0..jam_types::core_count()).find(|c| !cores.contains(c)) else {
                    return;
                };
                m2_reference::assurance::sign_assurance(index, anchor, &[empty])
            }
            _ => m2_reference::assurance::sign_assurance(index, anchor, cores),
        };
        let wire = frame(CE141, &assurance.encode());
        let peers: Vec<Conn> = self
            .peers
            .lock()
            .expect("sim peers")
            .iter()
            .map(|(_, conn)| conn.clone())
            .collect();
        for conn in peers {
            let Ok((mut send, _recv)) = conn.open_bi().await else {
                continue;
            };
            if send.write_all(&wire).await.is_ok() {
                send.finish();
            }
        }
    }

    /// UP 0 is persistent: answer the handshake, then re-announce whatever
    /// the peer announces, for as long as it keeps the stream open.
    async fn serve_up0(&self, send: &mut SendHalf, reader: &mut StreamReader, first: &[u8]) {
        if self.fault == SimFault::SilentOnUp0 {
            // Hold the stream open: the peer grades the silence, not a
            // closed connection.
            while reader.next().await.is_some() {}
            return;
        }
        if Handshake::decode(&mut &first[..]).is_ok()
            && send.write_all(&self.handshake()).await.is_err()
        {
            return;
        }
        // Both halves at once: serving them in turn would stall whichever
        // came second.
        let mut announcements = self.announce.subscribe();
        loop {
            tokio::select! {
                incoming = reader.next() => {
                    let Some((_, content)) = incoming else { return };
                    let Ok(announcement) = Announcement::decode(&mut &content[..]) else {
                        continue;
                    };
                    if self.fault == SimFault::NeverReannounces {
                        continue;
                    }
                    if send
                        .write_all(&frame_message(&announcement.encode()))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                own = announcements.recv() => match own {
                    Ok(wire) => {
                        if send.write_all(&wire).await.is_err() {
                            return;
                        }
                    }
                    // Falling behind skips what was missed; the peer can
                    // still fetch a block it hears about later.
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return,
                },
            }
        }
    }

    /// This node's handshake: its finalized head and no leaves.
    fn handshake(&self) -> Vec<u8> {
        let header_hash = if self.fault == SimFault::FinalIsNotGenesis {
            // A hash that is not genesis and not any block in the chain.
            HeaderHash::from([0x5a; 32])
        } else {
            HeaderHash::from(self.genesis_hash)
        };
        frame_message(
            &Handshake {
                final_block: Final {
                    header_hash,
                    slot: 0,
                },
                leaves: vec![],
            }
            .encode(),
        )
    }

    /// Take delivery of a ticket, refusing what it cannot act on by resetting
    /// the stream (`simple.md:335-337`) and forwarding what it proxies.
    async fn receive_ticket(self: &Arc<Self>, send: &mut SendHalf, kind: u8, content: &[u8]) {
        let Ok(distribution) = TicketDistribution::decode(&mut &content[..]) else {
            send.reset(TICKET_REFUSED_CODE);
            return;
        };
        // Exactly the next epoch: a later one has entropy nobody holds yet, an
        // earlier one is stale. polkajam refuses both ("bad ticket epoch
        // value"), and pooling a stale ticket puts it in a block uninvited.
        let period = jam_types::epoch_period();
        let next_epoch = m2_reference::chain::wall_clock_slot() / period + 1;
        if distribution.epoch_index != next_epoch && self.fault != SimFault::AcceptsUnknownEpoch {
            send.reset(TICKET_REFUSED_CODE);
            return;
        }
        // At or above the per-validator cap there is no lawful attempt index,
        // so the proof cannot belong to this epoch's lottery however well it
        // verifies. polkajam refuses these too ("bad ticket attempt value").
        if distribution.ticket.attempt
            >= jam_types::tickets_per_validator(jam_types::max_val_count())
        {
            send.reset(TICKET_REFUSED_CODE);
            return;
        }
        let verifies = self
            .chain
            .ticket_ctx()
            .map(|ctx| {
                verify_ticket(
                    &ctx,
                    distribution.ticket.attempt,
                    &distribution.ticket.proof,
                )
            })
            .unwrap_or(false);
        if !verifies && self.fault != SimFault::AcceptsBadProof {
            send.reset(TICKET_REFUSED_CODE);
            return;
        }
        // A CE 131 arrival is a ticket sent to this node *as proxy*, so one
        // the proxy rule names another validator for was misrouted: refuse it
        // rather than pass it on or carry it. A CE 132 arrival is a broadcast
        // and belongs to no proxy, so it is kept whoever it names.
        let id = ticket_id(&distribution.ticket.proof);
        let proxies_here = proxy_index(&id, usize::from(jam_types::max_val_count())) == self.index;
        if kind == CE131 && !proxies_here {
            send.reset(TICKET_REFUSED_CODE);
            return;
        }
        send.finish();
        // Into its own pool, so a block it authors this epoch carries it.
        // Whichever stream it arrived on -- hence before the CE 131-only
        // forwarding rule below.
        if self.fault != SimFault::OmitsDeliveredTickets {
            let envelope = TicketEnvelope {
                attempt: distribution.ticket.attempt,
                signature: ring_vrf::Signature(distribution.ticket.proof),
            };
            if let Err(e) = self.chain.submit_tickets(&[envelope]) {
                // A simulated node that could not pool a ticket will not
                // carry it in a block, which is the fault this very method
                // can be asked to inject. Saying so is what keeps the two
                // apart.
                eprintln!("[sim] could not pool a delivered ticket: {e}");
            }
        }
        // Only a CE 131 arrival is this node's to pass on: a CE 132 one is
        // already a broadcast.
        if kind != CE131 || self.fault == SimFault::NeverForwards {
            return;
        }
        self.forwarded
            .lock()
            .expect("sim forwards")
            .push((id, distribution));
        if self.fault == SimFault::ForwardsInTail {
            self.sleep_until_tail().await;
        }
        self.broadcast_ticket(&distribution).await;
        if self.fault == SimFault::RepeatsForwards {
            let node = Arc::clone(self);
            tokio::spawn(async move {
                clock::current()
                    .sleep(Duration::from_millis(jam_types::slot_period_sec() * 1000))
                    .await;
                node.broadcast_ticket(&distribution).await;
            });
        }
    }

    /// Serve a block request from the reference chain.
    async fn serve_ce128(&self, send: &mut SendHalf, content: &[u8]) {
        if self.fault == SimFault::Ce128Silent {
            send.finish();
            return;
        }
        let Ok(request) = BlockRequest::decode(&mut &content[..]) else {
            return;
        };
        // The fetch that follows an announcement -- by hash, descending, one
        // block -- which only this node can answer.
        if request.direction == Direction::DescendingInclusive && request.max_blocks == 1 {
            let own = self
                .own_blocks
                .lock()
                .expect("sim blocks")
                .iter()
                .find(|b| b.header.hash() == request.header_hash)
                .cloned();
            if let Some(block) = own {
                let response = BlockResponse {
                    blocks: vec![block],
                };
                let _ = send.write_all(&frame_message(&response.encode())).await;
                send.finish();
                return;
            }
        }
        let Ok(chain) = self.chain.chain_blocks() else {
            eprintln!("[sim] could not read the reference chain to serve CE 128");
            return;
        };
        let Ok(mut response) = m2_emu::emu::serve_ce128(&request, &chain) else {
            return;
        };
        if self.fault == SimFault::Ce128Descending {
            // The walk the peer asked for, in the opposite order. Every block
            // it asked for is there, so only the ordering rule can catch it.
            response.blocks.reverse();
        }
        if self.fault == SimFault::Ce128OverMax {
            // One past the cap the *request* named, which is the bound the row
            // reads -- the chain is usually shorter than it, so serving one
            // more block than it holds would not exceed anything. The last
            // block is repeated rather than a new one invented, so only the
            // count is wrong.
            if let Some(last) = response.blocks.last().cloned() {
                while response.blocks.len() as u32 <= request.max_blocks {
                    response.blocks.push(last.clone());
                }
            }
        }
        let _ = send.write_all(&frame_message(&response.encode())).await;
        if self.fault == SimFault::Ce128DirtyClose {
            // Two bytes of a four-byte length prefix, then FIN.
            let _ = send.write_all(&[0xff, 0xff]).await;
        }
        send.finish();
    }

    /// Serve a state request: the same empty response the emulator serves.
    ///
    /// Two messages, not one -- boundary nodes then key/value pairs, each read
    /// as items-until-end-of-message.
    async fn serve_ce129(&self, send: &mut SendHalf, content: &[u8]) {
        let Ok(request) = StateRequest::decode(&mut &content[..]) else {
            return;
        };
        if self.fault == SimFault::Ce129Refuses {
            send.reset(TICKET_REFUSED_CODE);
            return;
        }
        let response = self.state_response(&request);
        let (boundary, entries) = response.messages();
        for message in [boundary, entries] {
            if send.write_all(&frame_message(&message)).await.is_err() {
                return;
            }
        }
        send.finish();
    }
}

/// The Ed25519 public key validator `index` is known by, which is what the
/// preferred-initiator rule compares.
pub fn validator_key(index: usize) -> [u8; 32] {
    let secret = jam_std_common::SecretKeyset::trivial(index as u32).ed25519;
    ed25519_consensus::VerificationKey::from(&SigningKey::from(secret.to_bytes())).to_bytes()
}

/// Incremental frame reader. One read routinely delivers several frames, so a
/// reader rebuilt per message drops everything behind the first.
struct StreamReader {
    recv: RecvHalf,
    reader: FrameReader,
    buf: [u8; 4096],
    /// The stream-opening kind byte, as it arrived and before anyone judged
    /// it.
    ///
    /// Kept because `next` cannot report it: a kind naming no protocol makes
    /// `next_frame` error, and a kind with no message behind it leaves it
    /// waiting, and both reach the caller as `None`. A real node has already
    /// dispatched by then -- `simple.md:122-124` puts the protocol in force
    /// the moment the byte is sent -- so a stand-in that forgets the byte
    /// cannot model what a node does with a stream it will not serve.
    opened_kind: Option<u8>,
}

impl StreamReader {
    fn new(recv: RecvHalf) -> Self {
        Self {
            recv,
            reader: FrameReader::new(),
            buf: [0u8; 4096],
            opened_kind: None,
        }
    }

    /// The kind byte this stream was opened with, once any byte has arrived.
    fn opened_kind(&self) -> Option<u8> {
        self.opened_kind
    }

    /// The next complete message, or `None` once the stream ends or breaks.
    async fn next(&mut self) -> Option<(u8, Vec<u8>)> {
        loop {
            match self.reader.next_frame() {
                Ok(Some(item)) => return Some(item),
                Ok(None) => {}
                Err(_) => return None,
            }
            match self.recv.read(&mut self.buf).await {
                Ok(Some(n)) => {
                    if self.opened_kind.is_none() && n > 0 {
                        self.opened_kind = Some(self.buf[0]);
                    }
                    let (buf, reader) = (&self.buf, &mut self.reader);
                    reader.push(&buf[..n]);
                }
                _ => return None,
            }
        }
    }
}
