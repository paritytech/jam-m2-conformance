//! The five emulated validators (P0 N0 subset): JAMNP-S reactive skeletons.
//!
//! `m2-emu` executes no core protocol logic: every block is served byte-for-byte
//! from `m2-reference`'s [`RefChain`] and every decision is made by the
//! runner/scenario. This module only frames, signs and records.

use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc, Mutex, MutexGuard,
    },
};

use ed25519_consensus::SigningKey;
use jam_std_common::{Block, SecretKeyset};
use jam_types::{Decode, Encode, HeaderHash};
use jamnp_s::{
    codec::ce128_129::{BlockRequest, BlockResponse, Direction, StateRequest, StateResponse},
    codec::up0::{Announcement, Final, Handshake},
    endpoint::{EndpointConfig, EndpointError},
    framing::{frame, frame_message, FrameReader, CE128, CE129, CE131, CE132, CE134, CE135, UP},
    trace::{mono_ts, wall_ts, Direction as TraceDir, Trace, TraceRecord},
    transport::{quic::QuicTransport, Conn, Listener, RecvHalf, SendHalf, Transport},
};
use m2_reference::chain::RefChain;
use m2_reference::reports::{ScheduledReport, SharingAnswer, SubmissionSchedule};
use m2_reference::tickets::ScheduledTicket;
use m2_scenario::ctx::{DeliveredTicket, NutBlock};
use m2_scenario::dsl::{Obs, ObsKind, ObsLog};
use m2_scenario::scenarios::n0;
use m2_scenario::scenarios::n0::{Ce128Probe, Ce129Probe};
use m2_scenario::scenarios::n3::{DistributedReport, ReportSeen, SharingSeen, SubmittedPackage};
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;

use crate::nut_block::{fetch_block, should_fetch};
use crate::sync_probe::start_sync_probe;
use crate::ticket_io::spawn_ticket_sender;

/// Errors raised while building or running the emulated validators.
#[derive(Debug, thiserror::Error)]
pub enum EmuError {
    /// Endpoint construction or dialing failed.
    #[error("endpoint error: {0}")]
    Endpoint(#[from] EndpointError),
    /// Binding or runtime setup failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// An emulator task failed to join.
    #[error("task join error: {0}")]
    Join(#[from] tokio::task::JoinError),
    /// A requested block hash is not in the reference chain (reset the stream).
    #[error("block {0:02x?} is not in the reference chain")]
    UnknownHash([u8; 32]),
    /// A frame or codec-level protocol error.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// A response failed to decode into the expected type.
    #[error("decode error: {0}")]
    Decode(String),
}

/// The emulated validators: every validator index except the NUT's.
///
/// Each validator is one listener bound to `127.0.0.1:(base_port + i)` with
/// the Ed25519 identity `SecretKeyset::trivial(i)`. The endpoints stay alive
/// in the caller's runtime; [`Emulator::accept_loop`] spawns one reactive
/// accept task per endpoint.
///
/// Which carrier those listeners are on is the caller's choice and travels
/// with the emulator: [`Emulator::n0`] binds them over QUIC, and whatever
/// dials out later -- [`dial_nut`] included -- uses the same transport, so a
/// run cannot end up with one side on each.
pub struct Emulator {
    transport: Arc<dyn Transport>,
    endpoints: Vec<Arc<dyn Listener>>,
    /// Validator index of each endpoint, positionally. Not a range: the NUT can
    /// sit anywhere in the keyset, so the emulated indices straddle it.
    emu_indices: Vec<usize>,
    genesis_hash: [u8; 32],
    trace: Arc<Mutex<Trace>>,
    obs: Arc<Mutex<ObsLog>>,
    nut_blocks: Arc<Mutex<Vec<NutBlock>>>,
    ticket_plans: Arc<Mutex<HashMap<u16, Vec<ScheduledTicket>>>>,
    /// Published to [`EmuShared::plans_set`] by `set_ticket_plans` and
    /// `set_submission_plan`.
    plans_set: watch::Sender<bool>,
    /// The CE 133 submission for this run, claimed by the first connection
    /// to the NUT. One per run, not one per peer: a work package is submitted
    /// by a builder, and one builder is enough to pose the row.
    submission_plan: Arc<Mutex<Vec<SubmissionSchedule>>>,
    /// CE 133 submissions the emulator made, with what the node did with them.
    submissions: Arc<Mutex<Vec<SubmittedPackage>>>,
    /// What an emulated co-guarantor answers a CE 134 share with, once the
    /// submission it belongs to has been planned.
    sharing_answer: Arc<Mutex<Option<SharingAnswer>>>,
    /// The reference-guaranteed report this run distributes to the NUT.
    report_plan: Arc<Mutex<Option<ScheduledReport>>>,
    /// Reports the emulator distributed, for the inclusion rows.
    distributed: Arc<Mutex<Vec<DistributedReport>>>,
    deliveries: Arc<Mutex<Vec<DeliveredTicket>>>,
    ce128_probes: Arc<Mutex<Vec<Ce128Probe>>>,
    ce129_probes: Arc<Mutex<Vec<Ce129Probe>>>,
    /// CE 134 sharing streams the NUT opened to an emulated co-guarantor.
    sharing_seen: Arc<Mutex<Vec<SharingSeen>>>,
    /// CE 135 report distributions the NUT sent.
    reports_seen: Arc<Mutex<Vec<ReportSeen>>>,
    sync_probe_pending: Arc<AtomicBool>,
    /// Highest finalized slot the NUT has advertised over UP 0; see
    /// [`EmuShared::nut_final_slot`].
    nut_final_slot: Arc<AtomicU32>,
    /// Fan-out for blocks authored after the connections are up (A10).
    ///
    /// Every live UP 0 stream subscribes, so a block announced here reaches
    /// each one without the emulator holding their send halves: a
    /// a send half is not clonable, and sharing one behind a lock would
    /// mean holding that lock across a write. A subscriber also disappears on
    /// its own when its stream task ends.
    announce: broadcast::Sender<Vec<u8>>,
}

/// Everything a connection handler shares with the rest of the emulator.
///
/// Bundled rather than passed one argument at a time: the handlers already
/// carried eight to ten parameters each, and the ticket plans and the delivery
/// log would have made every one of them longer again.
#[derive(Clone)]
pub struct EmuShared {
    /// The carrier this run is on; see [`Emulator`].
    pub transport: Arc<dyn Transport>,
    pub ref_chain: Arc<RefChain>,
    pub trace: Arc<Mutex<Trace>>,
    pub obs: Arc<Mutex<ObsLog>>,
    pub nut_blocks: Arc<Mutex<Vec<NutBlock>>>,
    /// Blocks authored after the connections are up; see [`Emulator::announce`].
    pub announce: broadcast::Sender<Vec<u8>>,
    /// Each emulated validator's undelivered tickets, keyed by peer.
    ///
    /// A plan is *taken* by the first connection to that peer, whichever side
    /// opened it. Ticket delivery used to live in [`dial_nut`] alone, so a peer
    /// the NUT connected to first never delivered its tickets at all — and
    /// after the harness stopped dialling peers that had already connected,
    /// that was most of them.
    pub ticket_plans: Arc<Mutex<HashMap<u16, Vec<ScheduledTicket>>>>,
    /// Flips once [`Emulator::set_ticket_plans`] has run.
    ///
    /// The plans are laid out after the connections are up, because a
    /// schedule written while the node is still importing the seeded chain
    /// names slots the tickets will not arrive in. So a sender cannot read
    /// its plan at connect time -- it has to wait for one to exist, and an
    /// empty map at connect time means "not yet", not "nothing to send".
    pub plans_set: watch::Receiver<bool>,
    /// The CE 133 submission for this run; see [`Emulator::set_submission_plan`].
    pub submission_plan: Arc<Mutex<Vec<SubmissionSchedule>>>,
    /// CE 133 submissions the emulator made.
    pub submissions: Arc<Mutex<Vec<SubmittedPackage>>>,
    /// The CE 134 answer for this run's submission, if one was planned.
    pub sharing_answer: Arc<Mutex<Option<SharingAnswer>>>,
    /// The reference-guaranteed report this run distributes to the NUT.
    pub report_plan: Arc<Mutex<Option<ScheduledReport>>>,
    /// Reports the emulator distributed.
    pub distributed: Arc<Mutex<Vec<DistributedReport>>>,
    /// Tickets actually put on the wire, with the wall-clock time they were
    /// sent. The sender knows each ticket's id, so the N1 lane reads this
    /// rather than re-deriving ids from the observation log.
    pub deliveries: Arc<Mutex<Vec<DeliveredTicket>>>,
    /// CE 128 replies the node under test gave the emulator.
    pub ce128_probes: Arc<Mutex<Vec<Ce128Probe>>>,
    /// CE 129 replies the node under test gave the emulator.
    pub ce129_probes: Arc<Mutex<Vec<Ce129Probe>>>,
    /// CE 134 sharing streams the NUT opened to an emulated co-guarantor
    /// (`simple.md:406-458`).
    pub sharing_seen: Arc<Mutex<Vec<SharingSeen>>>,
    /// CE 135 report distributions the NUT sent (`simple.md:460-485`).
    pub reports_seen: Arc<Mutex<Vec<ReportSeen>>>,
    /// Cleared by whichever connection runs the sync probes, so they run once
    /// per run rather than once per peer.
    pub sync_probe_pending: Arc<AtomicBool>,
    /// Highest finalized slot the NUT has advertised over UP 0, or
    /// [`NO_ADVERTISED_FINAL`] before it has advertised any.
    ///
    /// Every UP 0 message the node sends carries its finalized block
    /// (`simple.md:192-236`), handshake and announcement alike, so this is the
    /// one thing the harness knows about the node's internal progress without
    /// asking it anything. The ticket sender gates on it.
    pub nut_final_slot: Arc<AtomicU32>,
}

/// `nut_final_slot` before the NUT has advertised a finalized block.
///
/// Zero rather than a sentinel: the run's genesis is anchored at the current
/// epoch's start, millions of slots in, so no real advertisement can collide
/// with it — and a node that has told us nothing and a node finalized at slot
/// zero are equally unready.
pub const NO_ADVERTISED_FINAL: u32 = 0;

impl EmuShared {
    /// Take `peer`'s ticket plan, leaving nothing behind.
    ///
    /// Returns `None` once taken, so a second connection to the same peer does
    /// not deliver the same tickets twice.
    pub fn take_ticket_plan(&self, peer: u16) -> Option<Vec<ScheduledTicket>> {
        lock(&self.ticket_plans)
            .remove(&peer)
            .filter(|p| !p.is_empty())
    }

    /// Take this run's CE 135 distribution, leaving nothing behind.
    ///
    /// Claimed once, like the submission: the same report sent twice is a
    /// duplicate the node is right to drop, which would read as a failure to
    /// include it.
    pub fn take_report_plan(&self) -> Option<ScheduledReport> {
        lock(&self.report_plan).take()
    }

    /// Take this run's CE 135 distribution, but only on the connection to the
    /// validator that must send it.
    ///
    /// Checked before taking, not after: a peer that took a plan it may not
    /// send would have to put it back, and another connection could claim it
    /// in between.
    pub fn claim_report_plan(&self, peer: u16) -> Option<ScheduledReport> {
        let mut plan = lock(&self.report_plan);
        if plan.as_ref().is_some_and(|p| p.sender == peer) {
            plan.take()
        } else {
            None
        }
    }

    /// Take this run's CE 133 submission, leaving nothing behind.
    ///
    /// `None` once taken, so a second connection does not submit the same
    /// package twice -- which a node would be right to treat as a duplicate.
    /// Take the whole submission plan, leaving nothing behind.
    ///
    /// A list, not one entry: a run poses the honest submission and each
    /// injected fault in turn, and they are claimed together so a second
    /// connection cannot interleave with the first.
    pub fn take_submission_plan(&self) -> Vec<SubmissionSchedule> {
        std::mem::take(&mut *lock(&self.submission_plan))
    }

    /// True for the first caller only: the sync probes are assertions about
    /// the node, so one answer is the whole evidence.
    pub fn claim_sync_probe(&self) -> bool {
        self.sync_probe_pending.swap(false, Ordering::SeqCst)
    }

    /// Record a finalized slot the NUT advertised, keeping the highest.
    ///
    /// Monotonic because the advertisements are not: they arrive on five
    /// connections at once, and a message that was in flight while another
    /// overtook it would otherwise walk the watermark backwards.
    pub fn note_nut_final(&self, slot: u32) {
        self.nut_final_slot.fetch_max(slot, Ordering::SeqCst);
    }

    /// The highest finalized slot the NUT has advertised, or
    /// [`NO_ADVERTISED_FINAL`].
    pub fn nut_final_slot(&self) -> u32 {
        self.nut_final_slot.load(Ordering::SeqCst)
    }
}

impl Emulator {
    /// Bind one endpoint per emulated validator in `emu_indices`.
    ///
    /// The endpoint for validator `i` listens on `127.0.0.1:(base_port + i)`
    /// with the Ed25519 secret `SecretKeyset::trivial(i)` and identifies as a
    /// non-builder peer for `genesis_hash`.
    pub async fn n0(
        emu_indices: Vec<usize>,
        genesis_hash: [u8; 32],
        base_port: u16,
    ) -> Result<Self, EmuError> {
        Self::n0_on(
            Arc::new(QuicTransport),
            emu_indices,
            genesis_hash,
            base_port,
        )
        .await
    }

    /// [`Emulator::n0`] on a chosen carrier.
    ///
    /// The QUIC one is what grades a real node. An in-process transport is
    /// what a simulated node is graded on, where a run costs no sockets and no
    /// handshakes.
    pub async fn n0_on(
        transport: Arc<dyn Transport>,
        emu_indices: Vec<usize>,
        genesis_hash: [u8; 32],
        base_port: u16,
    ) -> Result<Self, EmuError> {
        let config = EndpointConfig {
            genesis_hash,
            builder: false,
        };
        let endpoints = async {
            let mut endpoints = Vec::with_capacity(emu_indices.len());
            for &i in &emu_indices {
                let secret = SecretKeyset::trivial(i as u32).ed25519;
                let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, base_port + i as u16));
                let endpoint = transport
                    .listen(config.clone(), SigningKey::from(secret.to_bytes()), addr)
                    .await?;
                endpoints.push(Arc::from(endpoint));
            }
            Ok::<_, EmuError>(endpoints)
        }
        .await?;
        Ok(Self {
            transport,
            endpoints,
            emu_indices,
            genesis_hash,
            trace: Arc::new(Mutex::new(Trace::default())),
            obs: Arc::new(Mutex::new(ObsLog::new())),
            nut_blocks: Arc::new(Mutex::new(Vec::new())),
            ticket_plans: Arc::new(Mutex::new(HashMap::new())),
            plans_set: watch::channel(false).0,
            submission_plan: Arc::new(Mutex::new(Vec::new())),
            submissions: Arc::new(Mutex::new(Vec::new())),
            sharing_answer: Arc::new(Mutex::new(None)),
            report_plan: Arc::new(Mutex::new(None)),
            distributed: Arc::new(Mutex::new(Vec::new())),
            deliveries: Arc::new(Mutex::new(Vec::new())),
            ce128_probes: Arc::new(Mutex::new(Vec::new())),
            ce129_probes: Arc::new(Mutex::new(Vec::new())),
            sharing_seen: Arc::new(Mutex::new(Vec::new())),
            reports_seen: Arc::new(Mutex::new(Vec::new())),
            sync_probe_pending: Arc::new(AtomicBool::new(true)),
            nut_final_slot: Arc::new(AtomicU32::new(NO_ADVERTISED_FINAL)),
            announce: broadcast::Sender::new(ANNOUNCE_BUFFER),
        })
    }

    /// Hand each emulated validator the tickets it is to deliver to the NUT.
    ///
    /// Whichever side opens the first connection to a peer delivers that
    /// peer's plan; see [`EmuShared::ticket_plans`].
    pub fn set_ticket_plans(&self, plans: HashMap<u16, Vec<ScheduledTicket>>) {
        *lock(&self.ticket_plans) = plans;
        // After the map, never before: a sender woken by this goes straight
        // to `take_ticket_plan`. `send_replace` rather than `send` so the flag
        // sticks even when no sender is listening yet.
        self.plans_set.send_replace(true);
    }

    /// Set the CE 133 submission for this run.
    ///
    /// Gated behind the same flag as the ticket plans and for the same
    /// reason: a plan written while the node is still importing the seeded
    /// chain names a slot the submission will not arrive in.
    pub fn set_submission_plan(&self, plan: Vec<SubmissionSchedule>) {
        // No answer yet: it is signed over the report the package refines
        // to, and the package is not built until shortly before its slot.
        *lock(&self.submission_plan) = plan;
        self.plans_set.send_replace(true);
    }

    /// CE 133 submissions the emulator made, with what the node did with them.
    pub fn submissions(&self) -> Arc<Mutex<Vec<SubmittedPackage>>> {
        Arc::clone(&self.submissions)
    }

    /// The CE 134 answer planned for this run, if any. The lane reads the
    /// report hash out of it to compare the node's own against.
    pub fn sharing_answer(&self) -> Arc<Mutex<Option<SharingAnswer>>> {
        Arc::clone(&self.sharing_answer)
    }

    /// Set the reference-guaranteed report this run distributes to the NUT.
    ///
    /// Behind the same gate as the other plans: a report distributed while
    /// the node is still importing names a slot it will not act in.
    pub fn set_report_plan(&self, plan: ScheduledReport) {
        *lock(&self.report_plan) = Some(plan);
        self.plans_set.send_replace(true);
    }

    /// Reports the emulator distributed, for the inclusion rows.
    pub fn distributed(&self) -> Arc<Mutex<Vec<DistributedReport>>> {
        Arc::clone(&self.distributed)
    }

    /// The tickets the emulator put on the wire, with their send times.
    pub fn deliveries(&self) -> Arc<Mutex<Vec<DeliveredTicket>>> {
        Arc::clone(&self.deliveries)
    }

    /// CE 128 replies the node under test gave the emulator.
    pub fn ce128_probes(&self) -> Arc<Mutex<Vec<Ce128Probe>>> {
        Arc::clone(&self.ce128_probes)
    }

    /// CE 129 replies the node under test gave the emulator.
    pub fn ce129_probes(&self) -> Arc<Mutex<Vec<Ce129Probe>>> {
        Arc::clone(&self.ce129_probes)
    }

    /// CE 134 sharing streams the NUT opened to an emulated co-guarantor.
    pub fn sharing_seen(&self) -> Arc<Mutex<Vec<SharingSeen>>> {
        Arc::clone(&self.sharing_seen)
    }

    /// CE 135 report distributions the NUT sent.
    pub fn reports_seen(&self) -> Arc<Mutex<Vec<ReportSeen>>> {
        Arc::clone(&self.reports_seen)
    }

    /// The state every connection handler shares, over `ref_chain`.
    pub fn shared(&self, ref_chain: Arc<RefChain>) -> EmuShared {
        EmuShared {
            transport: Arc::clone(&self.transport),
            ref_chain,
            trace: Arc::clone(&self.trace),
            obs: Arc::clone(&self.obs),
            nut_blocks: Arc::clone(&self.nut_blocks),
            announce: self.announce.clone(),
            ticket_plans: Arc::clone(&self.ticket_plans),
            plans_set: self.plans_set.subscribe(),
            submission_plan: Arc::clone(&self.submission_plan),
            submissions: Arc::clone(&self.submissions),
            sharing_answer: Arc::clone(&self.sharing_answer),
            report_plan: Arc::clone(&self.report_plan),
            distributed: Arc::clone(&self.distributed),
            deliveries: Arc::clone(&self.deliveries),
            ce128_probes: Arc::clone(&self.ce128_probes),
            ce129_probes: Arc::clone(&self.ce129_probes),
            sharing_seen: Arc::clone(&self.sharing_seen),
            reports_seen: Arc::clone(&self.reports_seen),
            sync_probe_pending: Arc::clone(&self.sync_probe_pending),
            nut_final_slot: Arc::clone(&self.nut_final_slot),
        }
    }

    /// Sender for live block announcements; see [`Emulator::announce`].
    pub fn announce_tx(&self) -> broadcast::Sender<Vec<u8>> {
        self.announce.clone()
    }

    /// Validator index of each endpoint, positionally.
    pub fn emu_indices(&self) -> &[usize] {
        &self.emu_indices
    }

    /// The bound addresses of the five endpoints.
    pub fn local_addrs(&self) -> Vec<SocketAddr> {
        self.endpoints
            .iter()
            .map(|endpoint| endpoint.local_addr())
            .collect()
    }

    /// The shared message trace recorder.
    pub fn trace(&self) -> Arc<Mutex<Trace>> {
        Arc::clone(&self.trace)
    }

    /// The shared observation log.
    pub fn obs(&self) -> Arc<Mutex<ObsLog>> {
        Arc::clone(&self.obs)
    }

    /// The shared store of blocks fetched from the NUT (announce, then CE 128).
    pub fn nut_blocks(&self) -> Arc<Mutex<Vec<NutBlock>>> {
        Arc::clone(&self.nut_blocks)
    }

    /// Spawn one reactive accept task per endpoint, serving the N0 subset from
    /// `ref_chain`. The returned handle completes when every accept task ends
    /// (i.e. once the endpoints are closed).
    pub fn accept_loop(&self, ref_chain: Arc<RefChain>) -> JoinHandle<()> {
        let handle = tokio::runtime::Handle::current();
        let shared = self.shared(ref_chain);
        let tasks: Vec<JoinHandle<()>> = self
            .endpoints
            .iter()
            .enumerate()
            .map(|(i, endpoint)| {
                let endpoint = Arc::clone(endpoint);
                let shared = shared.clone();
                let peer_index = self.emu_indices[i] as u16;
                let genesis_hash = self.genesis_hash;
                handle.spawn(async move {
                    endpoint_task(endpoint, peer_index, genesis_hash, shared).await;
                })
            })
            .collect();
        handle.spawn(async move {
            futures::future::join_all(tasks).await;
        })
    }
}

/// The framed UP 0 announcement for `block`, advertising the chain's current
/// head as final.
///
/// Shared by the announcements a connection sends when it opens and by the ones
/// the slot driver broadcasts later, so both describe the chain the same way.
pub fn announcement_wire(block: &Block, ref_chain: &RefChain) -> Vec<u8> {
    let ann = Announcement {
        header: (**block.header).clone(),
        final_block: advertised_final(&ref_chain.chain_blocks(), ref_chain.genesis_hash()),
    };
    frame_message(&ann.encode())
}

/// Announcements buffered per UP 0 subscriber.
///
/// A slot is 6 s and a stream only falls behind if its write stalls, so a few
/// slots of slack is plenty; a lagging subscriber drops the oldest and keeps
/// going rather than stalling the driver.
const ANNOUNCE_BUFFER: usize = 16;

/// Dial the NUT as emulated validator `index` and run the N0 reactive handler
/// on the connection: verify the NUT's cert/ALPN (the handshake proves it),
/// open UP 0 as the connection initiator, then serve the NUT's CE 128 / CE 129
/// requests. Used where the emulated validator is the preferred initiator
/// (DESIGN.md §4.3).
pub async fn dial_nut(
    index: usize,
    genesis_hash: [u8; 32],
    nut_addr: SocketAddr,
    nut_san: String,
    shared: EmuShared,
) -> Result<(), EmuError> {
    let (ref_chain, trace, obs) = (
        Arc::clone(&shared.ref_chain),
        Arc::clone(&shared.trace),
        Arc::clone(&shared.obs),
    );
    let secret = SecretKeyset::trivial(index as u32).ed25519;
    let config = EndpointConfig {
        genesis_hash,
        builder: false,
    };
    let connection = shared
        .transport
        .connect(
            config,
            SigningKey::from(secret.to_bytes()),
            nut_san,
            nut_addr,
        )
        .await?;
    let peer = index as u16;
    // A completed handshake proves the N0 cert + ALPN contract.
    record(&obs, peer, ObsKind::Other(n0::CERT_ED25519));
    record(&obs, peer, ObsKind::Other(n0::CERT_KEY_MATCH));
    record(&obs, peer, ObsKind::Other(n0::CERT_SAN_OK));
    record(&obs, peer, ObsKind::Other(n0::ALPN_ACCEPTED));
    record(&obs, peer, ObsKind::Other(n0::ALPN_OFFERED));
    record(&obs, peer, ObsKind::Other(n0::ENDPOINT_DIALED));

    // Open UP 0 as the connection initiator and send the genesis handshake.
    let (mut send, recv) = connection
        .open_bi()
        .await
        .map_err(|e| EmuError::Protocol(e.to_string()))?;
    record(&obs, peer, ObsKind::OpenUp0);
    let up0_stream_id = send.id();
    let handshake = Handshake {
        final_block: advertised_final(&ref_chain.chain_blocks(), genesis_hash),
        leaves: vec![],
    };
    let wire = frame(UP, &handshake.encode());
    trace_record(peer, UP, send.id(), &wire, &trace, TraceDir::Rx);
    let _ = send.write_all(&wire).await;

    // Announce the reference blocks (skip genesis) so the NUT has something to
    // sync and re-announce (N1 authoring is announced like a real author).
    for block in ref_chain.chain_blocks().iter().skip(1) {
        record(&obs, peer, ObsKind::Up0Announce);
        let wire = announcement_wire(block, &ref_chain);
        trace_record(peer, UP, send.id(), &wire, &trace, TraceDir::Rx);
        let _ = send.write_all(&wire).await;
    }
    // UP 0 is a persistent stream: keep the send half open for future
    // announcements rather than finishing it (simple.md:108-111). Nothing else
    // writes to it from here, so hand it to a pump task that forwards every
    // block the slot driver authors from now on (A10).
    tokio::spawn(pump_announcements(
        send,
        shared.announce.subscribe(),
        peer,
        up0_stream_id,
        Arc::clone(&trace),
        Arc::clone(&obs),
    ));

    // Read the receive half of the UP 0 stream we opened. The NUT's handshake
    // and its announcements come back on it, and nothing else observes them on
    // an emulator-initiated connection: the accept loop only sees streams the
    // NUT opens. Left unread, the node's whole UP 0 output on these three
    // connections is invisible to the harness (A3).
    tokio::spawn(read_dialed_up0(
        connection.clone(),
        recv,
        peer,
        genesis_hash,
        up0_stream_id,
        shared.clone(),
    ));

    // Deliver the peer's N2 tickets on their own streams, concurrently with
    // the handler — unless the accept side already took the plan.
    start_ticket_delivery(&connection, peer, &shared);
    // And the N3 report, for the same reason the tickets are here: a plan is
    // claimed on the first connection to its peer, whichever side opened it.
    // This was missing, so a run whose designated sender was a peer the
    // emulator dialled had no distributor at all and sent nothing -- the
    // node never saw a CE 135 and the inclusion row failed with no trace of
    // why, in half the runs.
    start_report_distribution(&connection, peer, &shared);
    start_sync_probe(&connection, peer, &shared);

    // Serve the NUT's CE 128 / CE 129 requests on the dialed connection.
    handle_connection(connection, peer, genesis_hash, shared).await;
    Ok(())
}

/// Serve a CE 128 block request against `chain` (genesis-first).
///
/// Ascending-exclusive starts at the child of `header_hash`;
/// descending-inclusive starts at `header_hash` and walks parents. Both are
/// capped at `max_blocks`; an unknown hash is an error (reset the stream).
pub fn serve_ce128(request: &BlockRequest, chain: &[Block]) -> Result<BlockResponse, EmuError> {
    let Some(index) = chain
        .iter()
        .position(|block| block.header.hash().0 == request.header_hash.0)
    else {
        return Err(EmuError::UnknownHash(request.header_hash.0));
    };
    let blocks = match request.direction {
        Direction::AscendingExclusive => chain[index + 1..]
            .iter()
            .take(request.max_blocks as usize)
            .cloned()
            .collect(),
        Direction::DescendingInclusive => chain[..=index]
            .iter()
            .rev()
            .take(request.max_blocks as usize)
            .cloned()
            .collect(),
    };
    Ok(BlockResponse { blocks })
}

/// Serve a CE 129 state request: P0 returns an empty state range.
pub fn serve_ce129(_request: &StateRequest) -> StateResponse {
    StateResponse {
        boundary_nodes: vec![],
        entries: vec![],
    }
}

/// Accept-loop for one emulated validator: record accepts and run the N0
/// reactive handler on each connection.
async fn endpoint_task(
    endpoint: Arc<dyn Listener>,
    peer_index: u16,
    genesis_hash: [u8; 32],
    shared: EmuShared,
) {
    let obs = Arc::clone(&shared.obs);
    while let Some(incoming) = endpoint.accept().await {
        record(&obs, peer_index, ObsKind::Accept);
        let Ok(connection) = incoming.established().await else {
            continue;
        };
        // A completed NUT-initiated handshake proves the N0 cert + ALPN
        // contract (simple.md:7-23,48-59): Ed25519 sig alg, key == on-chain,
        // single SAN, and `jamnp-s/1/..` accepted/offered.
        record(&obs, peer_index, ObsKind::Other(n0::CERT_ED25519));
        record(&obs, peer_index, ObsKind::Other(n0::CERT_KEY_MATCH));
        record(&obs, peer_index, ObsKind::Other(n0::CERT_SAN_OK));
        record(&obs, peer_index, ObsKind::Other(n0::ALPN_ACCEPTED));
        record(&obs, peer_index, ObsKind::Other(n0::ALPN_OFFERED));
        record(&obs, peer_index, ObsKind::Other(n0::NUT_INITIATED));
        // Deliver this peer's tickets on the first connection to it, whichever
        // side opened it: the NUT reaching us first must not cost the peer its
        // whole ticket plan.
        start_ticket_delivery(&connection, peer_index, &shared);
        start_report_distribution(&connection, peer_index, &shared);
        start_sync_probe(&connection, peer_index, &shared);
        // One task per connection: with UP 0 persistent the handler runs for
        // the lifetime of the connection, so awaiting it here would stall the
        // accept loop and the peer's redials would never be answered.
        let shared = shared.clone();
        tokio::spawn(async move {
            handle_connection(connection, peer_index, genesis_hash, shared).await;
        });
    }
}

/// Spawn the CE 135 distributor on this connection, if it claims this run's
/// report.
fn start_report_distribution(connection: &Conn, peer: u16, shared: &EmuShared) {
    let connection = connection.clone();
    let mut plans_set = shared.plans_set.clone();
    let shared = shared.clone();
    tokio::spawn(async move {
        while !*plans_set.borrow_and_update() {
            if plans_set.changed().await.is_err() {
                return;
            }
        }
        let Some(plan) = shared.claim_report_plan(peer) else {
            return;
        };
        crate::report_io::spawn_report_sender(
            connection,
            plan.slot,
            plan.nut,
            Arc::clone(&shared.ref_chain),
            Arc::clone(&shared.trace),
            Arc::clone(&shared.obs),
            Arc::clone(&shared.distributed),
            peer,
        )
        .await;
    });
}

/// Spawn the ticket sender for `peer` once a plan exists and if its plan has
/// not been taken yet.
///
/// The wait is what makes the connection order and the planning order
/// independent. Connections come up while the node is still importing the
/// seeded chain; the plan is written once it can accept tickets. Reading the
/// map at connect time found it empty and delivered nothing.
fn start_ticket_delivery(connection: &Conn, peer: u16, shared: &EmuShared) {
    let connection = connection.clone();
    let mut plans_set = shared.plans_set.clone();
    let shared = shared.clone();
    tokio::spawn(async move {
        while !*plans_set.borrow_and_update() {
            // Err only once the `Emulator` is dropped, which ends the run.
            if plans_set.changed().await.is_err() {
                return;
            }
        }
        let Some(plan) = shared.take_ticket_plan(peer) else {
            return;
        };
        spawn_ticket_sender(
            connection,
            plan,
            Arc::clone(&shared.trace),
            Arc::clone(&shared.obs),
            Arc::clone(&shared.deliveries),
            Arc::clone(&shared.nut_final_slot),
            peer,
        )
        .await;
    });
}

/// Application error code used when the emulator refuses a stream: an unknown
/// or refused stream kind, a malformed frame, or a kind outside this subset.
/// The stream is reset; the connection stays up (DESIGN.md `:477`).
const STREAM_REFUSED: u32 = 1;

/// Run the N0 reactive handler on one connection, one task per accepted stream.
///
/// Streams on a JAMNP-S connection are concurrent and independent, and UP 0 is
/// *static*: it stays open for the lifetime of the connection, and closing a
/// peer's incoming static stream is misbehaviour (`simple.md:108-111`). So the
/// accept loop must neither serve streams one at a time — a persistent stream
/// would block every later one — nor drop a stream's halves once its first
/// message is handled. Each accepted stream gets its own task instead, living
/// exactly as long as the peer keeps the stream open.
async fn handle_connection(
    connection: Conn,
    peer_index: u16,
    genesis_hash: [u8; 32],
    shared: EmuShared,
) {
    while let Ok((send, recv)) = connection.accept_bi().await {
        let connection = connection.clone();
        let announce = shared.announce.subscribe();
        let shared = shared.clone();
        tokio::spawn(async move {
            handle_stream(
                connection,
                send,
                recv,
                peer_index,
                genesis_hash,
                &shared,
                announce,
            )
            .await;
        });
    }
}

/// Serve one accepted stream for its whole lifetime.
///
/// The stream-kind byte arrives once, on the opening frame
/// (`simple.md:122-124`), and selects the handler. CE streams are ephemeral:
/// one request, one response, FIN. UP 0 is persistent: keep reading messages
/// until the peer closes it, and never drop the halves first.
async fn handle_stream(
    connection: Conn,
    mut send: SendHalf,
    recv: RecvHalf,
    peer_index: u16,
    genesis_hash: [u8; 32],
    shared: &EmuShared,
    mut announce: broadcast::Receiver<Vec<u8>>,
) {
    let (ref_chain, trace, obs) = (&*shared.ref_chain, &*shared.trace, &*shared.obs);
    let stream_id = send.id();
    let mut reader = StreamReader::new(recv);
    let (kind, content) = match reader.next().await {
        Ok(Some(frame)) => frame,
        // A clean close before any message: nothing to serve, nothing to refuse.
        Ok(None) => return,
        // An unknown or refused kind byte, or a malformed length prefix.
        Err(_) => return refuse(&mut send, &mut reader),
    };
    trace_record(peer_index, kind, stream_id, &content, trace, TraceDir::Tx);
    match kind {
        UP => {
            handle_up0(
                &connection,
                Some(&mut send),
                peer_index,
                genesis_hash,
                stream_id,
                &content,
                shared,
            )
            .await;
            // UP 0 is static for the lifetime of the connection: serve every
            // further message until the peer closes the stream. Returning here
            // would drop both halves, which the peer reads as its incoming
            // static stream being closed — misbehaviour, and it disconnects.
            // Both halves are live from here: the NUT keeps sending on this
            // stream, and the slot driver keeps authoring blocks to announce
            // back on it (A10).
            loop {
                tokio::select! {
                    incoming = reader.next() => match incoming {
                        Ok(Some((_, content))) => {
                            trace_record(peer_index, UP, stream_id, &content, trace, TraceDir::Tx);
                            handle_up0(
                                &connection,
                                Some(&mut send),
                                peer_index,
                                genesis_hash,
                                stream_id,
                                &content,
                                shared,
                            )
                            .await;
                        }
                        // The peer closed its half: the stream is done, not refused.
                        Ok(None) => break,
                        Err(_) => {
                            refuse(&mut send, &mut reader);
                            break;
                        }
                    },
                    announced = announce.recv() => match announced {
                        Ok(wire) => {
                            record(obs, peer_index, ObsKind::Up0Announce);
                            trace_record(peer_index, UP, stream_id, &wire, trace, TraceDir::Rx);
                            if send.write_all(&wire).await.is_err() {
                                break;
                            }
                        }
                        // Fell behind: skip what was missed rather than stall
                        // the driver. The NUT can still fetch over CE 128.
                        Err(broadcast::error::RecvError::Lagged(_)) => {}
                        // The sender lives as long as the `Emulator`, so this
                        // only happens at teardown, when the run is over.
                        Err(broadcast::error::RecvError::Closed) => break,
                    },
                }
            }
        }
        CE128 => {
            serve_block_request(
                &mut send, peer_index, &content, stream_id, ref_chain, trace, obs,
            )
            .await
        }
        CE129 => serve_state_request(&mut send, peer_index, &content, stream_id, trace, obs).await,
        CE131 | CE132 => {
            crate::ticket_io::handle_inbound_ticket(kind, &content, peer_index, obs).await;
        }
        // CE 134 is the NUT sharing a package it was given with its
        // co-guarantors; CE 135 is it distributing the resulting report. Both
        // are the node talking, so neither is refused -- the harness records
        // what it said and the N3 lane grades it.
        CE134 => {
            crate::report_io::handle_inbound_sharing(
                &content,
                &mut reader,
                &mut send,
                peer_index,
                obs,
                &shared.sharing_seen,
                &shared.sharing_answer,
            )
            .await;
        }
        CE135 => {
            crate::report_io::handle_inbound_report(
                &content,
                peer_index,
                obs,
                &shared.reports_seen,
            );
        }
        // Spec-known kinds outside this subset: reset rather than drop, so the
        // refusal is observable to the NUT (DESIGN.md `:477`).
        _ => refuse(&mut send, &mut reader),
    }
}

/// Reset both halves of a stream the emulator will not serve, leaving the
/// connection up.
fn refuse(send: &mut SendHalf, reader: &mut StreamReader) {
    send.reset(STREAM_REFUSED);
    reader.stop(STREAM_REFUSED);
}

/// Forward every announcement the slot driver broadcasts onto one UP 0 send
/// half, for as long as the stream lives.
///
/// A subscriber that falls behind by more than [`ANNOUNCE_BUFFER`] skips what
/// it missed and carries on: dropping announcements on a stalled stream is
/// better than stalling the driver, and the node can still fetch any block it
/// hears about later over CE 128.
async fn pump_announcements(
    mut send: SendHalf,
    mut rx: broadcast::Receiver<Vec<u8>>,
    peer_index: u16,
    stream_id: u64,
    trace: Arc<Mutex<Trace>>,
    obs: Arc<Mutex<ObsLog>>,
) {
    loop {
        match rx.recv().await {
            Ok(wire) => {
                record(&obs, peer_index, ObsKind::Up0Announce);
                trace_record(peer_index, UP, stream_id, &wire, &trace, TraceDir::Rx);
                if send.write_all(&wire).await.is_err() {
                    break;
                }
            }
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}

/// Read the receive half of a UP 0 stream the emulator opened, for as long as
/// the NUT keeps it open.
///
/// The mirror of the UP 0 arm of [`handle_stream`], with two differences: the
/// half carries no opening kind byte, since we wrote it when we opened the
/// stream, and nothing is answered — our handshake went out with the open.
async fn read_dialed_up0(
    connection: Conn,
    recv: RecvHalf,
    peer_index: u16,
    genesis_hash: [u8; 32],
    stream_id: u64,
    shared: EmuShared,
) {
    let mut reader = StreamReader::with_kind(recv, UP);
    loop {
        match reader.next().await {
            Ok(Some((_, content))) => {
                trace_record(
                    peer_index,
                    UP,
                    stream_id,
                    &content,
                    &shared.trace,
                    TraceDir::Tx,
                );
                handle_up0(
                    &connection,
                    None,
                    peer_index,
                    genesis_hash,
                    stream_id,
                    &content,
                    &shared,
                )
                .await;
            }
            // The NUT closed its half: the stream is done, not refused.
            Ok(None) => break,
            // Do not reset the stream on a malformed frame: the send half is
            // still carrying our announcements, and resetting would take the
            // whole UP 0 stream down with it.
            Err(_) => break,
        }
    }
}

/// Handle a NUT UP 0 message: an `Announcement` is recorded (`Up0Announce`
/// plus the N0 re-announce observation — the P0 emulator cannot distinguish
/// announce from re-announce) and left unanswered; anything else is a
/// handshake, answered with our own (recording `OpenUp0`).
///
/// `send` is `None` on a stream the emulator opened itself: our handshake went
/// out when the stream was opened, so the NUT's is an answer to it, and
/// answering back would put a second handshake on the stream.
async fn handle_up0(
    connection: &Conn,
    send: Option<&mut SendHalf>,
    peer_index: u16,
    genesis_hash: [u8; 32],
    stream_id: u64,
    content: &[u8],
    shared: &EmuShared,
) {
    let (ref_chain, trace, obs) = (&*shared.ref_chain, &*shared.trace, &*shared.obs);
    if let Ok(announcement) = Announcement::decode(&mut &content[..]) {
        shared.note_nut_final(announcement.final_block.slot);
        record(obs, peer_index, ObsKind::Up0Announce);
        record(obs, peer_index, ObsKind::Other(n0::REANNOUNCED));
        // An announced block outside the reference chain is a NUT-authored
        // block: fetch it over CE 128 and record it (fetch errors leave the
        // announcement recorded and the stream open).
        let hash = announcement.header.hash().0;
        if should_fetch(&hash, ref_chain, &shared.nut_blocks) {
            let _ = fetch_block(connection, hash, peer_index, shared).await;
        }
        return;
    }
    record(obs, peer_index, ObsKind::Other(n0::UP0_KIND0));
    if let Ok(handshake) = Handshake::decode(&mut &content[..]) {
        shared.note_nut_final(handshake.final_block.slot);
        if handshake.final_block.header_hash == HeaderHash::from(genesis_hash) {
            record(obs, peer_index, ObsKind::Other(n0::UP0_FINAL_GENESIS));
        }
        if let Some(send) = send {
            respond_up0(
                send,
                peer_index,
                genesis_hash,
                stream_id,
                ref_chain,
                trace,
                obs,
            )
            .await;
        }
        return;
    }
    if let Some(send) = send {
        respond_up0(
            send,
            peer_index,
            genesis_hash,
            stream_id,
            ref_chain,
            trace,
            obs,
        )
        .await;
    }
}

/// The `Final` block the emulator advertises on UP 0.
///
/// polkajam only requests blocks from a peer whose advertised final slot is
/// *strictly* greater than its own queued slot (`sync/mod.rs`
/// `maybe_request_from_peer`), so advertising genesis means it never syncs.
pub fn advertised_final(chain: &[Block], genesis_hash: [u8; 32]) -> Final {
    match chain.last() {
        Some(head) => Final {
            header_hash: head.header.hash(),
            slot: head.header.slot,
        },
        None => Final {
            header_hash: HeaderHash::from(genesis_hash),
            slot: 0,
        },
    }
}

/// Respond to the NUT's UP 0 handshake with our own, recording `OpenUp0`.
async fn respond_up0(
    send: &mut SendHalf,
    peer_index: u16,
    genesis_hash: [u8; 32],
    stream_id: u64,
    ref_chain: &RefChain,
    trace: &Mutex<Trace>,
    obs: &Mutex<ObsLog>,
) {
    record(obs, peer_index, ObsKind::OpenUp0);
    let handshake = Handshake {
        final_block: advertised_final(&ref_chain.chain_blocks(), genesis_hash),
        leaves: vec![],
    };
    let wire = frame_message(&handshake.encode());
    trace_record(peer_index, UP, stream_id, &wire, trace, TraceDir::Rx);
    let _ = send.write_all(&wire).await;
    // UP 0 is persistent: keep the send half open (simple.md:108-111).
}

/// Serve a NUT CE 128 block request from the reference chain.
async fn serve_block_request(
    send: &mut SendHalf,
    peer_index: u16,
    content: &[u8],
    stream_id: u64,
    ref_chain: &RefChain,
    trace: &Mutex<Trace>,
    obs: &Mutex<ObsLog>,
) {
    let Ok(request) = BlockRequest::decode(&mut &content[..]) else {
        return;
    };
    let at = mono_ts();
    lock(obs).push(
        at,
        Obs {
            peer: peer_index,
            kind: ObsKind::ServesCe128,
            at_ms: at,
        },
    );
    let chain = ref_chain.chain_blocks();
    let Ok(response) = serve_ce128(&request, &chain) else {
        return;
    };
    record(obs, peer_index, ObsKind::Other(n0::CE128_FIN_BOTH));
    record(obs, peer_index, ObsKind::Other(n0::CE128_MAX_RESPECTED));
    let wire = frame_message(&response.encode());
    trace_record(peer_index, CE128, stream_id, &wire, trace, TraceDir::Rx);
    let _ = send.write_all(&wire).await;
    send.finish();
}

/// Serve a NUT CE 129 state request: empty response for P0.
async fn serve_state_request(
    send: &mut SendHalf,
    peer_index: u16,
    content: &[u8],
    stream_id: u64,
    trace: &Mutex<Trace>,
    obs: &Mutex<ObsLog>,
) {
    let Ok(request) = StateRequest::decode(&mut &content[..]) else {
        return;
    };
    let at = mono_ts();
    lock(obs).push(
        at,
        Obs {
            peer: peer_index,
            kind: ObsKind::ServesCe129,
            at_ms: at,
        },
    );
    let response = serve_ce129(&request);
    // The P0 CE 129 response is an empty well-formed reply: an empty key range
    // trivially satisfies the sorted/boundary/size/len-prefix rules.
    record(obs, peer_index, ObsKind::Other(n0::CE129_SORTED));
    record(obs, peer_index, ObsKind::Other(n0::CE129_BOUNDARY_ORDER));
    record(obs, peer_index, ObsKind::Other(n0::CE129_SIZE_CAP));
    record(obs, peer_index, ObsKind::Other(n0::CE129_LEN_PREFIXED));
    // Two messages, then FIN (`simple.md:300-302`): the boundary nodes first,
    // the key/value pairs second. Both are size-implied sequences, so an empty
    // reply is two *empty* messages — packing them into one, or prefixing
    // either with its length, makes a conforming requester read the prefix as
    // the first item and reject the responder.
    let (nodes, entries) = response.messages();
    for payload in [nodes, entries] {
        let wire = frame_message(&payload);
        trace_record(peer_index, CE129, stream_id, &wire, trace, TraceDir::Rx);
        if send.write_all(&wire).await.is_err() {
            return;
        }
    }
    send.finish();
}

/// Incremental frame reader over one QUIC receive stream.
///
/// The [`FrameReader`] is kept across reads rather than rebuilt per message: a
/// single `read` routinely delivers the opening frame together with the bytes
/// of the frames behind it, so a reader recreated per message silently drops
/// everything that arrived alongside the first one. On a persistent stream that
/// loses messages; on an ephemeral one it is invisible.
pub(crate) struct StreamReader {
    recv: RecvHalf,
    reader: FrameReader,
    buf: [u8; 4096],
}

impl StreamReader {
    /// Wrap a freshly accepted receive stream, whose first frame carries the
    /// stream-kind byte.
    pub(crate) fn new(recv: RecvHalf) -> Self {
        Self {
            recv,
            reader: FrameReader::new(),
            buf: [0u8; 4096],
        }
    }

    /// Wrap the receive half of a stream *we* opened, which carries no kind
    /// byte: we wrote it, so the peer's replies are bare messages under `kind`.
    pub(crate) fn with_kind(recv: RecvHalf, kind: u8) -> Self {
        Self {
            recv,
            reader: FrameReader::with_kind(kind),
            buf: [0u8; 4096],
        }
    }

    /// The next complete message as `(kind, content)`, or `None` at a clean end
    /// of stream. The kind byte is carried by the first frame only
    /// (`simple.md:122-124`); later frames report the same kind.
    pub(crate) async fn next(&mut self) -> Result<Option<(u8, Vec<u8>)>, EmuError> {
        loop {
            // Drain what is already buffered before waiting on the wire.
            match self.reader.next_frame() {
                Ok(Some(item)) => return Ok(Some(item)),
                Ok(None) => {}
                Err(e) => return Err(EmuError::Protocol(format!("{e:?}"))),
            }
            match self.recv.read(&mut self.buf).await {
                Ok(Some(n)) => {
                    let (buf, reader) = (&self.buf, &mut self.reader);
                    reader.push(&buf[..n]);
                }
                Ok(None) => {
                    self.reader
                        .finish()
                        .map_err(|e| EmuError::Protocol(format!("{e:?}")))?;
                    return Ok(None);
                }
                Err(e) => return Err(EmuError::Protocol(format!("{e:?}"))),
            }
        }
    }

    /// Ask the peer to stop sending on this stream.
    pub(crate) fn stop(&mut self, code: u32) {
        self.recv.stop(code);
    }
}

/// Record a frame in the shared trace (direction is from the NUT's perspective:
/// `Tx` = the NUT sent it, `Rx` = the emulator sent it).
pub(crate) fn trace_record(
    peer: u16,
    kind: u8,
    stream_id: u64,
    bytes: &[u8],
    trace: &Mutex<Trace>,
    direction: TraceDir,
) {
    lock(trace).push(TraceRecord {
        direction,
        peer_index: peer,
        stream_kind: kind,
        stream_id,
        mono_ts: mono_ts(),
        wall_ts: wall_ts(),
        bytes: bytes.to_vec(),
    });
}

/// Lock a shared mutex, recovering from poisoning (emulator code never panics).
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Record an observation from `peer` at the current monotonic time.
///
/// Public so the runner can record decisions it makes about a connection
/// before any emulator code runs on it, such as the post-grace fallback dial.
/// Seconds per slot (JAM common slot period).
pub const SLOT_PERIOD_SEC: u64 = 6;

/// Wall-clock milliseconds at which `slot` begins.
///
/// Wall clock, not run-relative: everything that schedules against a slot --
/// ticket delivery, package submission -- is compared by the lanes against
/// absolute slot starts, and a run-relative stamp would put every event
/// before the run began.
pub fn slot_start_ms(slot: u32) -> u64 {
    (jam_types::JAM_COMMON_ERA + u64::from(slot) * SLOT_PERIOD_SEC) * 1000
}

pub fn record(obs: &Mutex<ObsLog>, peer: u16, kind: ObsKind) {
    let at = mono_ts();
    lock(obs).push(
        at,
        Obs {
            peer,
            kind,
            at_ms: at,
        },
    );
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use jam_types::{Encode, HeaderHash};
    use jamnp_s::codec::ce128_129::{BlockRequest, Direction, StateRequest};
    use m2_reference::chain::RefChain;

    fn chain_err(e: m2_reference::chain::ChainError) -> EmuError {
        EmuError::Protocol(e.to_string())
    }

    #[tokio::test]
    async fn boots_five_endpoints() -> Result<(), EmuError> {
        let emu = Emulator::n0(vec![1, 2, 3, 4, 5], [0xaa; 32], 40000).await?;
        let addrs = emu.local_addrs();
        assert_eq!(addrs.len(), 5);
        let ports: HashSet<u16> = addrs.iter().map(|a| a.port()).collect();
        assert_eq!(ports.len(), 5, "the five ports must be distinct");
        assert!(
            ports.iter().all(|&p| p >= 40001),
            "ports must be >= base + 1"
        );
        Ok(())
    }

    /// A share is answered with the reference's report hash and this
    /// validator's signature over it (`simple.md:456`).
    ///
    /// The reply carries no kind byte: the node opened the stream, so what
    /// comes back on it is a bare message. Getting that wrong would put a
    /// stray 134 in front of the hash and the node would read the first 32
    /// bytes of a 33-byte value.
    #[tokio::test]
    async fn a_ce134_share_is_answered_with_the_reference_hash_and_signature(
    ) -> Result<(), EmuError> {
        use jamnp_s::codec::ce131_136::{SharingContext, SharingReply};
        use jamnp_s::framing::CE134;
        use jamnp_s::transport::mock::MockNetwork;
        use jamnp_s::transport::Transport;
        use m2_reference::reports::SharingAnswer;
        use std::time::Duration;

        const GENESIS: [u8; 32] = [0xdd; 32];
        const PEER: u16 = 1;
        let net = MockNetwork::new();
        let emu =
            Emulator::n0_on(Arc::new(net.clone()), vec![PEER as usize], GENESIS, 40300).await?;
        let addr = emu.local_addrs()[0];
        let ref_chain = Arc::new(RefChain::tiny(0).map_err(chain_err)?);

        let report_hash = [0x3c; 32];
        let signature = [0x9e; 64];
        *lock(&emu.sharing_answer) = Some(SharingAnswer {
            report_hash,
            // Validator 4 holds the core too; only this peer's own signature
            // may come back on this stream.
            signatures: vec![(PEER, signature), (4, [0x11; 64])],
        });
        let _accepting = emu.accept_loop(ref_chain);

        let conn = net
            .connect(
                EndpointConfig {
                    genesis_hash: GENESIS,
                    builder: false,
                },
                SigningKey::from([9u8; 32]),
                "peer".to_string(),
                addr,
            )
            .await
            .expect("the stand-in node reaches the emulated validator");

        let (mut send, mut recv) = conn.open_bi().await.expect("CE 134 opens");
        let context = SharingContext {
            core_index: 0,
            shard_count: 6,
            mappings: Vec::new(),
        };
        send.write_all(&frame(CE134, &context.encode()))
            .await
            .expect("message 1 goes out");
        send.write_all(&frame_message(&[0xab; 16]))
            .await
            .expect("message 2 goes out");
        send.finish();

        // We opened the stream, so the answer is a bare message under CE 134.
        let mut reader = FrameReader::with_kind(CE134);
        let mut buf = [0u8; 4096];
        let answer = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(Some((_, content))) = reader.next_frame() {
                    return content;
                }
                match recv.read(&mut buf).await {
                    Ok(Some(n)) => reader.push(&buf[..n]),
                    _ => return Vec::new(),
                }
            }
        })
        .await
        .expect("the answer arrives in time");

        let decoded = SharingReply::decode(&mut &answer[..]).expect("the answer is a CE 134 reply");
        assert_eq!(decoded.report_hash.0, report_hash);
        assert_eq!(
            decoded.signature, signature,
            "the peer signs as itself, not as another holder of the core"
        );
        Ok(())
    }

    /// The CE 133 submitter puts both messages on one stream and records the
    /// node's answer.
    ///
    /// Driven directly rather than through the emulator's accept loop: the
    /// submission is builder-to-guarantor and no longer rides a validator
    /// connection, so the emulator does not spawn it. What is still worth
    /// proving over the carrier is the sender itself -- two messages on one
    /// stream, under the CE 133 kind byte, with the package unprefixed and
    /// the extrinsic bodies concatenated.
    #[tokio::test]
    async fn a_ce133_submission_reaches_the_node_as_two_messages() -> Result<(), EmuError> {
        use jamnp_s::framing::CE133;
        use jamnp_s::transport::mock::MockNetwork;
        use jamnp_s::transport::Transport;
        use m2_reference::reports::ScheduledSubmission;
        use std::time::Duration;

        const GENESIS: [u8; 32] = [0xcc; 32];
        let net = MockNetwork::new();
        let config = EndpointConfig {
            genesis_hash: GENESIS,
            builder: false,
        };
        // A stand-in node, listening.
        let node = net
            .listen(
                config.clone(),
                SigningKey::from([7u8; 32]),
                "127.0.0.1:40200".parse().expect("addr parses"),
            )
            .await
            .expect("the stand-in node binds");
        let addr = node.local_addr();

        // Slot 0 is long past, so the sender does not wait for a slot start.
        let package = vec![0xa1; 48];
        let extrinsics = vec![vec![0x01, 0x02], vec![0x03]];
        let plan = ScheduledSubmission {
            slot: 0,
            core: 1,
            package: package.clone(),
            package_hash: [0x5a; 32],
            extrinsics: extrinsics.clone(),
            co_guarantors: vec![2, 3],
            fault: None,
        };

        let builder = net
            .connect(
                EndpointConfig {
                    genesis_hash: GENESIS,
                    builder: true,
                },
                SigningKey::from([9u8; 32]),
                "peer".to_string(),
                addr,
            )
            .await
            .expect("the builder reaches the node");

        let submissions = Arc::new(Mutex::new(Vec::new()));
        let sender = tokio::spawn(crate::report_io::spawn_package_sender(
            builder.clone(),
            plan,
            Arc::new(Mutex::new(Trace::default())),
            Arc::new(Mutex::new(ObsLog::new())),
            Arc::clone(&submissions),
            0xB0,
        ));

        let incoming = tokio::time::timeout(Duration::from_secs(5), node.accept())
            .await
            .expect("the builder connects in time")
            .expect("a connection arrives");
        let connection = incoming
            .established()
            .await
            .expect("the connection establishes");
        let (_send, mut recv) =
            tokio::time::timeout(Duration::from_secs(5), connection.accept_bi())
                .await
                .expect("the submission arrives in time")
                .expect("a stream is opened");

        let mut reader = FrameReader::new();
        let mut buf = [0u8; 4096];
        let mut messages: Vec<(u8, Vec<u8>)> = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), async {
            while messages.len() < 2 {
                if let Ok(Some(item)) = reader.next_frame() {
                    messages.push(item);
                    continue;
                }
                match recv.read(&mut buf).await {
                    Ok(Some(n)) => reader.push(&buf[..n]),
                    _ => break,
                }
            }
        })
        .await
        .expect("both messages arrive in time");

        assert_eq!(messages.len(), 2, "two messages on one stream");
        assert_eq!(messages[0].0, CE133, "under the CE 133 kind byte");
        let mut expected_first = 1u16.encode();
        expected_first.extend_from_slice(&package);
        assert_eq!(
            messages[0].1, expected_first,
            "message 1 is the core index then the package, unprefixed"
        );
        assert_eq!(
            messages[1].1,
            vec![0x01, 0x02, 0x03],
            "message 2 is the extrinsic bodies concatenated"
        );

        sender.abort();
        assert_eq!(
            lock(&submissions).first().map(|s| s.core),
            Some(1),
            "the submission is recorded against the core it named"
        );
        Ok(())
    }

    /// A CE 134 share the node opens is recorded whole: the context from
    /// message 1 and the bundle from message 2.
    ///
    /// End to end over the carrier rather than by calling the handler, because
    /// the thing most likely to be wrong is the dispatch -- a kind byte that
    /// reaches the catch-all is refused, and the share would be lost with no
    /// record that anything arrived.
    #[tokio::test]
    async fn a_ce134_share_from_the_node_is_recorded() -> Result<(), EmuError> {
        use jamnp_s::codec::ce131_136::{SharingBundle, SharingContext};
        use jamnp_s::framing::CE134;
        use jamnp_s::transport::mock::MockNetwork;
        use jamnp_s::transport::Transport;
        use std::time::Duration;

        const GENESIS: [u8; 32] = [0xbb; 32];
        let net = MockNetwork::new();
        let emu = Emulator::n0_on(Arc::new(net.clone()), vec![1], GENESIS, 40100).await?;
        let addr = emu.local_addrs()[0];
        let ref_chain = Arc::new(RefChain::tiny(0).map_err(chain_err)?);
        let records = emu.sharing_seen();
        let _accepting = emu.accept_loop(ref_chain);

        let conn = net
            .connect(
                EndpointConfig {
                    genesis_hash: GENESIS,
                    builder: false,
                },
                SigningKey::from([9u8; 32]),
                "peer".to_string(),
                addr,
            )
            .await
            .expect("the stand-in node reaches the emulated validator");

        let context = SharingContext {
            core_index: 1,
            shard_count: 6,
            mappings: vec![(jam_types::WorkPackageHash::from([0x11; 32]), [0x22; 32])],
        };
        let bundle = SharingBundle {
            bundle: vec![0xab; 64],
        };
        let (mut send, _recv) = conn.open_bi().await.expect("CE 134 opens");
        send.write_all(&frame(CE134, &context.encode()))
            .await
            .expect("message 1 goes out");
        send.write_all(&frame_message(&bundle.encode()))
            .await
            .expect("message 2 goes out");
        send.finish();

        let seen = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(first) = lock(&records).first() {
                    return first.clone();
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the share is recorded in time");

        assert_eq!(seen.core_index, 1);
        assert_eq!(seen.shard_count, 6);
        assert_eq!(seen.mappings, context.mappings);
        assert_eq!(
            seen.bundle.as_deref(),
            Some(&bundle.bundle[..]),
            "the bundle is the message, with no length of its own"
        );
        Ok(())
    }

    /// The emulator on the in-process carrier: a stand-in node dials it,
    /// opens UP 0, and is answered.
    ///
    /// `n0_on` is the injection point M2-B's self-test runs through, so it is
    /// worth one test that the whole emulator -- accept loop, stream handler,
    /// UP 0 responder -- works over a transport with no sockets under it, and
    /// not just that the mock carries bytes.
    #[tokio::test]
    async fn runs_over_an_in_process_transport() -> Result<(), EmuError> {
        use jamnp_s::transport::mock::MockNetwork;
        use jamnp_s::transport::Transport;
        use std::time::Duration;

        const GENESIS: [u8; 32] = [0xaa; 32];
        let net = MockNetwork::new();
        let emu = Emulator::n0_on(Arc::new(net.clone()), vec![1], GENESIS, 40000).await?;
        let addr = emu.local_addrs()[0];
        let ref_chain = Arc::new(RefChain::tiny(0).map_err(chain_err)?);
        let _accepting = emu.accept_loop(ref_chain);

        let config = EndpointConfig {
            genesis_hash: GENESIS,
            builder: false,
        };
        let conn = net
            .connect(
                config,
                SigningKey::from([9u8; 32]),
                "peer".to_string(),
                addr,
            )
            .await
            .expect("the stand-in node reaches the emulated validator");
        let (mut send, mut recv) = conn.open_bi().await.expect("UP 0 opens");
        let handshake = Handshake {
            final_block: Final {
                header_hash: HeaderHash::from(GENESIS),
                slot: 0,
            },
            leaves: vec![],
        };
        send.write_all(&frame(UP, &handshake.encode()))
            .await
            .expect("the handshake goes out");

        // We opened the stream, so the reply is a bare message under UP.
        let mut reader = FrameReader::with_kind(UP);
        let mut buf = [0u8; 4096];
        let answer = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(Some((_, content))) = reader.next_frame() {
                    return content;
                }
                match recv.read(&mut buf).await {
                    Ok(Some(n)) => reader.push(&buf[..n]),
                    _ => return Vec::new(),
                }
            }
        })
        .await
        .expect("the emulator answers in time");
        assert!(
            Handshake::decode(&mut &answer[..]).is_ok(),
            "the emulator answers UP 0 with its own handshake"
        );
        Ok(())
    }

    #[test]
    fn serves_ce128_ascending_from_genesis() -> Result<(), EmuError> {
        let ref_chain = RefChain::tiny(0).map_err(chain_err)?;
        let start = ref_chain.next_slot();
        for slot in start..start + 12 {
            let _ = ref_chain.author_block(slot).map_err(chain_err)?;
        }
        let chain = ref_chain.chain_blocks();
        let genesis = ref_chain.genesis_hash();

        // Ascending-exclusive from genesis equals the reference chain (minus genesis).
        let ascending = BlockRequest {
            header_hash: HeaderHash::from(genesis),
            direction: Direction::AscendingExclusive,
            max_blocks: u32::MAX,
        };
        let got: Vec<Vec<u8>> = serve_ce128(&ascending, &chain)?
            .blocks
            .iter()
            .map(|b| b.encode())
            .collect();
        let want: Vec<Vec<u8>> = chain[1..].iter().map(|b| b.encode()).collect();
        assert_eq!(got, want);

        // max_blocks is respected.
        let capped = BlockRequest {
            header_hash: HeaderHash::from(genesis),
            direction: Direction::AscendingExclusive,
            max_blocks: 2,
        };
        assert_eq!(serve_ce128(&capped, &chain)?.blocks.len(), 2);

        // Unknown header hash -> Err (the stream is reset).
        let unknown = BlockRequest {
            header_hash: HeaderHash::from([0xee; 32]),
            direction: Direction::AscendingExclusive,
            max_blocks: 5,
        };
        assert!(serve_ce128(&unknown, &chain).is_err());

        // Descending-inclusive from the head walks parents.
        let head = chain
            .last()
            .expect("reference chain is non-empty")
            .header
            .hash()
            .0;
        let descending = BlockRequest {
            header_hash: HeaderHash::from(head),
            direction: Direction::DescendingInclusive,
            max_blocks: 3,
        };
        let got: Vec<Vec<u8>> = serve_ce128(&descending, &chain)?
            .blocks
            .iter()
            .map(|b| b.encode())
            .collect();
        let want: Vec<Vec<u8>> = chain.iter().rev().take(3).map(|b| b.encode()).collect();
        assert_eq!(got, want);
        Ok(())
    }

    #[test]
    fn serves_ce129_shapes() {
        let request = StateRequest {
            header_hash: HeaderHash::from([0xaa; 32]),
            start: [0; 31],
            end: [0xff; 31],
            max_size: 4096,
        };
        let response = serve_ce129(&request);
        assert!(
            response.boundary_nodes.is_empty(),
            "P0 serves no boundary nodes"
        );
        assert!(response.entries.is_empty(), "P0 serves no entries");
    }

    #[test]
    fn preferred_initiator_connects_first() {
        let nut_key = SecretKeyset::trivial(0)
            .public(Default::default())
            .ed25519
            .to_bytes();
        for i in 1..=5u32 {
            let emu_key = SecretKeyset::trivial(i)
                .public(Default::default())
                .ed25519
                .to_bytes();
            let emu_preferred = jamnp_s::preferred::preferred_initiator(&emu_key, &nut_key);
            let winner = jamnp_s::preferred::initiator(&emu_key, &nut_key);
            // `emu_key` is the preferred initiator exactly when it wins the tie-break.
            assert_eq!(emu_preferred, winner == emu_key);
            // The rule is a strict total order: the winner is one of the two keys.
            assert!(winner == emu_key || winner == nut_key);
        }
    }

    fn chain_with_blocks() -> Result<RefChain, m2_reference::chain::ChainError> {
        let chain = RefChain::tiny(0)?;
        let start = chain.next_slot();
        let mut authored = 0;
        for slot in start..start + 12 {
            if chain.author_block(slot)?.is_some() {
                authored += 1;
                if authored >= 2 {
                    break;
                }
            }
        }
        assert!(authored > 0, "an emulated slot appears within 12 slots");
        Ok(chain)
    }

    #[test]
    fn advertised_final_is_reference_head() -> Result<(), m2_reference::chain::ChainError> {
        let chain = chain_with_blocks()?;
        let genesis = chain.genesis_hash();
        let blocks = chain.chain_blocks();
        let head = blocks.last().expect("chain has a head beyond genesis");

        let advertised = advertised_final(&blocks, genesis);

        assert_eq!(
            advertised.slot, head.header.slot,
            "advertised final slot must be the reference head, else polkajam \
             never requests blocks (it needs peer.final_slot > its queued slot)"
        );
        assert_eq!(advertised.header_hash.0, head.header.hash().0);
        assert!(advertised.slot > 0, "head slot is past genesis");
        Ok(())
    }

    #[test]
    fn advertised_final_falls_back_to_genesis_when_empty() {
        let genesis = [7u8; 32];
        let advertised = advertised_final(&[], genesis);
        assert_eq!(advertised.header_hash.0, genesis);
        assert_eq!(advertised.slot, 0);
    }
}
