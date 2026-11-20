//! CE 142 and CE 143: introducing a preimage as a non-validator
//! (`simple.md:700-744`).
//!
//! The lane this feeds is N6. It is the one place the harness speaks as an
//! *ordinary* peer rather than a validator or a builder, because the spec
//! writes the protocol that way: "This should be used by non-validator
//! nodes to introduce preimages" (`:702-703`), and polkajam agrees --
//! `as_val_from_ordinary[PreimageAnnouncement]` is unlimited while
//! `as_val_from_non_neighbor[PreimageAnnouncement]` is disallowed, so an
//! announcement from a validator the NUT does not neighbour is refused for
//! a reason that has nothing to do with the preimage.
//!
//! The exchange is two protocols on one connection, in opposite directions.
//! The harness opens CE 142 and says what it has; the node opens CE 143
//! back on the *same* connection to ask for it. So the announcer cannot
//! send and leave: `:707-710` asks a non-validator to "keep the connection
//! open for a reasonable time (eg 10 seconds) to allow this request to be
//! made", and a harness that dropped the connection after the announcement
//! would grade the node on a request it was given no chance to make.

use std::sync::{Arc, Mutex};

use jam_types::{Decode, Encode};
use jamnp_s::{
    clock,
    codec::ce141_145::{PreimageAnnouncement, PreimageReply, PreimageRequest},
    framing::{frame, frame_message, CE142, CE143},
    trace::{wall_ts, Direction as TraceDir, Trace},
    transport::{Conn, RecvHalf, SendHalf},
};
use m2_scenario::dsl::{ObsKind, ObsLog};
use m2_scenario::scenarios::n6::{AnnouncedPreimage, PreimageRequested};
use m2_scenario::scenarios::obs::{EMU_SENT_142, EMU_SERVED_143, NUT_SENT_143};

use crate::emu::{lock, record, trace_record, StreamReader};

/// How long the announcer holds its connection open after announcing.
///
/// `simple.md:708` says "a reasonable time (eg 10 seconds)". Ten, because
/// the spec names ten: a shorter hold would make a node that is merely slow
/// look like a node that never asked, and the row could not tell the two
/// apart.
const HOLD_SECS: u64 = 10;

/// Announce a preimage over CE 142, then serve CE 143 on the same
/// connection for as long as the spec asks.
///
/// Returns once the hold is over, whether or not the node asked.
#[allow(clippy::too_many_arguments)]
pub async fn announce_and_serve(
    connection: Conn,
    service_id: u32,
    blob: Vec<u8>,
    trace: Arc<Mutex<Trace>>,
    obs: Arc<Mutex<ObsLog>>,
    announced: Arc<Mutex<Vec<AnnouncedPreimage>>>,
    requests: Arc<Mutex<Vec<PreimageRequested>>>,
    peer: u16,
) {
    let hash = jam_std_common::hash_raw(&blob);
    let announcement = PreimageAnnouncement {
        service_id,
        hash,
        length: blob.len() as u32,
    };

    let Ok((mut send, _recv)) = connection.open_bi().await else {
        eprintln!(
            "[preimage] could not open CE 142: {}",
            match connection.end_reason() {
                Some(end) => format!("the connection had ended: {end}"),
                None => "the connection is up but would not open a stream".to_string(),
            }
        );
        return;
    };
    let wire = frame(CE142, &announcement.encode());
    trace_record(peer, CE142, send.id(), &wire, &trace, TraceDir::Rx);
    if send.write_all(&wire).await.is_err() {
        eprintln!("[preimage] could not write the CE 142 announcement");
        return;
    }
    send.finish();
    let announced_at = wall_ts();
    record(&obs, peer, ObsKind::Other(EMU_SENT_142));
    lock(&announced).push(AnnouncedPreimage {
        peer,
        service_id,
        hash,
        length: blob.len() as u32,
        at_wall_ms: announced_at,
    });
    eprintln!(
        "[preimage] announced {} ({} bytes) for service {service_id}; holding {HOLD_SECS}s",
        hex8(&hash),
        blob.len()
    );

    // The hold. Every stream the node opens in it is served, because a node
    // may ask more than once and a harness that answered only the first
    // would record the rest as unanswered.
    let clock = clock::current();
    let deadline = clock.sleep(std::time::Duration::from_secs(HOLD_SECS));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            biased;
            () = &mut deadline => break,
            accepted = connection.accept_bi() => {
                let Ok((send, recv)) = accepted else {
                    // The node closed, or the connection died. Either way
                    // there is nothing more to serve, and the row reads the
                    // end rather than the silence.
                    if let Some(end) = connection.end_reason() {
                        eprintln!("[preimage] the announcing connection ended: {end}");
                    }
                    break;
                };
                serve_one(
                    send,
                    recv,
                    &blob,
                    hash,
                    announced_at,
                    &trace,
                    &obs,
                    &requests,
                    peer,
                )
                .await;
            }
        }
    }
}

/// Serve one stream the node opened, which should be CE 143 asking for the
/// preimage just announced.
#[allow(clippy::too_many_arguments)]
async fn serve_one(
    mut send: SendHalf,
    recv: RecvHalf,
    blob: &[u8],
    announced_hash: [u8; 32],
    announced_at: u64,
    trace: &Arc<Mutex<Trace>>,
    obs: &Arc<Mutex<ObsLog>>,
    requests: &Arc<Mutex<Vec<PreimageRequested>>>,
    peer: u16,
) {
    let mut reader = StreamReader::new(recv);
    let Ok(Some((kind, content))) = reader.next().await else {
        return;
    };
    trace_record(peer, kind, send.id(), &content, trace, TraceDir::Tx);
    if kind != CE143 {
        // Not the protocol this connection exists for. Reset rather than
        // drop, so the refusal is observable to the node (DESIGN `:477`).
        send.reset(STREAM_REFUSED);
        return;
    }
    record(obs, peer, ObsKind::Other(NUT_SENT_143));

    let asked = PreimageRequest::decode(&mut &content[..])
        .ok()
        .map(|r| r.hash);
    lock(requests).push(PreimageRequested {
        peer,
        asked: asked.unwrap_or_default(),
        matched_announcement: asked == Some(announced_hash),
        after_announcement_ms: wall_ts().saturating_sub(announced_at),
        answered: asked == Some(announced_hash),
    });

    // Answered only where the hash is the one announced. A node that asked
    // for something else is not owed this blob, and sending it anyway would
    // make the harness the source of a preimage nobody requested.
    if asked != Some(announced_hash) {
        eprintln!(
            "[preimage] the NUT asked for {} but {} was announced",
            asked
                .map(|h| hex8(&h))
                .unwrap_or_else(|| "a malformed request".into()),
            hex8(&announced_hash)
        );
        send.reset(STREAM_REFUSED);
        return;
    }
    let reply = frame_message(
        &PreimageReply {
            preimage: blob.to_vec(),
        }
        .encode(),
    );
    trace_record(peer, CE143, send.id(), &reply, trace, TraceDir::Rx);
    let _ = send.write_all(&reply).await;
    send.finish();
    record(obs, peer, ObsKind::Other(EMU_SERVED_143));
}

/// The code an unserved stream kind is reset with, as the emulator uses
/// elsewhere (DESIGN `:477`).
const STREAM_REFUSED: u32 = 1;

/// First four bytes of a hash, for a message a reader has to scan.
fn hex8(bytes: &[u8; 32]) -> String {
    bytes.iter().take(4).map(|b| format!("{b:02x}")).collect()
}
