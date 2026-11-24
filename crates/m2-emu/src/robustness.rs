//! N7 provocations: the emulator sends the node things no conforming peer
//! would send, and records what survived.
//!
//! Every other module here speaks the protocol correctly and grades the
//! answer. This one is the exception, so the bytes are built by hand rather
//! than through `jamnp-s`'s codecs — a codec that would let us emit a
//! truncated message would be a codec with a bug.
//!
//! **Reading the node's verdict.** A rejection can arrive three ways and they
//! are not the same answer: a stream reset costs the stream, a connection
//! close costs every protocol with that peer, and a hang costs the harness a
//! timeout. `report_io` learned this the hard way (`findings.md` §8): a
//! timeout and a refusal fail the same read identically, so the end is read
//! from the *connection* rather than inferred from the read, which gives one
//! answer over both carriers.

use std::sync::Mutex;
use std::time::Duration;

use jamnp_s::{
    clock,
    framing::frame,
    trace::{Direction as TraceDir, Trace},
    transport::{Conn, ConnectionEnd, ReadError},
};
use m2_scenario::scenarios::n7::{Fault, Provocation, StreamOutcome};

use crate::emu::trace_record;

/// How long to wait for the node to say something about a malformed stream.
///
/// A node that has said nothing by now has not rejected it — that is the
/// `TimedOut` outcome, and it is a finding rather than a harness failure, so
/// the wait has to be long enough that a slow-but-correct node is not
/// reported as hung. Five seconds is many times the node's observed reply
/// latency on every other protocol.
const VERDICT_TIMEOUT: Duration = Duration::from_secs(5);

/// A CE kind the NP does not assign.
///
/// CE kinds run from 128 upward and `aa0e2b8` defines 128, 129, 131..=148.
/// **130 is the gap** — it sits inside the assigned range and is not
/// defined, which makes it the more interesting of the two: a node that
/// range-checks rather than matching exactly would accept it.
pub const UNASSIGNED_IN_RANGE: u8 = 130;

/// A CE kind far outside anything assigned, for the node that range-checks.
pub const UNASSIGNED_OUT_OF_RANGE: u8 = 200;

// The in-range probe only poses its fault if it really is in range: a kind
// above CE 148 is refused by a bounds check and never reaches the "is this
// one defined?" question. Compile-time, so moving the constant out of the
// span breaks the build rather than one test.
const _: () = assert!(
    UNASSIGNED_IN_RANGE > jamnp_s::framing::CE128 && UNASSIGNED_IN_RANGE < jamnp_s::framing::CE148,
    "the in-range probe must sit inside the assigned CE span"
);

fn wall_ms() -> u64 {
    clock::current().wall_ms()
}

/// Open a stream, send `bytes` verbatim, and record what the node did with
/// it.
///
/// `bytes` is written raw and is not required to be a well-formed frame;
/// that is the point of the module.
async fn provoke(
    connection: &Conn,
    peer: u16,
    kind: u8,
    bytes: &[u8],
    finish: bool,
    trace: &Mutex<Trace>,
) -> StreamOutcome {
    provoke_waiting(
        connection,
        peer,
        kind,
        bytes,
        finish,
        VERDICT_TIMEOUT,
        trace,
    )
    .await
}

/// As [`provoke`], with the wait for the node's verdict given explicitly.
///
/// Slow-loris needs a wait longer than every other fault here, because the
/// fault *is* the wait: the question is whether the node reclaims a stream
/// nobody is feeding, and asking for five seconds would report every node
/// with a sane-but-slower timeout as holding it forever.
#[allow(clippy::too_many_arguments)]
async fn provoke_waiting(
    connection: &Conn,
    peer: u16,
    kind: u8,
    bytes: &[u8],
    finish: bool,
    wait: Duration,
    trace: &Mutex<Trace>,
) -> StreamOutcome {
    let opened = connection.open_bi().await;
    let (mut send, mut recv) = match opened {
        Ok(halves) => halves,
        Err(_) => {
            // The connection is already gone; say so from the connection
            // rather than calling it a stream outcome.
            return match connection.end_reason() {
                Some(ConnectionEnd::PeerClosed { code, reason }) => {
                    StreamOutcome::ConnectionClosed { code, reason }
                }
                _ => StreamOutcome::TimedOut { after_ms: 0 },
            };
        }
    };
    let stream_id = send.id();
    trace_record(peer, kind, stream_id, bytes, trace, TraceDir::Rx);
    if send.write_all(bytes).await.is_err() {
        return connection_verdict(connection, 0);
    }
    if finish {
        send.finish();
    }

    let started = clock::current().mono_ms();
    let mut buf = [0u8; 8192];
    let mut answered = 0usize;
    let verdict = tokio::time::timeout(wait, async {
        loop {
            match recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    trace_record(peer, kind, stream_id, &buf[..n], trace, TraceDir::Tx);
                    answered += n;
                }
                // The stream ended. That is a clean finish only if the
                // connection under it is still up: closing a connection
                // takes its streams with it, and the carriers disagree on
                // how that surfaces here -- QUIC errors the read, the mock
                // ends it cleanly (`findings.md` §8). Asking the connection
                // gives one answer on both.
                Ok(None) => {
                    if let Some(ConnectionEnd::PeerClosed { code, reason }) =
                        connection.end_reason()
                    {
                        return StreamOutcome::ConnectionClosed { code, reason };
                    }
                    return if answered > 0 {
                        StreamOutcome::Answered { bytes: answered }
                    } else {
                        StreamOutcome::FinishedSilently
                    };
                }
                Err(ReadError::Reset(_)) => return StreamOutcome::Reset,
                // The stream died under us. Ask the connection why, because
                // a reset and a close surface identically here on some
                // carriers and are different verdicts.
                Err(_) => {
                    return connection_verdict(
                        connection,
                        clock::current().mono_ms().saturating_sub(started),
                    )
                }
            }
        }
    })
    .await;

    match verdict {
        Ok(outcome) => outcome,
        Err(_) => {
            // Timed out waiting. The connection may still have gone away
            // quietly, so ask it before calling this a hang.
            match connection.end_reason() {
                Some(ConnectionEnd::PeerClosed { code, reason }) => {
                    StreamOutcome::ConnectionClosed { code, reason }
                }
                _ => StreamOutcome::TimedOut {
                    after_ms: wait.as_millis() as u64,
                },
            }
        }
    }
}

/// What the connection says happened, for a read that failed without being a
/// stream reset.
fn connection_verdict(connection: &Conn, after_ms: u64) -> StreamOutcome {
    match connection.end_reason() {
        Some(ConnectionEnd::PeerClosed { code, reason }) => {
            StreamOutcome::ConnectionClosed { code, reason }
        }
        // The connection is still up and the stream merely failed: that is
        // the node disposing of the stream, which is what a reset is.
        None => StreamOutcome::Reset,
        // Our own teardown, a timeout, or a transport error. Not a verdict.
        Some(_) => StreamOutcome::TimedOut { after_ms },
    }
}

/// Open a stream whose kind byte names a protocol that does not exist.
///
/// The kind byte is the whole message: `simple.md:122-124` says the initiator
/// sends one byte identifying the kind and "the identified protocol becomes
/// active immediately after this byte is sent", so there is nothing further
/// to send on a protocol nobody defines.
pub async fn unknown_kind(
    connection: &Conn,
    peer: u16,
    kind: u8,
    trace: &Mutex<Trace>,
) -> Provocation {
    let at_wall_ms = wall_ms();
    let outcome = provoke(connection, peer, kind, &[kind], true, trace).await;
    Provocation {
        peer,
        fault: Fault::UnknownKind(kind),
        outcome,
        connection_reusable: None,
        at_wall_ms,
    }
}

/// Send a message whose length prefix promises more than follows it.
///
/// `simple.md:128-131`: a message is a little-endian u32 length and then that
/// many bytes. This sends the length, fewer bytes than it claims, and a clean
/// FIN — so the node reaches end-of-stream mid-message.
pub async fn truncated_message(
    connection: &Conn,
    peer: u16,
    kind: u8,
    claimed: u32,
    sent: u32,
    trace: &Mutex<Trace>,
) -> Provocation {
    let at_wall_ms = wall_ms();
    let mut bytes = vec![kind];
    bytes.extend_from_slice(&claimed.to_le_bytes());
    bytes.extend(std::iter::repeat_n(0xA5u8, sent as usize));
    let outcome = provoke(connection, peer, kind, &bytes, true, trace).await;
    Provocation {
        peer,
        fault: Fault::TruncatedMessage {
            kind,
            claimed,
            sent,
        },
        outcome,
        connection_reusable: None,
        at_wall_ms,
    }
}

/// Send a complete, well-formed message and then junk.
///
/// The message itself is valid, so a node that rejects this is rejecting the
/// trailing bytes rather than the request — which is the distinction the row
/// cares about, and the reason the payload is a real encoded request rather
/// than filler.
pub async fn trailing_bytes(
    connection: &Conn,
    peer: u16,
    kind: u8,
    payload: &[u8],
    extra: usize,
    trace: &Mutex<Trace>,
) -> Provocation {
    let at_wall_ms = wall_ms();
    let mut bytes = frame(kind, payload);
    bytes.extend(std::iter::repeat_n(0x5Au8, extra));
    let outcome = provoke(connection, peer, kind, &bytes, true, trace).await;
    Provocation {
        peer,
        fault: Fault::TrailingBytes { kind, extra },
        outcome,
        connection_reusable: None,
        at_wall_ms,
    }
}

/// Open a stream, name a real protocol, and then say nothing at all.
///
/// The kind byte puts the protocol in force (`simple.md:122-124`), so the
/// node is left waiting for a message that never arrives, on a stream that
/// is never finished. A node that waits forever holds the stream — and
/// whatever it allocated for it — for as long as the peer keeps the
/// connection open, and one peer can open many.
///
/// **A real kind, deliberately.** Using an unassigned one would let the
/// node reject on the kind byte alone and never reach the waiting, which is
/// the thing being measured.
///
/// The verdict is whatever the node does within `silence`: a reset or a
/// finish means it reclaimed the stream, and nothing at all means it did
/// not. DESIGN §11 N7 marks this soft, and so does the row — the NP sets no
/// timeout for an idle stream, so "it waited longer than we did" is a
/// report, not a violation.
pub async fn slow_loris(
    connection: &Conn,
    peer: u16,
    kind: u8,
    silence: Duration,
    trace: &Mutex<Trace>,
) -> Provocation {
    let at_wall_ms = wall_ms();
    // The kind byte and nothing else, and the stream is never finished:
    // finishing it would tell the node no message is coming, which is the
    // opposite of what a slow-loris does.
    let outcome = provoke_waiting(connection, peer, kind, &[kind], false, silence, trace).await;
    Provocation {
        peer,
        fault: Fault::SlowLoris {
            kind,
            silence_ms: silence.as_millis() as u64,
        },
        outcome,
        connection_reusable: None,
        at_wall_ms,
    }
}

/// Open streams as fast as a target rate allows, and count what got open.
///
/// **A stream flood, not a message flood.** Each stream carries its kind
/// byte and is finished immediately: no message follows. That is deliberate.
/// A flood of *invalid* CE 141 messages would be refused on the first one
/// and, against a node that answers a refusal by closing the connection
/// (`findings.md` §30), the flood would end before it started — measuring
/// that finding over again instead of this one. The kind byte alone is what
/// DESIGN §11 N7 asks for ("500 CE 141 streams per second"), and it puts the
/// load where the row is aiming: stream setup and teardown.
///
/// Returns the number of streams successfully opened, which is normally well
/// under `rate * seconds`. QUIC bounds concurrent streams per connection, so
/// the carrier pushes back before the node has to — that backpressure is the
/// transport working, not the node failing, and the count is reported rather
/// than graded.
pub async fn flood_streams(
    connection: &Conn,
    peer: u16,
    kind: u8,
    rate_per_sec: u32,
    duration: Duration,
    trace: &Mutex<Trace>,
) -> u32 {
    let started = clock::current().mono_ms();
    let deadline_ms = started + duration.as_millis() as u64;
    let mut opened = 0u32;
    // Trace one stream. At this rate a per-stream record would bury every
    // other protocol in the run's trace, and they are all identical.
    trace_record(peer, kind, 0, &[kind], trace, TraceDir::Rx);

    // Opened in concurrent batches, not one at a time. Each open is a round
    // trip, so a sequential loop is paced by latency rather than by the
    // target: the first version of this reached 228/s against a target of
    // 500 and was quietly testing half of what it claimed. A batch per tick
    // puts the rate back under the caller's control, and what the carrier
    // will not grant still shows up in the returned count.
    let per_tick = (rate_per_sec as usize).div_ceil(TICKS_PER_SEC);
    let tick = Duration::from_millis(1000 / TICKS_PER_SEC as u64);

    while clock::current().mono_ms() < deadline_ms {
        let opens = (0..per_tick).map(|_| async {
            let (mut send, _recv) = connection.open_bi().await.ok()?;
            send.write_all(&[kind]).await.ok()?;
            send.finish();
            Some(())
        });
        let landed = futures::future::join_all(opens).await;
        let got = landed.iter().filter(|r| r.is_some()).count() as u32;
        opened += got;
        // Nothing at all got open: the connection is gone, which is the
        // node dropping the flooder and a legitimate answer. Stop rather
        // than spin for the rest of the window.
        if got == 0 {
            break;
        }
        tokio::time::sleep(tick).await;
    }
    opened
}

/// How many batches a second [`flood_streams`] opens.
///
/// Ten: fine enough that a batch is a small fraction of the target rate,
/// coarse enough that the pacing sleep is not the dominant cost.
const TICKS_PER_SEC: usize = 10;

/// Does an ordinary request get an **answer** on this connection?
///
/// Stricter than [`connection_still_serves`], and the two measure different
/// failures. That one asks whether the connection survived, which is the
/// right question after a provocation the node may answer by closing it.
/// This one asks whether bytes came back, which is the right question under
/// load: a node that stops answering while leaving every connection open is
/// exactly the flood defect, and a liveness check that only watched the
/// connection would call it healthy.
pub async fn connection_answers(
    connection: &Conn,
    peer: u16,
    from: [u8; 32],
    trace: &Mutex<Trace>,
) -> bool {
    use jam_types::{Encode, HeaderHash};
    use jamnp_s::codec::ce128_129::{BlockRequest, Direction};
    use jamnp_s::framing::CE128;

    if connection.end_reason().is_some() {
        return false;
    }
    let request = BlockRequest {
        header_hash: HeaderHash::from(from),
        direction: Direction::AscendingExclusive,
        max_blocks: 1,
    };
    let Ok((mut send, mut recv)) = connection.open_bi().await else {
        return false;
    };
    let stream_id = send.id();
    let wire = frame(CE128, &request.encode());
    trace_record(peer, CE128, stream_id, &wire, trace, TraceDir::Rx);
    if send.write_all(&wire).await.is_err() {
        return false;
    }
    send.finish();

    let mut buf = [0u8; 4096];
    let mut answered = 0usize;
    let _ = tokio::time::timeout(VERDICT_TIMEOUT, async {
        loop {
            match recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    trace_record(peer, CE128, stream_id, &buf[..n], trace, TraceDir::Tx);
                    answered += n;
                }
                _ => return,
            }
        }
    })
    .await;
    answered > 0
}

/// Does an ordinary request still get through on this connection?
///
/// A valid CE 128 ascending walk from genesis: every node holds genesis, so
/// a conforming one answers. What is being measured is not the answer's
/// contents — N0 grades those — but whether the connection still carries a
/// protocol at all after the provocation.
///
/// The verdict is read from the *connection*, not from the reply. A node may
/// legitimately answer with no blocks, reset the stream, or finish silently,
/// and none of those means the connection is unusable. Only the connection
/// having ended does.
pub async fn connection_still_serves(
    connection: &Conn,
    peer: u16,
    from: [u8; 32],
    trace: &Mutex<Trace>,
) -> bool {
    use jam_types::{Encode, HeaderHash};
    use jamnp_s::codec::ce128_129::{BlockRequest, Direction};
    use jamnp_s::framing::CE128;

    // Already gone: no need to ask.
    if connection.end_reason().is_some() {
        return false;
    }
    let request = BlockRequest {
        header_hash: HeaderHash::from(from),
        direction: Direction::AscendingExclusive,
        max_blocks: 1,
    };
    let Ok((mut send, mut recv)) = connection.open_bi().await else {
        return false;
    };
    let stream_id = send.id();
    let wire = frame(CE128, &request.encode());
    trace_record(peer, CE128, stream_id, &wire, trace, TraceDir::Rx);
    if send.write_all(&wire).await.is_err() {
        return false;
    }
    send.finish();

    let mut buf = [0u8; 4096];
    let _ = tokio::time::timeout(VERDICT_TIMEOUT, async {
        loop {
            match recv.read(&mut buf).await {
                Ok(Some(n)) => trace_record(peer, CE128, stream_id, &buf[..n], trace, TraceDir::Tx),
                _ => return,
            }
        }
    })
    .await;
    // Whatever became of that stream, the question is whether the
    // connection outlived it.
    connection.end_reason().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kind byte we call "unassigned in range" must really be
    /// unassigned, or the provocation is testing a protocol that exists and
    /// the row means nothing.
    ///
    /// Checked against `jamnp-s`'s own constants rather than against a list
    /// written here, so that defining CE 130 upstream breaks this test
    /// instead of silently turning the provocation into a valid request.
    #[test]
    fn the_unassigned_kinds_are_really_unassigned() {
        use jamnp_s::framing::*;
        let assigned = [
            UP, CE128, CE129, CE131, CE132, CE133, CE134, CE135, CE136, CE137, CE138, CE139, CE140,
            CE141, CE142, CE143, CE144, CE145, CE146, CE147, CE148,
        ];
        assert!(
            !assigned.contains(&UNASSIGNED_IN_RANGE),
            "CE {UNASSIGNED_IN_RANGE} is assigned; pick another gap"
        );
        assert!(
            !assigned.contains(&UNASSIGNED_OUT_OF_RANGE),
            "CE {UNASSIGNED_OUT_OF_RANGE} is assigned; pick another"
        );
        // That the in-range probe is genuinely in range is asserted at
        // compile time beside the constant itself.
    }

    /// A truncated message must really be short: if `sent >= claimed` the
    /// bytes are a valid message and the provocation is not one.
    #[test]
    fn a_truncated_message_is_shorter_than_it_claims() {
        let kind = 128u8;
        let (claimed, sent) = (4096u32, 8u32);
        let mut bytes = vec![kind];
        bytes.extend_from_slice(&claimed.to_le_bytes());
        bytes.extend(std::iter::repeat_n(0xA5u8, sent as usize));
        assert_eq!(bytes.len(), 1 + 4 + sent as usize);
        let prefix = u32::from_le_bytes(bytes[1..5].try_into().unwrap());
        assert_eq!(prefix, claimed);
        assert!(
            (bytes.len() - 5) < prefix as usize,
            "the body must be shorter than the prefix claims"
        );
    }

    /// Trailing junk must sit after a frame that is itself complete, or the
    /// row grades a malformed message rather than a well-formed one with
    /// junk after it.
    #[test]
    fn trailing_bytes_follow_a_complete_frame() {
        let payload = [1u8, 2, 3, 4];
        let framed = frame(128, &payload);
        let mut bytes = framed.clone();
        bytes.extend(std::iter::repeat_n(0x5Au8, 16));
        assert_eq!(&bytes[..framed.len()], &framed[..]);
        let prefix = u32::from_le_bytes(bytes[1..5].try_into().unwrap());
        assert_eq!(
            prefix as usize,
            payload.len(),
            "the leading frame must be exactly the payload"
        );
        assert_eq!(bytes.len(), framed.len() + 16);
    }
}
