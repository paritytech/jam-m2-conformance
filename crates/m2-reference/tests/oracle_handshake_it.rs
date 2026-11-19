//! Does the handshake refuse an oracle it must not trust?
//!
//! Two guards ride the handshake, and until this test neither had been seen
//! to fire over a socket. The protocol version has refused a mismatch since
//! it existed; the codec probe is new, and exists because the harness and
//! the oracle are separate cargo trees with separate lockfiles that both ask
//! for `jam-codec` by a caret requirement -- and have already resolved
//! differently once, silently (`findings.md` §7).
//!
//! The stand-in answers the way a **real** divergence answers. `jam-codec`
//! 0.1.1 takes a compact integer written in more bytes than it needs and
//! 0.1.2 refuses it, so the lax probe here is 0.1.1's measured behaviour
//! rather than an invented one: `[true, true, true, true, false]` against
//! this build's `[true, false, false, false, false]`. A harness holding the
//! lax codec is laxer than the node it grades, which is a missed detection
//! on every length prefix on the wire.

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;

use m2_oracle_proto::{frame, read_frame, CodecProbe, Message, PeerInfo, PROTOCOL_VERSION};
use m2_reference::oracle::Oracle;

/// Serve exactly one handshake on `socket`, answering with `info`.
///
/// One connection and one message: the client refuses during `connect`, so
/// anything after the handshake would never be read.
fn stand_in(socket: PathBuf, info: PeerInfo) -> std::thread::JoinHandle<()> {
    let listener = UnixListener::bind(&socket).expect("the stand-in binds");
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let Ok(read) = stream.read(&mut chunk) else {
                return;
            };
            if read == 0 {
                return;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if read_frame(&buffer).is_ok() {
                break;
            }
        }
        let _ = stream.write_all(&frame(&Message::PeerInfo(info)));
        let _ = stream.flush();
        // Held open until the client has read the reply and dropped its end.
        let _ = stream.read(&mut chunk);
    })
}

/// Serve one handshake answering with bytes chosen by the caller, for
/// replies this build cannot construct through its own types.
fn raw_stand_in(socket: PathBuf, reply: Vec<u8>) -> std::thread::JoinHandle<()> {
    let listener = UnixListener::bind(&socket).expect("the stand-in binds");
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut chunk = [0u8; 4096];
        let _ = stream.read(&mut chunk);
        let _ = stream.write_all(&reply);
        let _ = stream.flush();
        let _ = stream.read(&mut chunk);
    })
}

fn socket_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("m2-handshake-{}-{name}.sock", std::process::id()))
}

/// 0.1.1's answer to [`m2_oracle_proto::PROBE_CANARIES`], measured against
/// the published crate: it takes all three non-canonical inputs.
fn lax_codec_probe() -> CodecProbe {
    CodecProbe {
        encodings: m2_oracle_proto::codec_probe().encodings,
        decodes: vec![true, true, true, true, false],
    }
}

#[test]
fn an_oracle_whose_codec_is_laxer_is_refused_with_the_input_it_took() {
    let socket = socket_path("lax");
    let _ = std::fs::remove_file(&socket);
    let served = stand_in(
        socket.clone(),
        PeerInfo {
            protocol_version: PROTOCOL_VERSION,
            polkajam_revision: "d92cadd30".into(),
            name: "stand-in".into(),
            codec: lax_codec_probe(),
        },
    );

    let said = match Oracle::connect(&socket) {
        Err(refused) => refused.to_string(),
        Ok(_) => panic!("a laxer codec must be refused"),
    };
    assert!(
        said.contains("8000"),
        "the refusal names the input the two sides answer differently: {said}"
    );
    assert!(
        said.contains("jam-codec"),
        "and what to do about it: {said}"
    );

    let _ = served.join();
    let _ = std::fs::remove_file(&socket);
}

/// The control. An oracle built from the same codec is not refused, so the
/// guard is not simply refusing everything -- which is the failure mode a
/// test that only drove the bad case could not tell apart.
#[test]
fn an_oracle_whose_codec_agrees_is_accepted() {
    let socket = socket_path("agreeing");
    let _ = std::fs::remove_file(&socket);
    let served = stand_in(
        socket.clone(),
        PeerInfo {
            protocol_version: PROTOCOL_VERSION,
            polkajam_revision: "d92cadd30".into(),
            name: "stand-in".into(),
            codec: m2_oracle_proto::codec_probe(),
        },
    );

    let oracle = Oracle::connect(&socket).expect("an agreeing codec is accepted");
    assert_eq!(oracle.revision(), "d92cadd30");

    drop(oracle);
    let _ = served.join();
    let _ = std::fs::remove_file(&socket);
}

/// An oracle built before the probe existed does not send one, so its
/// handshake will not decode as this one -- the version check never gets to
/// run, and what comes back is a framing complaint. The message has to point
/// at the likely cause anyway, because the likely cause is a stale binary in
/// `third_party/bin` and the remedy is one command.
#[test]
fn an_oracle_from_before_the_probe_is_told_to_rebuild() {
    let socket = socket_path("legacy");
    let _ = std::fs::remove_file(&socket);
    // A protocol-8 `PeerInfo`, hand-encoded: tag, version, then the two
    // strings it used to end with.
    let mut body = vec![0u8];
    body.extend_from_slice(&8u16.to_le_bytes());
    for text in ["d92cadd30", "m2-oracle"] {
        body.push((text.len() as u8) << 2);
        body.extend_from_slice(text.as_bytes());
    }
    let mut wire = (body.len() as u32).to_le_bytes().to_vec();
    wire.extend_from_slice(&body);
    let served = raw_stand_in(socket.clone(), wire);

    let said = match Oracle::connect(&socket) {
        Err(refused) => refused.to_string(),
        Ok(_) => panic!("a handshake that will not decode must be refused"),
    };
    assert!(
        said.contains("prepare-nut.sh"),
        "the refusal says how to rebuild: {said}"
    );

    let _ = served.join();
    let _ = std::fs::remove_file(&socket);
}

/// The guard that was already there, now that something drives it: a
/// protocol mismatch is refused before any answer is trusted.
#[test]
fn an_oracle_speaking_another_protocol_is_refused() {
    let socket = socket_path("protocol");
    let _ = std::fs::remove_file(&socket);
    let served = stand_in(
        socket.clone(),
        PeerInfo {
            protocol_version: PROTOCOL_VERSION + 1,
            polkajam_revision: "d92cadd30".into(),
            name: "stand-in".into(),
            codec: m2_oracle_proto::codec_probe(),
        },
    );

    let said = match Oracle::connect(&socket) {
        Err(refused) => refused.to_string(),
        Ok(_) => panic!("a protocol mismatch must be refused"),
    };
    assert!(
        said.contains(&(PROTOCOL_VERSION + 1).to_string()),
        "the refusal names the version the oracle speaks: {said}"
    );

    let _ = served.join();
    let _ = std::fs::remove_file(&socket);
}
