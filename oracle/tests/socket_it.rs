//! A session over a real socket, which is Phase 2's exit criterion.
//!
//! The handler tests prove the answers; this proves the wire — binding,
//! framing, back-to-back requests on one connection, and the process
//! surviving a client that goes away.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use m2_oracle_proto::{frame, read_frame, Message, PeerInfo, PROTOCOL_VERSION};

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
