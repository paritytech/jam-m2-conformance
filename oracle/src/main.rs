//! The out-of-process polkajam reference oracle.
//!
//! The conformance harness used to compile polkajam's node crate in-process
//! to use as its oracle, behind the `hazmat` feature whose own docs say its
//! interfaces may change at any time. This binary is that dependency, moved
//! behind a unix socket: the harness speaks `m2-oracle-proto` to it and
//! depends only on polkajam's published crates.
//!
//! Single-threaded and serial on purpose. The harness's callers already see
//! serial semantics — `RefChain` wraps its harness in a mutex — and the
//! engine holds the only RNG, so a run stays seed-deterministic across the
//! boundary.

mod handle;
mod session;

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};

use m2_oracle_proto::{frame, read_frame, Message};

use session::Sessions;

/// Wall-clock slot, the way the reference chain computes it.
///
/// The harness is virtual-time: a session opened without this authors from
/// genesis, millions of slots behind the node it is meant to shadow.
pub fn wall_clock_slot() -> u32 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_secs();
    ((now - jam_types::JAM_COMMON_ERA) / 6) as u32
}

fn main() {
    let path = match std::env::args().nth(1) {
        // The revision this binary was built from, on stdout and nothing
        // else, so a build script can compare it with the pin. Checking it
        // there costs a process start; discovering a mismatch from a
        // handshake costs whatever the run had done by then.
        Some(flag) if flag == "--revision" => {
            println!("{}", handle::POLKAJAM_REVISION);
            return;
        }
        Some(path) => path,
        None => {
            eprintln!("usage: m2-oracle <socket-path>");
            eprintln!("       m2-oracle --revision");
            std::process::exit(2);
        }
    };
    // A stale socket from a killed run would otherwise make every later run
    // fail to bind, which reads as the oracle being broken.
    let _ = std::fs::remove_file(&path);

    let listener = match UnixListener::bind(&path) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("m2-oracle: cannot bind {path}: {e}");
            std::process::exit(2);
        }
    };
    eprintln!(
        "m2-oracle: listening on {path}, polkajam {}",
        handle::POLKAJAM_REVISION
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => serve(stream),
            Err(e) => eprintln!("m2-oracle: accept failed: {e}"),
        }
    }
}

/// Serve one connection until the peer goes away.
///
/// Sessions live and die with the connection: a run owns the oracle process,
/// so a dropped connection means the run is over and the harnesses it held
/// are of no use to anyone.
fn serve(mut stream: UnixStream) {
    let mut sessions = Sessions::default();
    let mut buffered: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 64 * 1024];

    loop {
        // Answer everything already buffered before waiting on the socket.
        loop {
            match read_frame(&buffered) {
                Ok((request, rest)) => {
                    let consumed = buffered.len() - rest.len();
                    let reply = handle::answer(&mut sessions, request);
                    buffered.drain(..consumed);
                    if stream.write_all(&frame(&reply)).is_err() {
                        return;
                    }
                }
                // Not a whole frame yet: wait for more.
                Err(m2_oracle_proto::FrameError::Short) => break,
                // Malformed or oversized. Say so and keep the connection:
                // the harness can tell a bad frame from a dead oracle only
                // if the oracle survives to answer.
                Err(e) => {
                    let _ = stream.write_all(&frame(&Message::OracleFault(e.to_string())));
                    return;
                }
            }
        }

        match stream.read(&mut chunk) {
            Ok(0) => return,
            Ok(n) => buffered.extend_from_slice(&chunk[..n]),
            Err(e) => {
                eprintln!("m2-oracle: read failed: {e}");
                return;
            }
        }
    }
}
