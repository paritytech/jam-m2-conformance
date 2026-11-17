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

/// Exit when stdin reaches EOF, in a thread of its own.
///
/// A client that owns this process cannot always kill it: a test binary's
/// shared handle lives until the process exits and so never drops, and a
/// runner that is itself killed never gets to clean up either. Both would
/// leave an oracle holding a socket, and the next run would find it there.
///
/// The parent passes a pipe as this process's stdin and holds the write end.
/// When the parent goes -- cleanly or not -- the pipe closes, the read below
/// returns 0, and this process goes with it.
///
/// Opt-in, because stdin is otherwise inherited: under `cargo test` it may
/// already be at EOF, and an oracle that exited the moment it started would
/// look exactly like one that failed to bind.
fn exit_when_stdin_closes() {
    std::thread::spawn(|| {
        let mut sink = [0u8; 256];
        loop {
            match std::io::stdin().read(&mut sink) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        std::process::exit(0);
    });
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut watch_stdin = false;
    let mut positional = Vec::new();
    for arg in args.by_ref() {
        match arg.as_str() {
            "--exit-on-stdin-eof" => watch_stdin = true,
            other => positional.push(other.to_string()),
        }
    }
    if watch_stdin {
        exit_when_stdin_closes();
    }
    let path = match positional.into_iter().next() {
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
            eprintln!("usage: m2-oracle [--exit-on-stdin-eof] <socket-path>");
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
