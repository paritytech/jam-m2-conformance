//! The connection to the out-of-process reference engine.
//!
//! Everything this crate knows about polkajam's engine arrives through one
//! unix socket. The oracle on the other end is built from the same polkajam
//! revision as the node under test, which is what makes its answers a
//! standard to grade that node by; it states the revision in its handshake
//! and [`Oracle::connect`] refuses a mismatch.
//!
//! **One connection, several sessions.** The oracle serves connections
//! serially -- it holds the engine, which is where a run's determinism comes
//! from, and nothing is gained by racing it. A run needs two chains at once
//! (the harness's own and the view it hands the node), so the two share this
//! connection and tell themselves apart by session id. Opening a second
//! connection would not give a second engine; it would block until the first
//! one closed.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use m2_oracle_proto::{frame, read_frame, Message, PeerInfo, SessionId, PROTOCOL_VERSION};

use crate::chain::ChainError;

/// Environment variable naming the oracle binary.
///
/// Set by anything that builds it somewhere other than the default.
pub const ORACLE_BIN_ENV: &str = "M2_ORACLE_BIN";

/// Where `scripts/prepare-nut.sh` leaves it, relative to the repository root.
const DEFAULT_ORACLE_BIN: &str = "third_party/bin/m2-oracle";

/// A connection to a running oracle, and the process when we started it.
pub struct Oracle {
    conn: Mutex<Connection>,
    /// The oracle this handle started, killed when the handle drops.
    ///
    /// `None` when the handle connected to one somebody else owns.
    owned: Mutex<Option<Owned>>,
    socket: PathBuf,
    /// The polkajam revision the oracle reports, for a run to record.
    revision: String,
    /// How many requests have gone over this connection, and how long they
    /// took in total.
    ///
    /// Moving the engine out of process put a round trip on the slot-critical
    /// path, and the only question that matters is whether tickets still
    /// reach the node inside the submission window. Counting is how that
    /// stops being a guess.
    requests: AtomicU64,
    request_nanos: AtomicU64,
}

/// An oracle process this handle started.
struct Owned {
    child: Child,
    /// The oracle's stdin. Dropping it, or dying without dropping it, closes
    /// the pipe and the oracle exits -- which is what covers the case where
    /// the handle itself is never dropped.
    leash: Option<std::process::ChildStdin>,
}

struct Connection {
    stream: std::os::unix::net::UnixStream,
    /// Bytes read past the end of the last frame.
    ///
    /// A reply can arrive in pieces and two replies can arrive in one read,
    /// so what is left over after a frame belongs to the next one. Dropping
    /// it desynchronises the stream, which shows up much later as a reply
    /// that will not decode.
    buffered: Vec<u8>,
}

impl Oracle {
    /// Connect to an oracle already listening on `socket`.
    pub fn connect(socket: &Path) -> Result<Arc<Self>, ChainError> {
        Self::attach(socket, None)
    }

    /// Start an oracle of our own, listening on a socket under `dir`.
    ///
    /// The handle owns the process: dropping it kills the oracle and removes
    /// the socket. A run that wants the oracle to outlive one handle should
    /// start it itself and use [`Oracle::connect`].
    pub fn spawn(dir: &Path) -> Result<Arc<Self>, ChainError> {
        let binary = oracle_binary()?;
        std::fs::create_dir_all(dir)
            .map_err(|e| ChainError::Oracle(format!("creating {}: {e}", dir.display())))?;
        let socket = dir.join(format!("oracle-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&socket);

        // The oracle exits when this pipe closes, which is the only thing
        // that still happens when the handle below is never dropped -- a
        // shared test handle lives until the process exits, and a runner
        // that is killed never cleans up either. The write end is held in
        // the handle for as long as this process lives.
        let mut child = std::process::Command::new(&binary)
            .arg("--exit-on-stdin-eof")
            .arg(&socket)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| ChainError::Oracle(format!("starting {}: {e}", binary.display())))?;
        let leash = child.stdin.take();

        // Binding is the first thing it does, but starting a process and
        // connecting to it is still a race.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while std::time::Instant::now() < deadline {
            if std::os::unix::net::UnixStream::connect(&socket).is_ok() {
                return Self::attach(&socket, Some(Owned { child, leash }));
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let mut child = child;
        let _ = child.kill();
        Err(ChainError::Oracle(format!(
            "the oracle never bound {}",
            socket.display()
        )))
    }

    /// One oracle for every test in this process.
    ///
    /// Tests want a chain, not a process tree. The oracle is serial, so one
    /// of them serves a whole test binary; each `RefChain` gets a session of
    /// its own and they do not see each other. The handle is leaked on
    /// purpose -- it lives until the process exits, which is when the oracle
    /// should go too.
    ///
    /// Panics with the build step if the binary is not there. A test that
    /// quietly skipped instead would be a test that passes on a machine
    /// where nothing was checked.
    pub fn for_tests() -> Arc<Self> {
        static SHARED: OnceLock<Arc<Oracle>> = OnceLock::new();
        SHARED
            .get_or_init(|| {
                let dir = std::env::temp_dir().join(format!("m2-oracle-{}", std::process::id()));
                Oracle::spawn(&dir).unwrap_or_else(|e| panic!("{e}"))
            })
            .clone()
    }

    fn attach(socket: &Path, owned: Option<Owned>) -> Result<Arc<Self>, ChainError> {
        let stream = std::os::unix::net::UnixStream::connect(socket)
            .map_err(|e| ChainError::Oracle(format!("connecting to {}: {e}", socket.display())))?;
        let oracle = Arc::new(Self {
            conn: Mutex::new(Connection {
                stream,
                buffered: Vec::new(),
            }),
            owned: Mutex::new(owned),
            socket: socket.to_path_buf(),
            revision: String::new(),
            requests: AtomicU64::new(0),
            request_nanos: AtomicU64::new(0),
        });

        let reply = oracle.request(Message::PeerInfo(PeerInfo {
            protocol_version: PROTOCOL_VERSION,
            polkajam_revision: String::new(),
            name: "m2-reference".to_string(),
        }))?;
        let info = match reply {
            Message::PeerInfo(info) => info,
            other => {
                return Err(ChainError::Oracle(format!(
                    "the handshake answered {other:?}"
                )))
            }
        };
        if info.protocol_version != PROTOCOL_VERSION {
            return Err(ChainError::Oracle(format!(
                "the oracle speaks protocol {} and this build speaks {PROTOCOL_VERSION}. \
                 Rebuild both from one checkout.",
                info.protocol_version
            )));
        }

        // `Arc::get_mut` rather than a cell: this is the only reference, the
        // handshake has just finished, and the revision never changes after.
        let mut oracle = oracle;
        Arc::get_mut(&mut oracle)
            .expect("the handle has not been shared yet")
            .revision = info.polkajam_revision;
        Ok(oracle)
    }

    /// The polkajam revision the oracle was built from.
    pub fn revision(&self) -> &str {
        &self.revision
    }

    /// The socket this handle speaks over.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Requests sent over this connection, and the time they took.
    ///
    /// The handshake is counted with the rest: it is a round trip like any
    /// other, and leaving it out would flatter the mean by one.
    pub fn traffic(&self) -> (u64, std::time::Duration) {
        (
            self.requests.load(Ordering::Relaxed),
            std::time::Duration::from_nanos(self.request_nanos.load(Ordering::Relaxed)),
        )
    }

    /// Send one request and read its reply.
    ///
    /// An `Error` from the oracle is the engine refusing something, which is
    /// an answer; an `OracleFault` is the oracle itself being wrong, which is
    /// not. They are kept apart so that a lane cannot read a broken oracle as
    /// a node that misbehaved.
    pub fn request(&self, request: Message) -> Result<Message, ChainError> {
        let started = std::time::Instant::now();
        let answer = self.request_inner(request);
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.request_nanos.fetch_add(
            started.elapsed().as_nanos().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
        answer
    }

    fn request_inner(&self, request: Message) -> Result<Message, ChainError> {
        let mut conn = self
            .conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        conn.stream
            .write_all(&frame(&request))
            .map_err(|e| ChainError::Oracle(format!("sending to the oracle: {e}")))?;

        let mut chunk = [0u8; 64 * 1024];
        loop {
            match read_frame(&conn.buffered) {
                Ok((reply, rest)) => {
                    // `read_frame` hands back what it did not consume, and
                    // that tail belongs to the next reply.
                    let used = conn.buffered.len() - rest.len();
                    conn.buffered.drain(..used);
                    return match reply {
                        Message::OracleFault(why) => Err(ChainError::Oracle(why)),
                        other => Ok(other),
                    };
                }
                Err(m2_oracle_proto::FrameError::Short) => {}
                Err(e) => {
                    return Err(ChainError::Oracle(format!(
                        "the oracle's reply did not decode: {e}"
                    )))
                }
            }
            let read = conn
                .stream
                .read(&mut chunk)
                .map_err(|e| ChainError::Oracle(format!("reading from the oracle: {e}")))?;
            if read == 0 {
                return Err(ChainError::Oracle(
                    "the oracle closed the connection".to_string(),
                ));
            }
            conn.buffered.extend_from_slice(&chunk[..read]);
        }
    }

    /// Send a request, and refuse anything but the expected answer.
    pub fn expect(&self, request: Message) -> Result<Message, ChainError> {
        match self.request(request)? {
            // The engine refused: an answer, and the caller's error to map.
            Message::Error(why) => Err(ChainError::Chain(why)),
            other => Ok(other),
        }
    }

    /// Open a session over `spec_path`, holding the given validators.
    ///
    /// An empty path opens the default dev spec, which is what this crate's
    /// own tests run on.
    pub fn open(
        self: &Arc<Self>,
        spec_path: &str,
        holds: Vec<u16>,
    ) -> Result<(SessionId, [u8; 32], u32), ChainError> {
        match self.expect(Message::Open {
            spec_path: spec_path.to_string(),
            holds,
            // This process's clock, which under a simulation is the
            // installed virtual one. The oracle has no way to know it.
            now_slot: crate::chain::wall_clock_slot(),
        })? {
            Message::Opened {
                session,
                genesis_hash,
                genesis_slot,
            } => Ok((session, genesis_hash, genesis_slot)),
            other => Err(ChainError::Oracle(format!("Open answered {other:?}"))),
        }
    }
}

impl Drop for Oracle {
    fn drop(&mut self) {
        let mut owned = self
            .owned
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(owned) = owned.as_mut() {
            // The pipe first: closing it is what an oracle outliving a
            // handle that never drops would have seen anyway, so the two
            // paths end the same way.
            owned.leash.take();
            let _ = owned.child.kill();
            let _ = owned.child.wait();
            let _ = std::fs::remove_file(&self.socket);
        }
    }
}

/// Where the oracle binary is.
///
/// `M2_ORACLE_BIN` wins; otherwise `third_party/bin/m2-oracle` under the
/// repository root, which is where `scripts/prepare-nut.sh` puts it.
fn oracle_binary() -> Result<PathBuf, ChainError> {
    if let Some(named) = std::env::var_os(ORACLE_BIN_ENV) {
        let path = PathBuf::from(named);
        if !path.exists() {
            return Err(ChainError::Oracle(format!(
                "{ORACLE_BIN_ENV} names {}, which does not exist",
                path.display()
            )));
        }
        return Ok(path);
    }
    // `CARGO_MANIFEST_DIR` is this crate; the root is two levels up. Not the
    // working directory, which a test does not control.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let path = root.join(DEFAULT_ORACLE_BIN);
    if !path.exists() {
        return Err(ChainError::Oracle(format!(
            "no oracle binary at {}. It is built outside this workspace, \
             from the same polkajam revision as the node under test:\n\
             \n    ./scripts/prepare-nut.sh\n\n\
             or point {ORACLE_BIN_ENV} at one.",
            path.display()
        )));
    }
    Ok(path)
}
