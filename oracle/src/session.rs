//! Sessions: one `AuthoringHarness` each, over one genesis spec file.
//!
//! A run holds two chains at once — the harness's own and the view it hands
//! the node — so a single connection has to serve both without their slots
//! interleaving. Each gets a session, and every request names one.

use std::collections::HashMap;

use jam_node::hazmat::{AuthoringHarness, AuthoringHarnessConfig, SecretKeysets};
use jam_std_common::SecretKeyset;
use jam_types::FixedVec;
use m2_oracle_proto::SessionId;

/// Keyset index for a validator this session does *not* hold.
///
/// A real index would let the harness sign for a validator the run is
/// emulating elsewhere, which is how a harness ends up proving something the
/// node never did.
const NON_VALIDATOR_KEYSET: u32 = u32::MAX;

/// Everything one session owns.
pub struct Session {
    pub harness: AuthoringHarness,
    pub genesis_hash: [u8; 32],
    pub genesis_slot: u32,
}

#[derive(Default)]
pub struct Sessions {
    next: SessionId,
    open: HashMap<SessionId, Session>,
}

impl Sessions {
    /// Open a session over the spec at `spec_path`, holding `holds`.
    ///
    /// An empty `spec_path` opens the default dev spec under the tiny
    /// parameters, which is what the lane's own tests want.
    ///
    /// The spec comes from a file rather than over the wire: the runner
    /// writes one and both the oracle and the node under test load it, which
    /// is the only way to be sure they start from the same bytes. The reply
    /// carries the genesis hash so the runner can check that.
    pub fn open(&mut self, spec_path: &str, holds: &[u16]) -> Result<SessionId, String> {
        // Read the way the runner writes it. The runner emits `spec.json`
        // with `ChainSpec::to_file`, and the matching reader is
        // `load_from_file_and_apply_parameters` -- which decodes the file's
        // `protocol_parameters` and applies them process-wide *before*
        // decoding anything else, then rebuilds the genesis state from the
        // file's own `genesis_state` entries.
        //
        // Not `ChainSpecConfig::from_file` + `ChainSpec::from_config`: that
        // pair reads the other file -- a spec *config*, the recipe the
        // runner builds a spec from -- and `from_config` does not apply the
        // parameters, it checks them and fails when they disagree. The two
        // file shapes are both JSON and look alike enough to swap by
        // accident.
        //
        // `jam_node::ChainSpec`, not `jam_chainspec`'s: the node has its own
        // and `AuthoringHarness` takes that one. They look alike too.
        //
        // An empty path means the default dev spec, which is what the lane's
        // own tests run on. Its validator set is sized from the process-wide
        // parameters, so tiny has to be applied before it is built, not
        // after.
        let chain_spec = if spec_path.is_empty() {
            jam_types::ProtocolParameters::tiny()
                .apply()
                .map_err(|e| format!("applying the tiny parameters: {e}"))?;
            jam_node::hazmat::default_dev_spec()
        } else {
            jam_node::ChainSpec::load_from_file_and_apply_parameters(spec_path)
                .map_err(|e| format!("loading {spec_path}: {e}"))?
                .1
        };

        let genesis_hash = chain_spec.genesis_header.hash().0;
        let genesis_slot = chain_spec.genesis_header.slot;

        let held: Vec<u16> = holds.to_vec();
        let validators = SecretKeysets(FixedVec::from_fn(|i| {
            if held.contains(&(i as u16)) {
                SecretKeyset::trivial(i as u32)
            } else {
                SecretKeyset::trivial(NON_VALIDATOR_KEYSET)
            }
        }));

        let harness = AuthoringHarness::new(
            chain_spec,
            validators,
            AuthoringHarnessConfig {
                drop_exports: false,
                // The compiler backend needs a userfaultfd Linux sandbox;
                // the interpreter runs without one.
                pvm_backend: Some(jam_node::PvmBackend::Interpreter),
            },
        );

        let id = self.next;
        self.next = self.next.wrapping_add(1);
        self.open.insert(
            id,
            Session {
                harness,
                genesis_hash,
                genesis_slot,
            },
        );
        Ok(id)
    }

    pub fn get_mut(&mut self, id: SessionId) -> Result<&mut Session, String> {
        self.open
            .get_mut(&id)
            .ok_or_else(|| format!("no session {id}"))
    }

    pub fn close(&mut self, id: SessionId) {
        self.open.remove(&id);
    }

    /// The lowest open session id.
    ///
    /// The fuzz protocol's `ImportBlock` and `GetState` carry no session,
    /// and a run imports the node's blocks into exactly one chain, so those
    /// two act on the first session opened.
    pub fn first(&self) -> Option<SessionId> {
        self.open.keys().copied().min()
    }
}
