//! Work packages, reports and guarantees: the artefacts the N3 lane puts on
//! the wire.
//!
//! The same shape as [`crate::tickets`] -- one method per artefact a lane
//! needs, computed once here and handed over whole. The authoring harness
//! does the work; what this module adds is a surface that does not leak it,
//! so a lane cannot reach past the oracle into the engine.

use jam_types::CoreIndex;

use crate::chain::{ChainError, RefChain};

/// One pass of the guaranteeing path: the package as a builder would submit
/// it, the report it refines to, the bundle those shards are coded from, and
/// a guarantee signed by the validators that hold the core.
///
/// Kept together because the lane needs all four and they are one
/// computation: CE 133 carries the package, CE 134 the bundle, CE 135 the
/// guarantee, and the report is what a block must come to carry.
pub struct GuaranteedWork {
    pub package: jam_types::WorkPackage,
    pub report: jam_std_common::WorkReport,
    pub bundle: Vec<u8>,
    pub guarantee: jam_std_common::ReportGuarantee,
}

/// The GP work-package hash, as the engine computes it.
///
/// Not recomputed here. CE 134's mappings are keyed by this hash, so the lane
/// correlates what the node shared with what the harness submitted by it, and
/// a harness that hashed packages its own way would be comparing its
/// arithmetic against the node's rather than the node against the protocol.
pub fn package_hash(package: &jam_types::WorkPackage) -> jam_types::WorkPackageHash {
    jam_std_common::ImmutableWorkPackage::from(package).hash()
}

/// A CE 133 submission the harness will make, resolved down to wire values.
///
/// The package is carried encoded because that is what goes on the wire and
/// what the faults act on: an oversized initial message is a property of the
/// bytes, not of the structure.
#[derive(Debug, Clone)]
pub struct ScheduledSubmission {
    /// Slot to submit in; see [`RefChain::submission_slot_for`].
    pub slot: u32,
    /// Core index to address the submission to.
    ///
    /// Normally the core the NUT holds at `slot`. The "not a guarantor" fault
    /// is exactly this field naming a different one.
    pub core: u16,
    /// GP-encoded work package.
    pub package: Vec<u8>,
    /// Hash of that package, for correlating with what the node shares.
    pub package_hash: [u8; 32],
    /// Extrinsic bodies, in the order the package declares them.
    pub extrinsics: Vec<Vec<u8>>,
}

/// Where a CE 133 submission is aimed: a slot, and the core the NUT holds
/// at that slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubmissionPlan {
    pub slot: u32,
    pub core: CoreIndex,
}

/// A package as a builder would put it on CE 133, with the extrinsic bodies
/// that go with it as message 2.
///
/// Separate from [`GuaranteedWork`] because CE 133 is the builder-to-guarantor
/// hop, where the *node* does the refining. Refining here would be wasted
/// work, and worse, it would assert that the reference holds the core --
/// which on a CE 133 submission is exactly the validator the package is being
/// sent to, not us.
pub struct BuiltPackage {
    pub package: jam_types::WorkPackage,
    pub extrinsics: Vec<Vec<u8>>,
}

impl RefChain {
    /// Build `items` into an authorized package for a builder to submit.
    pub fn build_work_package(&self, items: Vec<jam_node::hazmat::BuildItem>) -> BuiltPackage {
        let (package, extrinsics) = self.harness().build_package(items);
        BuiltPackage {
            package,
            extrinsics,
        }
    }

    /// The same package, against an authorizer no core will accept.
    ///
    /// `Authorizer::any()`'s code hash is zero, so nothing on the core
    /// authorizes it. This is the "unauthorized package -> no sharing" fault
    /// of DESIGN §11 N3: the package is otherwise well-formed, so a node that
    /// shares it has skipped the authorization check rather than failed to
    /// parse anything.
    pub fn build_unauthorized_package(
        &self,
        items: Vec<jam_node::hazmat::BuildItem>,
    ) -> BuiltPackage {
        let (package, extrinsics) = self.harness().build_package_with_auth(
            items,
            jam_types::Authorizer::any(),
            jam_node::DEV_BOOTSTRAP_SERVICE_ID,
            jam_types::Authorization::new(),
        );
        BuiltPackage {
            package,
            extrinsics,
        }
    }

    /// Where to aim a CE 133 submission: the first slot at or after `from`
    /// that still has `margin` slots left in its rotation, and the core the
    /// NUT holds there.
    ///
    /// The core alone is not enough. CE 133 says the package goes to a
    /// guarantor "in the NUT's rotation", and a validator holds a different
    /// core after every rotation boundary. Submitting in the last slot before
    /// one leaves the node no room to share the package and distribute the
    /// report before the assignment it was given moves out from under it, and
    /// the lane would record a node that did nothing wrong as having failed
    /// to share.
    ///
    /// `None` if no slot within one rotation of `from` qualifies, which can
    /// only happen if `margin` is at least the rotation period.
    pub fn submission_slot_for(&self, nut: u16, from: u32, margin: u32) -> Option<SubmissionPlan> {
        let rotation = jam_types::rotation_period();
        let epoch = jam_types::epoch_period();
        for slot in from..from.saturating_add(rotation) {
            // Rotations are counted inside the epoch, so the position within
            // one is epoch-relative. `slot % rotation` agrees only when the
            // epoch is a whole number of rotations -- true under tiny, and
            // not something to rely on.
            let in_epoch = slot % epoch;
            let left_in_rotation = rotation - (in_epoch % rotation);
            // The epoch boundary moves the assignment too: it reshuffles on
            // new entropy, not just by the rotation offset. A window that
            // straddles one is no safer than one that straddles a rotation.
            let left_in_epoch = epoch - in_epoch;
            if left_in_rotation.min(left_in_epoch) >= margin {
                return self
                    .core_for(nut, slot)
                    .map(|core| SubmissionPlan { slot, core });
            }
        }
        None
    }

    /// Build `items` into a package, refine it on `core`, and sign the
    /// guarantee.
    ///
    /// Nothing is submitted to the reference pool. `submit_work_items` would
    /// do both, and a harness that could not send a report without also
    /// adopting it would have no way to pose "guaranteed but never included".
    pub fn guarantee_work(
        &self,
        items: Vec<jam_node::hazmat::BuildItem>,
        core: CoreIndex,
    ) -> Result<GuaranteedWork, ChainError> {
        let mut harness = self.harness();
        let (package, xts) = harness.build_package(items);
        let wire = package.clone();
        let (report, bundle, _) = harness
            .try_compose_report(package, &xts, core)
            .map_err(|e| ChainError::Chain(format!("compose report: {e}")))?;
        let guarantee = harness
            .try_compose_guarantee(report.clone())
            .map_err(|e| ChainError::Chain(format!("compose guarantee: {e}")))?;
        Ok(GuaranteedWork {
            package: wire,
            report,
            bundle: bundle.to_vec(),
            guarantee,
        })
    }

    /// The validators assigned to `core` at `slot`.
    ///
    /// The assignment is a shuffle of validators across cores by the epoch's
    /// entropy, rotated every `rotation_period` slots. The harness reads it
    /// off the engine rather than recomputing it, so the rule it grades
    /// against is the one the engine applies.
    ///
    /// Read from the *storage* for `slot`, which is the source
    /// `try_compose_guarantee` signs against. Taking it from the chain's
    /// current epoch instead looks equivalent and is not: that reads one
    /// epoch's entropy whatever slot is asked about, so the two disagree as
    /// soon as the slot is outside the epoch the chain happens to be in, and
    /// a guarantee's signers then look like validators that do not hold the
    /// core.
    ///
    /// Not factored into a shared helper: polkajam's `CoreAssignments` lives
    /// behind a private module, so the value can be used but its type cannot
    /// be named, and a helper returning one has nothing to return it as.
    pub fn guarantors_for(&self, core: CoreIndex, slot: u32) -> Option<Vec<u16>> {
        self.harness()
            .storage(None)
            .core_assignments_for(slot)
            .ok()?
            .core_to_vals(core)
            .map(|vals| vals.to_vec())
    }

    /// The core validator `index` guarantees at `slot`.
    pub fn core_for(&self, index: u16, slot: u32) -> Option<CoreIndex> {
        self.harness()
            .storage(None)
            .core_assignments_for(slot)
            .ok()?
            .val_to_core(index)
    }
}
