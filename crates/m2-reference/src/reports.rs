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
    /// The extrinsic bodies the package declares, in wire order. CE 133's
    /// second message is these concatenated, so the submission needs them
    /// from the same build as the package: building twice would re-read the
    /// chain head and could produce a different package entirely.
    pub extrinsics: Vec<Vec<u8>>,
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
    /// The validators that hold `core` at `slot` alongside the NUT.
    ///
    /// Computed here, off the engine's assignment, because it is the set the
    /// node is expected to share with. A harness that derived it itself would
    /// be grading the node against its own arithmetic rather than against the
    /// chain.
    pub co_guarantors: Vec<u16>,
}

/// The epoch info `slot` belongs to, out of the two the chain holds.
///
/// `EpochInfo::core_assignments` requires the slot to be in that epoch, and
/// the chain only ever holds the current one and the next. Asking the current
/// epoch about a slot in the next gives an assignment for neither: a run
/// whose reference head sat in epoch 815091 while the submission slot had
/// crossed into 815092 graded the node against exactly that, and the sharing
/// row failed for a split the node never made.
///
/// `None` for anything outside those two, which is the honest answer rather
/// than a shuffle computed from the wrong entropy.
fn epoch_info_for<'a, E>(
    slot: u32,
    current_index: u32,
    current: &'a E,
    next: &'a E,
) -> Option<&'a E> {
    let slot_epoch = slot / jam_types::epoch_period();
    if slot_epoch == current_index {
        Some(current)
    } else if slot_epoch == current_index + 1 {
        Some(next)
    } else {
        None
    }
}

/// A guaranteed work-report the harness distributes over CE 135, so the node
/// can be graded on including it.
#[derive(Debug, Clone)]
pub struct ScheduledReport {
    /// Slot to distribute in.
    pub slot: u32,
    /// Core the report is guaranteed on.
    pub core: u16,
    /// The emulated validator that must put this on the wire.
    ///
    /// A node validates a received guarantee against the peer that sent it
    /// and refuses one carrying `No signature from peer` -- in those words.
    /// So the sender has to be one of the signers, which is a property of
    /// the cohort and not of whichever connection happened to claim the plan.
    pub sender: u16,
    /// Hash of the report, which is what a block's guarantees are read by.
    pub report_hash: [u8; 32],
    /// The encoded `Guaranteed Work-Report` (`simple.md:478`).
    pub wire: Vec<u8>,
}

/// What an emulated co-guarantor answers a CE 134 share with
/// (`simple.md:456`): the hash of the refined work-report, and a signature
/// over it that can go into a guaranteed work-report.
///
/// Computed from the package the harness submitted rather than from the
/// bundle the node shares back. That is deliberate twice over: decoding a
/// bundle would make the harness's answer depend on the node getting the
/// bundle right, and the reference report is the value the lane compares the
/// node's against anyway. A node that refined something else will disagree
/// with this hash, which is the finding, not an error.
#[derive(Debug, Clone)]
pub struct SharingAnswer {
    /// Hash of the report the reference refined from the submitted package.
    pub report_hash: [u8; 32],
    /// One signature per validator holding the core, by validator index.
    ///
    /// Includes the NUT's own, which the harness never sends: the engine
    /// signs for every holder because it has every keyset, and filtering it
    /// out here would leave the emulator deciding who may answer.
    pub signatures: Vec<(u16, [u8; 64])>,
}

impl GuaranteedWork {
    /// The CE 134 answer for `cohort`: the report's hash, and each listed
    /// validator's own signature over it.
    ///
    /// Signed per validator rather than taken from `self.guarantee`. The
    /// guarantee is composed over the storage view of the assignment, while a
    /// node shares with the cohort its *epoch* view names, and the two
    /// disagree -- so the guarantee holds no signature for the validators
    /// that actually receive the share. Answering with nothing left the node
    /// unable to assemble a guarantee at all, and no CE 135 was ever sent.
    ///
    /// The message is `jam_guarantee ++ hash`, which is the engine's own
    /// [`ed25519::Message::Guarantee`], so the bytes are not reconstructed
    /// here.
    pub fn sharing_answer_for(&self, cohort: &[u16]) -> SharingAnswer {
        let hash = self.report.hash();
        SharingAnswer {
            report_hash: hash.0,
            signatures: cohort
                .iter()
                .map(|&validator| {
                    let secret =
                        jam_std_common::SecretKeyset::trivial(u32::from(validator)).ed25519;
                    (
                        validator,
                        secret
                            .sign(&jam_std_common::ed25519::Message::Guarantee(hash))
                            .to_bytes(),
                    )
                })
                .collect(),
        }
    }
}

impl SharingAnswer {
    /// The signature `validator` should reply with, if it holds the core.
    pub fn signature_for(&self, validator: u16) -> Option<[u8; 64]> {
        self.signatures
            .iter()
            .find(|(index, _)| *index == validator)
            .map(|(_, signature)| *signature)
    }
}

/// Where a CE 133 submission is aimed: a slot, and the core the NUT holds
/// at that slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmissionPlan {
    pub slot: u32,
    pub core: CoreIndex,
    /// The validators holding `core` at `slot` besides the NUT: who it is
    /// expected to open CE 134 to.
    pub co_guarantors: Vec<u16>,
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
                // The epoch view, not the storage one. A guarantor picks who
                // to share a package with from its epoch's own assignment,
                // and the two disagree: measured against a real node in the
                // same epoch as the reference head, storage said core 0 was
                // [2, 3, 5] while the epoch said [0, 4, 5], and the node
                // shared with 4. Aiming a submission by the storage view
                // grades the node against an assignment it is not using.
                return self
                    .core_for_in_epoch(nut, slot)
                    .map(|core| SubmissionPlan {
                        slot,
                        core,
                        co_guarantors: self
                            .guarantors_for_in_epoch(core, slot)
                            .unwrap_or_default()
                            .into_iter()
                            .filter(|v| *v != nut)
                            .collect(),
                    });
            }
        }
        None
    }

    /// A fully reference-guaranteed report for a core the NUT does *not*
    /// hold at `slot`, ready to distribute over CE 135.
    ///
    /// A different core on purpose. The node is already guaranteeing the
    /// package the harness submitted on its own core, and a second report for
    /// the same core would be a duplicate the node is right to drop -- which
    /// would read as a failure to include. On a core it does not hold, every
    /// signature is the reference's and the node's only job is to include it.
    ///
    /// `None` when the NUT holds every core, which cannot happen while there
    /// is more than one.
    pub fn report_to_distribute(
        &self,
        items: Vec<jam_node::hazmat::BuildItem>,
        nut: u16,
        slot: u32,
    ) -> Result<Option<ScheduledReport>, ChainError> {
        let Some(nut_core) = self.core_for_in_epoch(nut, slot) else {
            return Ok(None);
        };
        let cores = jam_types::core_count();
        if cores < 2 {
            return Ok(None);
        }
        let core = (nut_core + 1) % cores;
        let work = self.guarantee_work(items, core)?;
        // Signed by the cohort the *epoch* view names, not the one
        // `try_compose_guarantee` used. That composes over the storage view,
        // and a node checks a received guarantee's signers against its own
        // assignment: with the two views apart it answered every distributed
        // report with `Invalid guarantee: Wrong core assignment`, in those
        // words. The same split, and the same fix, as the CE 134 answer.
        let mut cohort = self.guarantors_for_in_epoch(core, slot).unwrap_or_default();
        // Strictly ascending, which is what a guarantee's signatures must be.
        cohort.sort_unstable();
        cohort.dedup();
        let signed = work.sharing_answer_for(&cohort);
        let distribution = jamnp_s::codec::ce131_136::GuaranteedWorkReport {
            report: work.report.clone(),
            // The slot the cohort was signed for, not the one the guarantee
            // was composed in. A node derives the expected signers from the
            // slot the guarantee declares, so a guarantee signed by the
            // cohort of one slot and stamped with another is rejected as a
            // wrong core assignment however right both halves are.
            slot,
            signatures: signed.signatures,
        };
        Ok(Some(ScheduledReport {
            slot,
            core,
            sender: *cohort.first().ok_or_else(|| {
                ChainError::Chain(format!("core {core} has no holders at slot {slot}"))
            })?,
            report_hash: work.report.hash().0,
            wire: jam_types::Encode::encode(&distribution),
        }))
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
        let xts: Vec<Vec<u8>> = xts.into_iter().collect();
        let (report, bundle, _) = harness
            .try_compose_report(package, &xts, core)
            .map_err(|e| ChainError::Chain(format!("compose report: {e}")))?;
        let guarantee = harness
            .try_compose_guarantee(report.clone())
            .map_err(|e| ChainError::Chain(format!("compose guarantee: {e}")))?;
        Ok(GuaranteedWork {
            package: wire,
            extrinsics: xts,
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

    /// The epoch index the chain's cached epoch view currently names, and the
    /// epoch its best block's state is in.
    ///
    /// The two can differ, and that is the whole of the storage-versus-epoch
    /// disagreement: `EpochInfo` is a cache built from an epoch mark, while
    /// `core_assignments_for` reads the state. When the cache lags, the
    /// "current" epoch is the previous one and its shuffle is a different
    /// shuffle.
    pub fn epoch_views(&self) -> (u32, u32) {
        let harness = self.harness();
        let jam = harness.chain();
        let (index, _current, _next) = jam.current_and_next_epochs();
        let head = jam.best_block().1;
        (index, head / jam_types::epoch_period())
    }

    /// The entropy each view would shuffle with: the cached epoch's, and
    /// entries 1 and 2 of the best block's buffer.
    ///
    /// The on-chain rule shuffles with entry 2 (`exec/reports.rs`), so a
    /// cached value equal to entry 1 is an epoch out, and one equal to
    /// neither came from a state the chain has moved past.
    pub fn assignment_entropy(&self) -> (String, String, String) {
        let harness = self.harness();
        let jam = harness.chain();
        let (_index, current, _next) = jam.current_and_next_epochs();
        let short =
            |bytes: &[u8]| -> String { bytes[..8].iter().map(|b| format!("{b:02x}")).collect() };
        let cached = short(&current.core_assignment_entropy.0);
        let storage = harness.storage(None);
        let buffer = storage
            .entropy()
            .expect("the best block has an entropy buffer");
        (cached, short(&buffer[1].0), short(&buffer[2].0))
    }

    /// The validators assigned to `core` at `slot`, as the *epoch view*
    /// computes it.
    ///
    /// The other half of a disagreement worth keeping visible.
    /// [`guarantors_for`](Self::guarantors_for) reads the storage, which
    /// picks its entropy relative to the storage's own slot -- `Same` takes
    /// entropy 2, `Prev` takes 3, `Next` takes 1. This reads the epoch's own
    /// precomputed entropy instead, which is what a guarantor uses when it
    /// chooses who to share a package with.
    ///
    /// They should agree whenever the reference's head and `slot` sit in the
    /// same epoch. Where they do not, one of the two is being read from the
    /// wrong state, and the lane needs to know which before it grades a node
    /// against either.
    pub fn guarantors_for_in_epoch(&self, core: CoreIndex, slot: u32) -> Option<Vec<u16>> {
        let harness = self.harness();
        let jam = harness.chain();
        let (index, current, next) = jam.current_and_next_epochs();
        epoch_info_for(slot, index, &current, &next)?
            .core_assignments(slot)
            .core_to_vals(core)
            .map(|vals| vals.to_vec())
    }

    /// The core validator `index` guarantees at `slot`, as the epoch view
    /// computes it.
    ///
    /// The view that decides whether the node considers itself a guarantor
    /// of the core a package is addressed to, so it is the one a submission
    /// is aimed with.
    pub fn core_for_in_epoch(&self, validator: u16, slot: u32) -> Option<CoreIndex> {
        let harness = self.harness();
        let jam = harness.chain();
        let (index, current, next) = jam.current_and_next_epochs();
        epoch_info_for(slot, index, &current, &next)?
            .core_assignments(slot)
            .val_to_core(validator)
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
