//! Work packages, reports and guarantees: the artefacts the N3 lane puts on
//! the wire.
//!
//! The same shape as [`crate::tickets`] -- one method per artefact a lane
//! needs, computed once here and handed over whole. The authoring harness
//! does the work; what this module adds is a surface that does not leak it,
//! so a lane cannot reach past the oracle into the engine.

use jam_types::{CoreIndex, Decode};
use m2_oracle_proto::{AssignmentView, Message, WireItem};

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
    /// Which protocol carries it: 133 or 146. See
    /// [`SubmissionSchedule::protocol`].
    pub protocol: u16,
    /// CE 146's segments-root mappings (`simple.md:393`).
    ///
    /// Empty here, and that is the answer rather than a gap: the mappings
    /// map the package's *imported* segments to the roots they come from,
    /// and this run's package imports none. A harness that invented one
    /// would be asking the node to accept a mapping for a segment nobody
    /// exported.
    pub mappings: Vec<([u8; 32], [u8; 32])>,
    /// CE 146's imported segments. Empty, for the same reason.
    pub segments: Vec<Vec<u8>>,
    /// CE 146's import proofs, one per imported segment. Empty likewise.
    pub import_proofs: Vec<Vec<[u8; 32]>>,
    /// What is deliberately wrong with this submission, carried through so
    /// the sender can apply the wire-level faults and the lane can say which
    /// rule it posed.
    pub fault: Option<SubmissionFault>,
    /// The validators that hold `core` at `slot` alongside the NUT.
    ///
    /// Computed here, off the engine's assignment, because it is the set the
    /// node is expected to share with. A harness that derived it itself would
    /// be grading the node against its own arithmetic rather than against the
    /// chain.
    pub co_guarantors: Vec<u16>,
    /// What the reference's report says this package exports, and the root
    /// those exports sit under.
    ///
    /// Zero for a package built without a report -- the unauthorized fault
    /// is never refined -- and that is the honest answer rather than a gap:
    /// a package nobody refined has no exports-root.
    pub exports_root: [u8; 32],
    pub exports_count: u16,
    /// The earlier package this one imports a segment from, if any.
    ///
    /// The lane needs it to grade CE 134's mappings: they must map exactly
    /// this hash to exactly this root (`simple.md:449`). Carried on the
    /// submission rather than looked up per run, because a run that
    /// submitted two importing packages would have two answers.
    pub imports_from: Option<ImportSource>,
}

/// The smallest work item that refines: no payload, no imports, no
/// extrinsics.
pub fn trivial_work_item() -> WireItem {
    work_item_with_payload(Vec::new())
}

/// The same item with a distinguishing payload, so two packages built in one
/// run are two packages.
///
/// The submission and the distributed report are built moments apart from
/// the same template. Given the same payload they are byte-identical, and a
/// node that has noted one refuses the other as already reported -- which
/// reads as the submission being rejected, not as a duplicate.
pub fn work_item_with_payload(payload: Vec<u8>) -> WireItem {
    WireItem {
        service: m2_oracle_proto::DEV_BOOTSTRAP_SERVICE_ID,
        payload,
        ref_gas: jam_types::max_refine_gas(),
        acc_gas: jam_types::max_accumulate_gas(),
        xts: Vec::new(),
        imports: Vec::new(),
        export_count: 0,
    }
}

/// Segments the honest submission exports.
///
/// Four, to match the most the availability plan will ask for: fewer would
/// leave the plan asking for slices that do not exist, and more would cost
/// refine gas for segments nothing fetches.
const EXPORTS_PER_PACKAGE: u16 = 4;

/// A salt that makes two packages in one run two packages, derived from the
/// slot they are aimed at.
///
/// Derived rather than random, because a run that cannot be repeated cannot
/// be bisected -- the same reason the ticket faults are chosen by index.
fn salt_for_slot(slot: u32) -> [u8; 32] {
    let mut salt = [0u8; 32];
    salt[..4].copy_from_slice(&slot.to_le_bytes());
    salt
}

/// Segment length the engine codes and serves in, which is what an exported
/// blob is padded to.
///
/// Named from the engine rather than repeated: a blob shorter than this is
/// padded, and a blob longer than this is more than one segment, so the
/// count a work item declares and the count refine produces only agree
/// when each blob fits in one.
const EXPORT_BLOB_LEN: usize = 64;

/// A work item that exports `count` segments during refine.
///
/// The dev bootstrap service reads its payload as an encoded `Instructions`
/// and acts on each one; `Export { data }` makes it call `export_slice` per
/// blob. So a package that exports anything has to be *asked* to, and
/// `export_count` is a declaration the refine has to live up to -- declare
/// more than refine produces and the item fails.
///
/// This is what `findings.md` §17 needs. Until it existed, every package
/// this harness built declared `export_count: 0`, so a run asked nothing
/// over CE 139, CE 140 or CE 148 and all three reported themselves
/// unexercised against a live node.
///
/// The salt is what makes two otherwise identical items different packages.
/// Taken from the caller rather than randomised, because a run that cannot
/// be repeated cannot be bisected.
pub fn work_item_that_exports(count: u16, salt: [u8; 32]) -> WireItem {
    work_item_that_exports_and_solicits(count, salt, None)
}

/// The exporting item, optionally also soliciting a preimage on chain.
///
/// The two jobs ride one item because only one package in a run can do the
/// second. A `Solicit` takes effect in *accumulate*, and a report is only
/// accumulated once it is available -- which means assured, which means the
/// availability plan covered it. That plan is built from the first report
/// the node distributes, so the first package is the only one whose
/// accumulate ever runs. A solicit on any later package is guaranteed,
/// included, and then sits unaccumulated for the rest of the run.
///
/// Measured rather than assumed: `sessions/n6-2` put the solicit on its own
/// submission a slot behind the honest one, the node guaranteed and
/// included it, and the bootstrap service accumulated exactly once -- for
/// the honest package. The announcement that followed was correctly
/// ignored, because no service had asked for anything.
pub fn work_item_that_exports_and_solicits(
    count: u16,
    salt: [u8; 32],
    solicit: Option<&[u8]>,
) -> WireItem {
    let data: Vec<Vec<u8>> = (0..count)
        .map(|i| vec![(i as u8).wrapping_add(1); EXPORT_BLOB_LEN])
        .collect();
    let mut instructions = vec![jam_bootstrap_service_common::Instruction::Export { data }];
    if let Some(blob) = solicit {
        instructions.push(jam_bootstrap_service_common::Instruction::Solicit {
            hash: jam_types::AnyHash(jam_std_common::hash_raw(blob)),
            len: blob.len() as u64,
        });
    }
    instruction_item(instructions, salt, count)
}

/// A work item that asks the service to solicit a preimage on chain.
///
/// N6's precondition. `simple.md:705-710` has a node follow up a CE 142
/// announcement with a CE 143 request **only** if the preimage "has been
/// requested on chain by the given service", and polkajam enforces exactly
/// that: `note_preimage` refuses with `NotRequested` unless the chain
/// carries a request for this service, hash and length.
///
/// So the lane cannot announce a preimage of its choosing and expect an
/// answer -- it has to put the request on chain first, which means a
/// package the node guarantees, includes and accumulates. The dev bootstrap
/// service takes `Solicit { hash, len }` for exactly this.
///
/// The length is part of the request, not just the hash: a request is keyed
/// on `(service, hash, len)`, so announcing the right hash with the wrong
/// length is a different request and is refused.
pub fn work_item_that_solicits(blob: &[u8], salt: [u8; 32]) -> WireItem {
    instruction_item(
        vec![jam_bootstrap_service_common::Instruction::Solicit {
            hash: jam_types::AnyHash(jam_std_common::hash_raw(blob)),
            len: blob.len() as u64,
        }],
        salt,
        0,
    )
}

/// The blob N6 solicits and then announces.
///
/// Fixed rather than random, because a run that cannot be repeated cannot
/// be bisected -- the same reason the ticket faults are chosen by index.
pub fn n6_preimage() -> Vec<u8> {
    b"m2-conformance-n6-preimage".to_vec()
}

/// A blob no service ever asks for, announced to show that the node reads
/// the condition rather than asking for whatever it is told about.
///
/// Distinct from [`n6_preimage`] by more than a byte, so a node that
/// confused the two would be asking for a visibly different hash.
pub fn n6_unsolicited_preimage() -> Vec<u8> {
    b"m2-conformance-n6-never-solicited".to_vec()
}

/// A package built earlier in the same run, and the one segment of it a
/// later package imports.
///
/// Carried rather than recomputed. The exports-root is what the *engine*
/// put in the earlier package's report, and a harness that derived its own
/// would be checking the node against its own arithmetic -- the same reason
/// [`package_hash`] is not recomputed here either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportSource {
    /// GP hash of the exporting package. This is what CE 134's mappings are
    /// keyed by, and what the import spec names.
    pub package_hash: [u8; 32],
    /// The exports-root its report declared, which is what the mappings
    /// must map that hash *to*.
    pub exports_root: [u8; 32],
    /// Which of its exported segments to import.
    pub index: u16,
}

/// Bytes of the exported blob a work item imports back.
///
/// The engine pads an export out to a whole segment and the service
/// truncates it back on import, so this is a length the import asks for and
/// not a length anything checks. It matches [`EXPORT_BLOB_LEN`] so the two
/// halves of the run describe the same blob.
const IMPORT_BLOB_LEN: u64 = EXPORT_BLOB_LEN as u64;

/// A work item that imports one segment exported by an earlier package.
///
/// The import spec names the earlier package by *hash*, not by its
/// exports-root (`RootIdentifier::Indirect`). That is deliberate and is the
/// whole point of the row this feeds: a guarantor given such a package has
/// to resolve the hash to a segments-root before it can fetch anything, and
/// `simple.md:412-415` makes it carry the resolution to its co-guarantors
/// in CE 134's mappings. An import by direct root needs no mapping, so it
/// would leave the mappings empty and the row unexercised -- which is
/// exactly the state `findings.md` §17 describes.
///
/// `Import { items }` is what makes refine actually read the segment: the
/// service calls `import(index)` and panics if it is not there, so a report
/// at all is evidence the node resolved the mapping and fetched the data.
pub fn work_item_that_imports(from: &ImportSource, salt: [u8; 32]) -> WireItem {
    let spec = jam_types::ImportSpec {
        root: jam_types::RootIdentifier::Indirect(jam_types::WorkPackageHash::from(
            from.package_hash,
        )),
        index: from.index,
    };
    let mut item = instruction_item(
        vec![jam_bootstrap_service_common::Instruction::Import {
            items: vec![(0, IMPORT_BLOB_LEN)],
        }],
        salt,
        0,
    );
    item.imports = vec![jam_types::Encode::encode(&spec)];
    item
}

/// Build a work item whose payload is `instructions`, addressed to the dev
/// bootstrap service.
///
/// One encoder, because the payload's shape is the service's and a second
/// copy of it would drift from the service the node is running.
fn instruction_item(
    instructions: Vec<jam_bootstrap_service_common::Instruction>,
    salt: [u8; 32],
    export_count: u16,
) -> WireItem {
    let payload = jam_types::Encode::encode(&jam_bootstrap_service_common::Instructions {
        instructions,
        salt: jam_bootstrap_service_common::PayloadSalt(salt),
    });
    WireItem {
        service: m2_oracle_proto::DEV_BOOTSTRAP_SERVICE_ID,
        payload,
        ref_gas: jam_types::max_refine_gas(),
        acc_gas: jam_types::max_accumulate_gas(),
        xts: Vec::new(),
        imports: Vec::new(),
        export_count,
    }
}

/// Payload that carries a package past the CE 133 initial-message cap.
///
/// The cap is `2 + 200 * 1024` on the whole message; a payload this size
/// clears it without relying on the rest of the package's overhead.
const OVERSIZED_PAYLOAD: usize = 2 + 200 * 1024;

/// When and where to submit, with no package attached.
///
/// The package is built a few slots before the slot, not when the run is
/// planned. Its refine context is anchored to the chain head at build time,
/// and the anchor has to satisfy two opposing bounds: recent enough to still
/// be in the node's recent history, old enough that the node has imported
/// it. Measured against a live node, about eleven slots ahead is accepted
/// and about fourteen is not, while building against the very head is
/// refused outright.
#[derive(Debug, Clone)]
pub struct SubmissionSchedule {
    pub slot: u32,
    pub core: u16,
    /// Which submission protocol to use: 133 or 146.
    ///
    /// The same package either way. `simple.md:378-404` makes CE 146 the
    /// whole-bundle form of CE 133 -- five messages instead of two, so a
    /// guarantor can authorize the package before downloading the rest --
    /// and DESIGN §11 N3 grades it by the same rules. What differs is the
    /// framing and where the size cap falls, which is exactly what sending
    /// the same package over both is for.
    pub protocol: u16,
    /// Validators holding `core` at `slot` besides the NUT.
    pub co_guarantors: Vec<u16>,
    /// What is deliberately wrong with this submission, if anything.
    pub fault: Option<SubmissionFault>,
    /// Whether this package imports a segment from an earlier one in the
    /// same run.
    ///
    /// A flag here and a value at build time, because the package it would
    /// import from does not exist when the run is planned: its hash and its
    /// exports-root are only known once the reference has refined it. The
    /// plan says what the submission is *for*; the builder supplies the
    /// package it turned out to be.
    pub imports: bool,
    /// Whether this package asks the service to solicit N6's preimage.
    ///
    /// Its own submission rather than a second instruction on the honest
    /// one: the honest package is what N3 and N4 grade, and giving it a
    /// second job would put a second reason in front of every row that
    /// reads it.
    pub solicits: bool,
}

/// A deliberate defect in a CE 133 submission (DESIGN §11 N3).
///
/// Each names one rule and nothing else. A submission that broke two would
/// prove neither: a node refusing it could be refusing the other one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmissionFault {
    /// A work-package over the cap its protocol sets.
    ///
    /// CE 133 caps message 1 -- core index and package together -- at
    /// `2 + 200 * 1024` (`simple.md:362-364`); CE 146 carries the core index
    /// in a message of its own and caps the package alone at `200 * 1024`
    /// (`simple.md:383`). One payload clears both.
    ///
    /// Oversized by payload rather than by padding. A padded package stops
    /// decoding, and a node that refuses one has refused a malformed
    /// message, not an oversized one -- which is a different rule.
    Oversized,
    /// Addressed to a core the NUT does not hold at the slot.
    NotAGuarantor,
    /// Built against an authorizer no core will accept.
    Unauthorized,
    /// Message 2 is not the sum of the declared extrinsic lengths.
    ///
    /// Applied on the wire, not here: the package is well-formed and only
    /// the bytes that follow it are wrong.
    ExtrinsicSizeMismatch,
}

impl SubmissionFault {
    /// Whether the node is expected to reset the stream rather than accept.
    ///
    /// DESIGN §11 N3 asks for a reset on the oversized message and the
    /// extrinsic mismatch, and for silence on the other two: a package for a
    /// core the node does not hold is ignored, and an unauthorized one is
    /// accepted onto the stream and then not shared. So "refused" is the
    /// wrong question for half of these, and the lane asks a different one
    /// of each.
    pub fn expects_reset(&self) -> bool {
        matches!(self, Self::Oversized | Self::ExtrinsicSizeMismatch)
    }

    pub fn describe(&self) -> &'static str {
        match self {
            Self::Oversized => "a first message over the CE 133 size cap",
            Self::NotAGuarantor => "a core the NUT does not hold",
            Self::Unauthorized => "an authorizer no core accepts",
            Self::ExtrinsicSizeMismatch => "an extrinsic message of the wrong size",
        }
    }
}

/// A CE 134 share the harness opens *to* the NUT, so the node does the
/// refining and the lane grades its answer (`simple.md:406-458`).
///
/// The other direction from the CE 134 the node opens after a CE 133. Here
/// the harness is the sharing guarantor and the node is the receiving one,
/// which is the only N3 row where the node's own refinement is the thing
/// measured.
#[derive(Debug, Clone)]
pub struct ScheduledShare {
    pub slot: u32,
    /// The node under test, carried so the sender can recompose the bundle
    /// near the slot without re-deriving which core it holds there.
    ///
    /// The same reason [`ScheduledReport`] carries it, and for the same
    /// defect: a bundle composed when the run is planned is anchored to
    /// that head, and nine slots later the node has dropped it from its
    /// recent blocks and refuses the anchor (`findings.md` §5).
    pub nut: u16,
    pub core: u16,
    pub shard_count: u16,
    pub mappings: Vec<(jam_types::WorkPackageHash, [u8; 32])>,
    /// The work-package bundle, message 2.
    pub bundle: Vec<u8>,
    /// What the reference refined from the same bundle, which the node's
    /// answer must equal.
    pub expected_report_hash: [u8; 32],
    pub fault: Option<ShareFault>,
}

/// A deliberate defect in a CE 134 share (DESIGN §11 N3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareFault {
    /// A shard count that is not the active validator count.
    ///
    /// `simple.md:432-436`: acceptable means matching the validators active
    /// at a slot the report could be included in. With a static set that is
    /// one number, so anything else is rejectable.
    WrongShardCount,
}

/// What [`RefChain::epoch_probe`] reads: the cached epoch index, the head's
/// epoch, the entropy the cached view shuffles with, and entries 1 and 2 of
/// the head's buffer.
type EpochProbe = (u32, u32, [u8; 32], [u8; 32], [u8; 32]);

impl RefChain {
    /// Build a share to send the NUT at `slot`, on a core it holds.
    ///
    /// The package carries a payload of its own so it cannot collide with
    /// the one the submission path builds: two identical packages in one run
    /// are one package, and the node refuses whichever arrives second.
    pub fn share_to_nut(
        &self,
        nut: u16,
        slot: u32,
        fault: Option<ShareFault>,
    ) -> Result<Option<ScheduledShare>, ChainError> {
        let Some(core) = self.core_for_in_epoch(nut, slot)? else {
            return Ok(None);
        };
        let work = self.guarantee_work(
            vec![work_item_with_payload(b"n3-shared-to-nut".to_vec())],
            core,
        )?;
        let validators = jam_types::max_val_count();
        let shard_count = match fault {
            // One below the active count: acceptable is exactly the active
            // count, so this is rejectable without being absurd.
            Some(ShareFault::WrongShardCount) => validators.saturating_sub(1),
            None => validators,
        };
        Ok(Some(ScheduledShare {
            slot,
            nut,
            core,
            shard_count,
            // No imported segments, so no mappings. The spec lets a
            // guarantor either refuse or trust unverifiable mappings
            // (`simple.md:443-445`), so a bad-mapping row could not fail
            // either way and the lane does not pose one.
            mappings: Vec::new(),
            bundle: work.bundle,
            expected_report_hash: work.report.hash().0,
            fault,
        }))
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
    /// The node under test, carried so the sender can recompose near the
    /// slot without re-deriving which core to avoid.
    pub nut: u16,
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
            signatures: guarantee_signatures(hash, cohort),
        }
    }
}

/// Sign `report_hash` as each of `cohort` would, in the order given.
///
/// One copy of the rule, because both sides of CE 135 compute it: the
/// harness signs as a co-guarantor answering a CE 134 share, and a node
/// distributing a guarantee signs the same hash the same way. A second copy
/// in the simulated node would let the two drift, and a drift there would
/// look like a node signing wrongly.
///
/// The message is `jam_guarantee ++ hash`, which is the engine's own
/// [`jam_std_common::ed25519::Message::Guarantee`], so the bytes are not
/// reconstructed here. The keys are the trivial keyset's, which is what
/// every validator in a harness run holds.
pub fn guarantee_signatures(
    report_hash: jam_types::WorkReportHash,
    cohort: &[u16],
) -> Vec<(u16, [u8; 64])> {
    cohort
        .iter()
        .map(|&validator| {
            let secret = jam_std_common::SecretKeyset::trivial(u32::from(validator)).ed25519;
            (
                validator,
                secret
                    .sign(&jam_std_common::ed25519::Message::Guarantee(report_hash))
                    .to_bytes(),
            )
        })
        .collect()
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
    /// Build this run's package against the current chain head, with the
    /// CE 134 answer its co-guarantors will give.
    ///
    /// Called a few slots before the submission so the anchor lands inside
    /// the window on [`SubmissionSchedule`].
    pub fn submission_now(
        &self,
        schedule: &SubmissionSchedule,
        imports_from: Option<&ImportSource>,
    ) -> Result<(ScheduledSubmission, SharingAnswer), ChainError> {
        // A plan that asked to import and was given nothing to import from
        // is a run that lost its exporting package, not a package with no
        // imports. Said out loud: building it anyway would hand the lane a
        // submission that looks honest and quietly grades nothing.
        if schedule.imports && imports_from.is_none() {
            return Err(ChainError::Chain(format!(
                "the submission for slot {} imports, but no earlier package in this run \
                 exported anything to import",
                schedule.slot
            )));
        }
        let items = match schedule.fault {
            // Big enough to clear the cap on its own, with the package's own
            // overhead on top.
            Some(SubmissionFault::Oversized) => {
                vec![work_item_with_payload(vec![0x5a; OVERSIZED_PAYLOAD])]
            }
            // The honest submission exports segments, and it is the only one
            // that needs to: the availability plan is built from the first
            // report the node distributes, and the honest submission leads
            // the run. Without this the report declares `exports_count: 0`,
            // the plan asks for no segments, and CE 139, CE 140 and CE 148
            // report themselves unexercised -- truthfully, and in a way that
            // reads on a green report exactly like a node that answered
            // (`findings.md` §17).
            //
            // The faulty submissions keep the trivial item. Each exists to
            // pose one defect, and giving them work to do as well would put
            // a second reason in front of every row they feed.
            None => match imports_from {
                // The importing submission imports and exports nothing. It
                // is here to make a node resolve a work-package hash to a
                // segments-root and say so in CE 134's mappings, and a
                // package that also exported would give the run a second
                // root to confuse that with.
                Some(from) => vec![work_item_that_imports(from, salt_for_slot(schedule.slot))],
                // The honest package exports for N4 and, where the run
                // asked, solicits for N6. One package because only the
                // first one's accumulate ever runs; see
                // `work_item_that_exports_and_solicits`.
                None => vec![work_item_that_exports_and_solicits(
                    EXPORTS_PER_PACKAGE,
                    salt_for_slot(schedule.slot),
                    schedule.solicits.then(n6_preimage).as_deref(),
                )],
            },
            _ => vec![trivial_work_item()],
        };

        let work = match schedule.fault {
            Some(SubmissionFault::Unauthorized) => {
                let built = self.build_unauthorized_package(items)?;
                // An unauthorized package is never refined: the node is
                // expected to take the submission and then not share it, so
                // the harness needs the package and no report at all.
                return Ok((
                    ScheduledSubmission {
                        slot: schedule.slot,
                        core: schedule.core,
                        protocol: schedule.protocol,
                        package: jam_types::Encode::encode(&built.package),
                        package_hash: package_hash(&built.package).0,
                        extrinsics: built.extrinsics,
                        mappings: Vec::new(),
                        segments: Vec::new(),
                        import_proofs: Vec::new(),
                        fault: schedule.fault,
                        co_guarantors: schedule.co_guarantors.clone(),
                        exports_root: [0u8; 32],
                        exports_count: 0,
                        imports_from: imports_from.copied(),
                    },
                    SharingAnswer {
                        report_hash: [0u8; 32],
                        signatures: Vec::new(),
                    },
                ));
            }
            _ => self.guarantee_work(items, schedule.core)?,
        };
        let answer = work.sharing_answer_for(&schedule.co_guarantors);
        Ok((
            ScheduledSubmission {
                slot: schedule.slot,
                core: schedule.core,
                protocol: schedule.protocol,
                package: jam_types::Encode::encode(&work.package),
                package_hash: package_hash(&work.package).0,
                extrinsics: work.extrinsics,
                mappings: Vec::new(),
                segments: Vec::new(),
                import_proofs: Vec::new(),
                fault: schedule.fault,
                co_guarantors: schedule.co_guarantors.clone(),
                exports_root: work.report.package_spec.exports_root.0,
                exports_count: work.report.package_spec.exports_count,
                imports_from: imports_from.copied(),
            },
            answer,
        ))
    }

    /// Whether a block on this chain carries a guarantee for `package`.
    ///
    /// What a guarantor needs before it can act on a package that imports
    /// by work-package hash: `available_data` resolves the hash out of the
    /// packages the chain has seen, so until the guarantee for the
    /// exporting package is in a block, the import names nothing. A node
    /// asked too early does not refuse the submission -- it takes it, fails
    /// to fetch, and never shares -- which would read on the report as a
    /// node that would not share a package it was given.
    ///
    /// Read off the whole chain, not the node's own blocks. The reference
    /// and the node import each other's blocks, so either one carrying the
    /// guarantee is enough, and the node authors one slot in six.
    pub fn carries_package(&self, package: &[u8; 32]) -> Result<bool, ChainError> {
        Ok(self.chain_blocks()?.iter().any(|block| {
            block
                .extrinsic
                .guarantees
                .iter()
                .any(|guarantee| guarantee.report.package_spec.hash.0 == *package)
        }))
    }

    /// Build `items` into an authorized package for a builder to submit.
    pub fn build_work_package(&self, items: Vec<WireItem>) -> Result<BuiltPackage, ChainError> {
        self.build_package(items, true)
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
        items: Vec<WireItem>,
    ) -> Result<BuiltPackage, ChainError> {
        self.build_package(items, false)
    }

    fn build_package(
        &self,
        items: Vec<WireItem>,
        authorized: bool,
    ) -> Result<BuiltPackage, ChainError> {
        match self.ask(Message::BuildPackage {
            session: self.session(),
            items,
            authorized,
        })? {
            Message::Package {
                package,
                extrinsics,
            } => Ok(BuiltPackage {
                package: decode(&package, "a work package")?,
                extrinsics,
            }),
            other => Err(ChainError::Oracle(format!(
                "BuildPackage answered {other:?}"
            ))),
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
    pub fn submission_slot_for(
        &self,
        nut: u16,
        from: u32,
        margin: u32,
    ) -> Result<Option<SubmissionPlan>, ChainError> {
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
                // `continue`, not an early return: a slot the epoch view
                // cannot answer for is not a reason to give up on the later
                // ones. Returning here made one unanswerable slot look like
                // a rotation with no usable slot in it at all.
                let Some(core) = self.core_for_in_epoch(nut, slot)? else {
                    continue;
                };
                return Ok(Some(SubmissionPlan {
                    slot,
                    core,
                    co_guarantors: self
                        .guarantors_for_in_epoch(core, slot)?
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|v| *v != nut)
                        .collect(),
                }));
            }
        }
        Ok(None)
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
        items: Vec<WireItem>,
        nut: u16,
        slot: u32,
    ) -> Result<Option<ScheduledReport>, ChainError> {
        let Some(nut_core) = self.core_for_in_epoch(nut, slot)? else {
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
        let mut cohort = self
            .guarantors_for_in_epoch(core, slot)?
            .unwrap_or_default();
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
            nut,
            sender: *cohort.first().ok_or_else(|| {
                ChainError::Chain(format!("core {core} has no holders at slot {slot}"))
            })?,
            report_hash: work.report.hash().0,
            wire: jam_types::Encode::encode(&distribution),
        }))
    }

    /// Pool a guaranteed work-report, so the next block this session
    /// authors can carry it.
    ///
    /// What [`RefChain::guarantee_work`] deliberately does not do, for a
    /// caller that does want it. A node's guarantees extrinsic carries what
    /// its peers distributed to it over CE 135 as well as what it refined
    /// itself, and until this existed a simulated node could receive a
    /// distribution and had no way to act on one -- which left
    /// `n3_ce135_report_included` with no fault to pose.
    ///
    /// Taken as already verified, like
    /// [`RefChain::submit_assurances`](crate::availability). The engine
    /// notes it into the guarantee table without checking it -- but unlike
    /// an assurance that is survivable, because block composition re-checks
    /// every guarantee it holds and skips the ones that do not. Pooling one
    /// that does not hold up costs a block its guarantee, not its validity,
    /// which is why the emulator can pool whatever the node distributes
    /// without risking the reference chain's own authoring.
    pub fn submit_guarantee(
        &self,
        guarantee: &jam_std_common::ReportGuarantee,
    ) -> Result<(), ChainError> {
        match self.ask(Message::SubmitGuarantee {
            session: self.session(),
            guarantee: jam_types::Encode::encode(guarantee),
        })? {
            Message::Done => Ok(()),
            other => Err(ChainError::Oracle(format!(
                "SubmitGuarantee answered {other:?}"
            ))),
        }
    }

    /// Build `items` into a package, refine it on `core`, and sign the
    /// guarantee.
    ///
    /// Nothing is submitted to the reference pool. `submit_work_items` would
    /// do both, and a harness that could not send a report without also
    /// adopting it would have no way to pose "guaranteed but never included".
    pub fn guarantee_work(
        &self,
        items: Vec<WireItem>,
        core: CoreIndex,
    ) -> Result<GuaranteedWork, ChainError> {
        // One request for all four artefacts, because they are one
        // computation. Building the package in a separate round trip would
        // re-read the chain head and could refine a different package than
        // the one handed back.
        match self.ask(Message::GuaranteeWork {
            session: self.session(),
            items,
            core,
        })? {
            Message::GuaranteedWork {
                package,
                extrinsics,
                report,
                bundle,
                guarantee,
            } => Ok(GuaranteedWork {
                package: decode(&package, "a work package")?,
                extrinsics,
                report: decode(&report, "a work report")?,
                bundle,
                guarantee: decode(&guarantee, "a guarantee")?,
            }),
            other => Err(ChainError::Oracle(format!(
                "GuaranteeWork answered {other:?}"
            ))),
        }
    }

    /// The validators assigned to `core` at `slot`.
    ///
    /// The assignment is a shuffle of validators across cores by the epoch's
    /// entropy, rotated every `rotation_period` slots. The oracle reads it
    /// off the engine rather than recomputing it, so the rule a lane grades
    /// against is the one the engine applies.
    ///
    /// Read from the *storage* for `slot`, which is the source
    /// `try_compose_guarantee` signs against. Taking it from the chain's
    /// current epoch instead looks equivalent and is not: that reads one
    /// epoch's entropy whatever slot is asked about, so the two disagree as
    /// soon as the slot is outside the epoch the chain happens to be in, and
    /// a guarantee's signers then look like validators that do not hold the
    /// core.
    pub fn guarantors_for(
        &self,
        core: CoreIndex,
        slot: u32,
    ) -> Result<Option<Vec<u16>>, ChainError> {
        Ok(self
            .assignment(AssignmentView::Storage, slot)?
            .get(core as usize)
            .cloned()
            .flatten())
    }

    /// The epoch index the chain's cached epoch view currently names, and the
    /// epoch its best block's state is in.
    ///
    /// The two can differ, and that is the whole of the storage-versus-epoch
    /// disagreement: `EpochInfo` is a cache built from an epoch mark, while
    /// `core_assignments_for` reads the state. When the cache lags, the
    /// "current" epoch is the previous one and its shuffle is a different
    /// shuffle.
    pub fn epoch_views(&self) -> Result<(u32, u32), ChainError> {
        let (cached, head, _, _, _) = self.epoch_probe()?;
        Ok((cached, head))
    }

    /// The entropy each view would shuffle with: the cached epoch's, and
    /// entries 1 and 2 of the best block's buffer.
    ///
    /// The on-chain rule shuffles with entry 2 (`exec/reports.rs`), so a
    /// cached value equal to entry 1 is an epoch out, and one equal to
    /// neither came from a state the chain has moved past.
    pub fn assignment_entropy(&self) -> Result<(String, String, String), ChainError> {
        let (_, _, cached, one, two) = self.epoch_probe()?;
        let short =
            |bytes: &[u8]| -> String { bytes[..8].iter().map(|b| format!("{b:02x}")).collect() };
        Ok((short(&cached), short(&one), short(&two)))
    }

    /// Entries 1 and 2 of the best block's entropy buffer, full width.
    ///
    /// Entry 2 is what a submitted ticket is checked against and what
    /// [`RefChain::ticket_ctx`](crate::tickets) seals with; entry 1 is what
    /// entry 2 becomes after the next epoch change. They agree whenever an
    /// epoch boundary falls between proving and delivery, which is why
    /// sealing with the wrong one went unnoticed for as long as it did.
    pub fn entropy_entries(&self) -> Result<([u8; 32], [u8; 32]), ChainError> {
        let (_, _, _, one, two) = self.epoch_probe()?;
        Ok((one, two))
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
    pub fn guarantors_for_in_epoch(
        &self,
        core: CoreIndex,
        slot: u32,
    ) -> Result<Option<Vec<u16>>, ChainError> {
        Ok(self
            .assignment(AssignmentView::Epoch, slot)?
            .get(core as usize)
            .cloned()
            .flatten())
    }

    /// The core validator `index` guarantees at `slot`, as the epoch view
    /// computes it.
    ///
    /// The view that decides whether the node considers itself a guarantor
    /// of the core a package is addressed to, so it is the one a submission
    /// is aimed with.
    pub fn core_for_in_epoch(
        &self,
        validator: u16,
        slot: u32,
    ) -> Result<Option<CoreIndex>, ChainError> {
        Ok(core_holding(
            &self.assignment(AssignmentView::Epoch, slot)?,
            validator,
        ))
    }

    /// The core validator `index` guarantees at `slot`.
    pub fn core_for(&self, index: u16, slot: u32) -> Result<Option<CoreIndex>, ChainError> {
        Ok(core_holding(
            &self.assignment(AssignmentView::Storage, slot)?,
            index,
        ))
    }

    /// The whole core-to-validators table at `slot` under one view.
    ///
    /// One request rather than one per core: the four public views above are
    /// all slices of this table, and a round trip each would put four on the
    /// slot-critical path.
    fn assignment(
        &self,
        view: AssignmentView,
        slot: u32,
    ) -> Result<Vec<Option<Vec<u16>>>, ChainError> {
        match self.ask(Message::CoreAssignment {
            session: self.session(),
            slot,
            view,
        })? {
            Message::Assignment(table) => Ok(table),
            other => Err(ChainError::Oracle(format!(
                "CoreAssignment answered {other:?}"
            ))),
        }
    }

    /// `(cached epoch, head epoch, cached entropy, entry 1, entry 2)`.
    fn epoch_probe(&self) -> Result<EpochProbe, ChainError> {
        match self.ask(Message::EpochProbe(self.session()))? {
            Message::EpochProbed {
                cached_index,
                head_epoch,
                cached_entropy,
                entropy_1,
                entropy_2,
            } => Ok((
                cached_index,
                head_epoch,
                cached_entropy,
                entropy_1,
                entropy_2,
            )),
            other => Err(ChainError::Oracle(format!("EpochProbe answered {other:?}"))),
        }
    }
}

/// The core whose cohort contains `validator`, if the table resolves at all.
fn core_holding(table: &[Option<Vec<u16>>], validator: u16) -> Option<CoreIndex> {
    table.iter().enumerate().find_map(|(core, cohort)| {
        cohort
            .as_ref()
            .filter(|vals| vals.contains(&validator))
            .map(|_| core as CoreIndex)
    })
}

/// One engine value, decoded from the bytes the oracle sent.
///
/// Trailing bytes are a failure rather than something to ignore: the oracle
/// encodes exactly one value per field, so anything left over means the two
/// sides disagree about the encoding and every field read out of it is
/// suspect.
fn decode<T: Decode>(encoded: &[u8], what: &str) -> Result<T, ChainError> {
    let mut cursor = encoded;
    let value = T::decode(&mut cursor).map_err(|e| ChainError::Oracle(format!("{what}: {e}")))?;
    if !cursor.is_empty() {
        return Err(ChainError::Oracle(format!(
            "{what} came back with {} trailing bytes",
            cursor.len()
        )));
    }
    Ok(value)
}

#[cfg(test)]
mod export_tests {
    use super::*;
    use crate::oracle::Oracle;

    /// Slots to author before refining: enough to reach the current epoch
    /// and leave a lookup anchor that is not genesis.
    const WALK: u32 = 12;

    /// A package asked to export segments exports them, and one that is not
    /// asked exports nothing.
    ///
    /// The whole of `findings.md` §17 rests on the first half. Every package
    /// this harness built declared `export_count: 0`, so the availability
    /// plan asked for no segments and CE 139, CE 140 and CE 148 reported
    /// themselves unexercised against a live node -- truthfully, and in a
    /// way that reads on a green report exactly like a node that answered.
    ///
    /// The second half is the control. Without it a passing assertion could
    /// mean the engine reports a count it was handed rather than one it
    /// produced.
    #[test]
    fn a_work_item_asked_to_export_does() -> Result<(), ChainError> {
        let oracle = Oracle::for_tests();
        let chain = RefChain::tiny(&oracle, 5)?;
        let from = crate::chain::wall_clock_slot();
        let authored = (from..from + WALK)
            .filter(|&slot| matches!(chain.author_block(slot), Ok(Some(_))))
            .count();
        assert!(
            authored > 1,
            "the chain must reach the current epoch to refine"
        );

        let exporting = chain.guarantee_work(vec![work_item_that_exports(2, [7u8; 32])], 0)?;
        assert_eq!(
            exporting.report.package_spec.exports_count, 2,
            "a package that asked to export two segments must report two"
        );
        assert_ne!(
            exporting.report.package_spec.exports_root.0, [0u8; 32],
            "two exported segments must sit under a root"
        );

        let plain = chain.guarantee_work(vec![work_item_with_payload(b"nothing".to_vec())], 0)?;
        assert_eq!(
            plain.report.package_spec.exports_count, 0,
            "the control must export nothing, or the count above says nothing"
        );
        Ok(())
    }

    /// A package that imports a segment from an earlier one refines, and
    /// its report carries the mapping that made it possible.
    ///
    /// Both halves matter. Refining at all is the harder one: the service
    /// calls `import(0)` and panics if the segment is not there, so a report
    /// is evidence that the hash in the import spec was resolved to a
    /// segments-root and the data behind it fetched. The lookup on the
    /// report is what `simple.md:449` then puts on the wire as CE 134's
    /// mappings, and is the value `n3_ce134_maps_the_imported_package`
    /// holds a node to -- so asserting it here is asserting the row's
    /// expectation and not just the reference's arithmetic.
    #[test]
    fn a_work_item_that_imports_resolves_the_package_it_imports_from() -> Result<(), ChainError> {
        let oracle = Oracle::for_tests();
        let chain = RefChain::tiny(&oracle, 5)?;
        let from = crate::chain::wall_clock_slot();
        let authored = (from..from + WALK)
            .filter(|&slot| matches!(chain.author_block(slot), Ok(Some(_))))
            .count();
        assert!(
            authored > 1,
            "the chain must reach the current epoch to refine"
        );

        let exporting = chain.guarantee_work(vec![work_item_that_exports(2, [9u8; 32])], 0)?;
        let source = ImportSource {
            package_hash: package_hash(&exporting.package).0,
            exports_root: exporting.report.package_spec.exports_root.0,
            index: 0,
        };

        let importing =
            chain.guarantee_work(vec![work_item_that_imports(&source, [10u8; 32])], 0)?;
        let mapped: Vec<([u8; 32], [u8; 32])> = importing
            .report
            .sr_lookup
            .iter()
            .map(|(hash, root)| (hash.0, root.0))
            .collect();
        assert_eq!(
            mapped,
            vec![(source.package_hash, source.exports_root)],
            "the importing report must resolve the exporting package's hash to its \
             exports-root, which is what a guarantor shares over CE 134"
        );
        Ok(())
    }
}
