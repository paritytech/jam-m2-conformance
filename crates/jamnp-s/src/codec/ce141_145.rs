//! Codecs for CE 141 (assurance), 142 (preimage announcement), 143 (preimage
//! request), 144 (audit announcement) and 145 (judgment) per `jam-np/simple.md`
//! (`:678-828`).

use codec::{Decode, Encode, Input, Output};
use jam_types::HeaderHash;

/// CE 141: Assurance distribution (`simple.md:678-698`).
///
/// `Assurance = Header Hash (Anchor) ++ Bitfield ++ Ed25519 Signature`
/// (`simple.md:691`). Three fixed-width fields and nothing else: the bitfield
/// is `[u8; ceil(C / 8)]`, so it carries no length prefix.
///
/// Held as a `Vec<u8>` so a validator can report a bitfield of the wrong
/// width as a fault rather than a decode failure, but encoded raw. A derived
/// codec would put a compact length in front of it and make every assurance
/// this harness sent one byte longer than the one a node expects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Assurance {
    /// Header hash of the block being assured.
    pub anchor: HeaderHash,
    /// One bit per core; one byte covers 8 cores.
    pub bitfield: Vec<u8>,
    /// Ed25519 signature over the assurance.
    pub signature: [u8; 64],
}

/// Bytes a bitfield occupies on the wire: one per eight cores
/// (`simple.md:691`, GP `C`).
///
/// Derived here from the active core count rather than taken from the
/// engine's own type, which is the point of this crate: a node is graded
/// against an independent reading of the protocol. `m2-reference`'s
/// `assurance::bitfield_len` asks the engine instead, and a test there holds
/// the two together.
pub fn bitfield_len() -> usize {
    (jam_types::core_count() as usize).div_ceil(8)
}

impl Encode for Assurance {
    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        dest.write(&self.anchor.0);
        dest.write(&self.bitfield);
        dest.write(&self.signature);
    }
}

impl Decode for Assurance {
    fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        let mut anchor = [0u8; 32];
        input.read(&mut anchor)?;
        let mut bitfield = vec![0u8; bitfield_len()];
        input.read(&mut bitfield)?;
        let mut signature = [0u8; 64];
        input.read(&mut signature)?;
        Ok(Self {
            anchor: HeaderHash::from(anchor),
            bitfield,
            signature,
        })
    }
}

/// CE 142: Preimage announcement (`simple.md:700-724`).
///
/// `Service ID ++ Hash ++ Preimage Length` (`simple.md:721`).
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct PreimageAnnouncement {
    /// The service the preimage was requested by.
    pub service_id: u32,
    /// Hash of the announced preimage.
    pub hash: [u8; 32],
    /// Length of the announced preimage.
    pub length: u32,
}

/// CE 143: Preimage request (`simple.md:726-744`).
///
/// `--> Hash` (`simple.md:740`).
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct PreimageRequest {
    /// Hash of the requested preimage.
    pub hash: [u8; 32],
}

/// CE 143 reply: `Preimage = [u8]` (`simple.md:736,739`).
///
/// The preimage is sent as raw bytes with no length prefix: its length is
/// already known from the CE 142 announcement. Decoding consumes the whole
/// remaining message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreimageReply {
    /// The raw preimage bytes.
    pub preimage: Vec<u8>,
}

impl Encode for PreimageReply {
    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        dest.write(&self.preimage);
    }
}

impl Decode for PreimageReply {
    fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        // The preimage has no length prefix on the wire; the whole remaining
        // message is the preimage.
        let mut preimage = Vec::new();
        while let Ok(byte) = input.read_byte() {
            preimage.push(byte);
        }
        Ok(Self { preimage })
    }
}

/// CE 144: Audit announcement (`simple.md:746-785`).
///
/// The announcement is one value and the message is a vector of them:
/// `--> [Announcement]` (`simple.md:782`). An earlier revision of the spec
/// framed this as `Header Hash ++ Tranche ++ Announcement` followed by a
/// separate `Evidence` message carrying no-show proofs; both are gone
/// (`findings.md` §28).
///
/// `Announcement = Header Hash ++ Validator Index ++ Intent ++ Bandersnatch
/// Signature` (`simple.md:778`).
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct Announcement {
    /// Header hash of the block being audited.
    pub header_hash: HeaderHash,
    /// Index of the announcing auditor.
    pub validator_index: u16,
    /// Which tranche's intent this is, and the core where that is declared.
    pub intent: Intent,
    /// `s_0` in the GP for the initial tranche, `S(r)` for a later one.
    ///
    /// The tranche is **not** declared on the wire. A recipient verifies
    /// this signature and derives the tranche from its VRF output
    /// (`simple.md:769-771`), so a harness that sent a tranche number would
    /// be sending a field no node reads.
    pub signature: [u8; 96],
}

/// `Intent = 0 (Initial tranche) OR 1 ++ Core Index (Later tranche)`, a
/// one-byte discriminator (`simple.md:777`).
///
/// The initial tranche does not declare its cores at all: the signature
/// selects the work-reports and recipients derive them from it
/// (`simple.md:762-764`). Only a later-tranche announcement names a core,
/// and it names exactly one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Intent {
    /// Tranche 0: the signature selects the reports, no core is declared.
    Initial,
    /// A later tranche: one work-report, on this core.
    Later(u16),
}

impl Encode for Intent {
    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        match self {
            Intent::Initial => dest.push_byte(0),
            Intent::Later(core) => {
                dest.push_byte(1);
                core.encode_to(dest);
            }
        }
    }
}

impl Decode for Intent {
    fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        match input.read_byte()? {
            0 => Ok(Intent::Initial),
            1 => u16::decode(input).map(Intent::Later),
            _ => Err(codec::Error::from("invalid Intent discriminator")),
        }
    }
}

/// CE 145: Judgment publication (`simple.md:787-828`).
///
/// `GuaranteeSignature = Validator Index ++ Ed25519 Signature`
/// (`simple.md:818`).
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct GuaranteeSignature {
    /// Index of the guaranteeing validator.
    pub validator_index: u16,
    /// Ed25519 signature over the work-report.
    pub signature: [u8; 64],
}

/// `Guarantee = Slot ++ len++[GuaranteeSignature]` (`simple.md:819`).
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct Guarantee {
    /// Slot in which the report could be included on chain.
    pub slot: u32,
    /// Guaranteeing validator signatures (2 or 3 in practice).
    pub signatures: Vec<GuaranteeSignature>,
}

/// `Validity = 0 ++ Guarantee (Invalid) OR 1 (Valid)`, a one-byte
/// discriminator (`simple.md:820`).
///
/// The guarantee rides **inside** the discriminator, which puts it in the
/// middle of the judgment rather than after it. An earlier revision sent it
/// as a separate optional message, present iff the validity byte was 0
/// (`findings.md` §28). A codec that appended the guarantee instead would
/// encode the work-report hash and the signature in the wrong place and
/// produce bytes no node can read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Validity {
    /// Invalid, with the guarantees that backed the report.
    Invalid(Guarantee),
    /// Valid. Needs no guarantee (`simple.md:811`).
    Valid,
}

impl Encode for Validity {
    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        match self {
            Validity::Invalid(guarantee) => {
                dest.push_byte(0);
                guarantee.encode_to(dest);
            }
            Validity::Valid => dest.push_byte(1),
        }
    }
}

impl Decode for Validity {
    fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        match input.read_byte()? {
            0 => Guarantee::decode(input).map(Validity::Invalid),
            1 => Ok(Validity::Valid),
            _ => Err(codec::Error::from("invalid Validity discriminator")),
        }
    }
}

/// `Judgment = Epoch Index ++ Validator Index ++ Validity ++ Work-Report Hash
/// ++ Ed25519 Signature` (`simple.md:821`), and the message is a vector of
/// them: `--> [Judgment]` (`simple.md:825`).
///
/// Judgments from different auditors, work-reports and epochs may be batched
/// into one message (`simple.md:814-815`).
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct Judgment {
    /// Epoch the judging validator belongs to.
    pub epoch_index: u32,
    /// Index of the judging validator.
    pub validator_index: u16,
    /// Valid, or invalid with the guarantees that backed the report.
    pub validity: Validity,
    /// Hash of the judged work-report.
    pub report_hash: [u8; 32],
    /// Ed25519 signature over the judgment.
    pub signature: [u8; 64],
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::{Decode, Encode};
    use jam_types::HeaderHash;

    /// 64-byte Ed25519 signature with `sig[i] = (i + offset) mod 256`.
    fn sig64(offset: u8) -> [u8; 64] {
        core::array::from_fn(|i| (i as u8).wrapping_add(offset))
    }

    /// 96-byte Bandersnatch signature with `sig[i] = (i + offset) mod 256`.
    fn sig96(offset: u8) -> [u8; 96] {
        core::array::from_fn(|i| (i as u8).wrapping_add(offset))
    }

    // --- CE 141: Assurance -------------------------------------------------

    /// The bitfield rides raw: `Anchor ++ Bitfield ++ Signature` and nothing
    /// in between. A compact length in front of it -- which a derived codec
    /// puts there -- makes every assurance one byte longer than the one a
    /// node reads, and the extra byte shifts the signature out of place.
    #[test]
    fn assurance_vector_has_no_length_before_the_bitfield() {
        let a = Assurance {
            anchor: HeaderHash::from([0x11; 32]),
            bitfield: vec![0xaa, 0xbb],
            signature: sig64(0x30),
        };
        let bytes = a.encode();
        let mut expected = vec![0x11; 32]; // Header Hash (Anchor)
        expected.extend_from_slice(&[0xaa, 0xbb]); // Bitfield, raw
        expected.extend_from_slice(&sig64(0x30)); // Ed25519 Signature
        assert_eq!(bytes, expected);
        assert_eq!(bytes.len(), 32 + 2 + 64);
    }

    /// Decoding reads the width from the active core count, because the wire
    /// does not carry it. A test that does not apply the parameters is
    /// decoding against whatever the process last set.
    #[test]
    fn assurance_roundtrip() {
        jam_types::ProtocolParameters::tiny()
            .apply()
            .expect("the tiny parameters are valid");
        assert_eq!(bitfield_len(), 1, "two cores fit in one byte");
        let a = Assurance {
            anchor: HeaderHash::from([0x22; 32]),
            bitfield: vec![0xcc],
            signature: sig64(0x10),
        };
        let bytes = a.encode();
        assert_eq!(bytes.len(), 32 + 1 + 64);
        let mut input: &[u8] = &bytes[..];
        let decoded = Assurance::decode(&mut input).unwrap();
        assert!(
            input.is_empty(),
            "the message is exactly those three fields"
        );
        assert_eq!(decoded, a);
    }

    /// Built from `bitfield_len()` rather than from a literal width. The
    /// message has no length prefix, so what counts as truncated depends on
    /// the parameters in force, and a fixed-width case stops being short the
    /// moment the core count changes.
    #[test]
    fn assurance_truncated_errs() {
        jam_types::ProtocolParameters::tiny()
            .apply()
            .expect("the tiny parameters are valid");
        let full = 32 + bitfield_len() + 64;
        // Header hash only.
        let mut input: &[u8] = &[0x11; 32];
        assert!(Assurance::decode(&mut input).is_err());
        // One byte short of the whole message.
        let bytes = vec![0x11; full - 1];
        let mut input: &[u8] = &bytes[..];
        assert!(Assurance::decode(&mut input).is_err());
        // Empty.
        let mut input: &[u8] = &[];
        assert!(Assurance::decode(&mut input).is_err());
    }

    // --- CE 142: Preimage announcement --------------------------------------

    #[test]
    fn preimage_announcement_vector() {
        let p = PreimageAnnouncement {
            service_id: 0x0403_0201,
            hash: [0x42; 32],
            length: 0x0807_0605,
        };
        let bytes = p.encode();
        let mut expected = vec![0x01, 0x02, 0x03, 0x04]; // Service ID (u32 LE)
        expected.extend_from_slice(&[0x42; 32]); // Hash
        expected.extend_from_slice(&[0x05, 0x06, 0x07, 0x08]); // Preimage Length (u32 LE)
        assert_eq!(bytes, expected);
        assert_eq!(bytes.len(), 4 + 32 + 4);
    }

    #[test]
    fn preimage_announcement_roundtrip() {
        let p = PreimageAnnouncement {
            service_id: 9,
            hash: [0x24; 32],
            length: 1000,
        };
        let bytes = p.encode();
        let mut input: &[u8] = &bytes[..];
        let decoded = PreimageAnnouncement::decode(&mut input).unwrap();
        assert!(input.is_empty());
        assert_eq!(decoded, p);
    }

    #[test]
    fn preimage_announcement_truncated_errs() {
        // Only the service id.
        let mut input: &[u8] = &[0x01, 0x02, 0x03, 0x04];
        assert!(PreimageAnnouncement::decode(&mut input).is_err());
        // Missing the trailing length.
        let mut bytes = vec![0x01, 0x02, 0x03, 0x04];
        bytes.extend_from_slice(&[0x42; 32]);
        bytes.extend_from_slice(&[0x05, 0x06]);
        let mut input: &[u8] = &bytes[..];
        assert!(PreimageAnnouncement::decode(&mut input).is_err());
    }

    // --- CE 143: Preimage request/reply -------------------------------------

    #[test]
    fn preimage_request_vector() {
        let r = PreimageRequest { hash: [0x13; 32] };
        assert_eq!(r.encode(), vec![0x13; 32]);
    }

    #[test]
    fn preimage_reply_vector_raw_bytes() {
        // `Preimage = [u8]` (simple.md:736): raw bytes, no length prefix.
        let reply = PreimageReply {
            preimage: vec![0xde, 0xad, 0xbe, 0xef],
        };
        assert_eq!(reply.encode(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn preimage_roundtrips() {
        let req = PreimageRequest { hash: [0x31; 32] };
        let bytes = req.encode();
        let mut input: &[u8] = &bytes[..];
        assert_eq!(PreimageRequest::decode(&mut input).unwrap(), req);
        assert!(input.is_empty());

        let reply = PreimageReply {
            preimage: vec![0x01, 0x02, 0x03],
        };
        let bytes = reply.encode();
        let mut input: &[u8] = &bytes[..];
        assert_eq!(PreimageReply::decode(&mut input).unwrap(), reply);
        assert!(input.is_empty());
    }

    #[test]
    fn preimage_request_truncated_errs() {
        // Hash truncated to 16 bytes.
        let mut input: &[u8] = &[0x13; 16];
        assert!(PreimageRequest::decode(&mut input).is_err());
    }

    // --- CE 144: Audit announcement ------------------------------------------

    fn sample_guarantee() -> Guarantee {
        Guarantee {
            slot: 0x1020_3040,
            signatures: vec![
                GuaranteeSignature {
                    validator_index: 0x0001,
                    signature: sig64(0x60),
                },
                GuaranteeSignature {
                    validator_index: 0x0002,
                    signature: sig64(0x61),
                },
            ],
        }
    }

    /// The initial-tranche announcement, byte for byte.
    ///
    /// Hand-built rather than round-tripped: a test that encodes with the
    /// same code it decodes with agrees with itself whatever the shape is,
    /// which is how the superseded layout survived a spec revision here
    /// (`findings.md` §28).
    #[test]
    fn initial_announcement_vector() {
        let ann = Announcement {
            header_hash: HeaderHash::from([0x55; 32]),
            validator_index: 0x0102,
            intent: Intent::Initial,
            signature: sig96(0x50),
        };
        let mut expected = vec![0x55; 32]; // Header Hash
        expected.extend_from_slice(&0x0102u16.to_le_bytes()); // Validator Index
        expected.push(0x00); // Intent: initial tranche, no core
        expected.extend_from_slice(&sig96(0x50)); // Bandersnatch Signature
        assert_eq!(ann.encode(), expected);
        assert_eq!(expected.len(), 32 + 2 + 1 + 96);
    }

    /// A later tranche names one core, and nothing else changes.
    #[test]
    fn later_announcement_vector_carries_one_core() {
        let ann = Announcement {
            header_hash: HeaderHash::from([0x55; 32]),
            validator_index: 0x0102,
            intent: Intent::Later(0x0304),
            signature: sig96(0x51),
        };
        let mut expected = vec![0x55; 32];
        expected.extend_from_slice(&0x0102u16.to_le_bytes());
        expected.push(0x01); // Intent: later tranche
        expected.extend_from_slice(&0x0304u16.to_le_bytes()); // Core Index
        expected.extend_from_slice(&sig96(0x51));
        assert_eq!(ann.encode(), expected);
        assert_eq!(expected.len(), 32 + 2 + 1 + 2 + 96);
    }

    /// The tranche is never on the wire, in either kind.
    ///
    /// The row this guards is the one the old shape got wrong: it sent a
    /// `Tranche` byte that a conforming recipient does not read, deriving
    /// the tranche from the signature's VRF output instead
    /// (`simple.md:769-771`).
    #[test]
    fn no_announcement_declares_a_tranche() {
        for (intent, len) in [(Intent::Initial, 131), (Intent::Later(0), 133)] {
            let ann = Announcement {
                header_hash: HeaderHash::from([0; 32]),
                validator_index: 0,
                intent,
                signature: sig96(0),
            };
            assert_eq!(
                ann.encode().len(),
                len,
                "an announcement carries the header hash, the validator index, the intent \
                 and the signature, and nothing else"
            );
        }
    }

    #[test]
    fn announcement_roundtrips() {
        for intent in [Intent::Initial, Intent::Later(0x0304)] {
            let ann = Announcement {
                header_hash: HeaderHash::from([0x55; 32]),
                validator_index: 0x0102,
                intent,
                signature: sig96(0x50),
            };
            let bytes = ann.encode();
            let mut input: &[u8] = &bytes[..];
            assert_eq!(Announcement::decode(&mut input).unwrap(), ann);
            assert!(input.is_empty());
        }
    }

    #[test]
    fn announcement_rejects_an_unknown_intent() {
        let mut bytes = vec![0x55; 32];
        bytes.extend_from_slice(&0x0102u16.to_le_bytes());
        bytes.push(0x02); // neither 0 nor 1
        bytes.extend_from_slice(&sig96(0x50));
        assert!(Announcement::decode(&mut &bytes[..]).is_err());
    }

    #[test]
    fn announcement_truncated_errs() {
        let ann = Announcement {
            header_hash: HeaderHash::from([0x55; 32]),
            validator_index: 0x0102,
            intent: Intent::Later(0x0304),
            signature: sig96(0x50),
        };
        let bytes = ann.encode();
        for cut in [1usize, 40, bytes.len() - 1] {
            assert!(
                Announcement::decode(&mut &bytes[..cut]).is_err(),
                "a short announcement must not decode: cut at {cut}"
            );
        }
    }

    /// The message is a vector, so several announcements ride one message
    /// (`simple.md:773`).
    #[test]
    fn announcements_batch_into_one_message() {
        let anns = vec![
            Announcement {
                header_hash: HeaderHash::from([0x55; 32]),
                validator_index: 1,
                intent: Intent::Initial,
                signature: sig96(0x50),
            },
            Announcement {
                header_hash: HeaderHash::from([0x56; 32]),
                validator_index: 2,
                intent: Intent::Later(3),
                signature: sig96(0x51),
            },
        ];
        let bytes = anns.encode();
        assert_eq!(bytes[0], 0x02, "compact(2) prefixes the vector");
        assert_eq!(Vec::<Announcement>::decode(&mut &bytes[..]).unwrap(), anns);
    }

    /// A positive judgment, byte for byte. No guarantee is carried
    /// (`simple.md:811`).
    #[test]
    fn valid_judgment_vector() {
        let judgment = Judgment {
            epoch_index: 0x1020_3040,
            validator_index: 0x0102,
            validity: Validity::Valid,
            report_hash: [0x99; 32],
            signature: sig64(0x70),
        };
        let mut expected = 0x1020_3040u32.to_le_bytes().to_vec();
        expected.extend_from_slice(&0x0102u16.to_le_bytes());
        expected.push(0x01); // Validity: valid
        expected.extend_from_slice(&[0x99; 32]);
        expected.extend_from_slice(&sig64(0x70));
        assert_eq!(judgment.encode(), expected);
    }

    /// A negative judgment carries its guarantees **inside** the validity
    /// discriminator, so they sit before the work-report hash rather than
    /// after the signature.
    ///
    /// This is the byte order the old shape got wrong: it appended the
    /// guarantee as a separate trailing message (`findings.md` §28). The
    /// assertion below is on the position, not just the presence.
    #[test]
    fn invalid_judgment_carries_the_guarantee_before_the_report_hash() {
        let judgment = Judgment {
            epoch_index: 0x1020_3040,
            validator_index: 0x0102,
            validity: Validity::Invalid(sample_guarantee()),
            report_hash: [0x99; 32],
            signature: sig64(0x70),
        };
        let mut expected = 0x1020_3040u32.to_le_bytes().to_vec();
        expected.extend_from_slice(&0x0102u16.to_le_bytes());
        expected.push(0x00); // Validity: invalid
        expected.extend_from_slice(&sample_guarantee().encode()); // then the guarantee
        expected.extend_from_slice(&[0x99; 32]); // and only then the hash
        expected.extend_from_slice(&sig64(0x70));
        assert_eq!(judgment.encode(), expected);

        let guarantee_len = sample_guarantee().encode().len();
        let hash_at = 4 + 2 + 1 + guarantee_len;
        assert_eq!(
            &judgment.encode()[hash_at..hash_at + 32],
            &[0x99; 32],
            "the work-report hash follows the guarantee, not the validity byte"
        );
    }

    #[test]
    fn judgment_roundtrips() {
        for validity in [Validity::Valid, Validity::Invalid(sample_guarantee())] {
            let judgment = Judgment {
                epoch_index: 7,
                validator_index: 5,
                validity,
                report_hash: [0xab; 32],
                signature: sig64(0x71),
            };
            let bytes = judgment.encode();
            let mut input: &[u8] = &bytes[..];
            assert_eq!(Judgment::decode(&mut input).unwrap(), judgment);
            assert!(input.is_empty());
        }
    }

    #[test]
    fn judgment_rejects_an_unknown_validity_byte() {
        let mut bytes = 7u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&5u16.to_le_bytes());
        bytes.push(0x02); // neither 0 nor 1
        bytes.extend_from_slice(&[0xab; 32]);
        bytes.extend_from_slice(&sig64(0x71));
        assert!(Judgment::decode(&mut &bytes[..]).is_err());
    }

    #[test]
    fn judgment_truncated_errs() {
        for validity in [Validity::Valid, Validity::Invalid(sample_guarantee())] {
            let bytes = Judgment {
                epoch_index: 7,
                validator_index: 5,
                validity,
                report_hash: [0xab; 32],
                signature: sig64(0x71),
            }
            .encode();
            assert!(Judgment::decode(&mut &bytes[..bytes.len() - 1]).is_err());
        }
    }

    /// Judgments from different auditors, reports and epochs batch together
    /// (`simple.md:814-815`).
    #[test]
    fn judgments_batch_into_one_message() {
        let judgments = vec![
            Judgment {
                epoch_index: 7,
                validator_index: 5,
                validity: Validity::Valid,
                report_hash: [0xab; 32],
                signature: sig64(0x71),
            },
            Judgment {
                epoch_index: 8,
                validator_index: 6,
                validity: Validity::Invalid(sample_guarantee()),
                report_hash: [0xcd; 32],
                signature: sig64(0x72),
            },
        ];
        let bytes = judgments.encode();
        assert_eq!(bytes[0], 0x02, "compact(2) prefixes the vector");
        assert_eq!(Vec::<Judgment>::decode(&mut &bytes[..]).unwrap(), judgments);
    }
}
