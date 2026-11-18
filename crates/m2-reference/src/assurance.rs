//! CE 141 availability assurances: signing the harness's own, and checking
//! the node's.
//!
//! The only part of the reference surface that needs no oracle. An assurance
//! is an `AvailabilityStatement` -- an anchor and a bitfield -- hashed and
//! signed with an Ed25519 key under the `jam_available` context, and every
//! piece of that lives in `jam-std-common`: the statement, its hash, the
//! signing context and the keys. Both sides of the socket would be calling
//! the same library code, so a round trip would add latency and no agreement.
//!
//! That is the test to apply before adding a message rather than a function:
//! not "does the engine know how" but "is there a second implementation to
//! diverge from". Here there is not.

use jam_std_common::{
    ed25519, AvailabilityAssurance, AvailabilityBitfield, AvailabilityStatement, SecretKeyset,
    ValSignature,
};
use jam_types::HeaderHash;
use jamnp_s::codec::ce141_145::Assurance;

/// Why an assurance was refused.
///
/// Kept apart from a bare `false` because the N4 lane grades the reasons
/// separately: `simple.md:675-695` makes a wrong anchor, a bad signature and
/// a bit set for an empty core three different faults, and a node that gets
/// one wrong is not the same node as one that gets another wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssuranceFault {
    /// The bitfield is not `ceil(core_count / 8)` bytes.
    BitfieldLength { got: usize, want: usize },
    /// A bit is set beyond the active core count.
    BitBeyondCores { bit: u16, cores: u16 },
    /// The anchor names no block the harness has seen.
    ///
    /// A set rather than one expected hash. Which block a node assures is
    /// its own choice -- `simple.md:679-680` puts the assurance roughly two
    /// seconds before a slot, and the head at that instant is not something
    /// the harness can name in advance. What it can say is that the anchor
    /// must be a block that exists, and a node assuring one nobody authored
    /// is assuring nothing.
    WrongAnchor { got: [u8; 32], known: usize },
    /// The signature does not verify against that validator's key.
    BadSignature,
}

/// Bytes a bitfield occupies on the wire, under the parameters in force.
///
/// Asked of the engine's own type rather than computed as
/// `ceil(core_count / 8)`. The two agree today, and a harness carrying its
/// own copy of that arithmetic is one re-pin away from grading a node
/// against a width the engine stopped using.
pub fn bitfield_len() -> usize {
    jam_types::Encode::encode(&AvailabilityBitfield::new()).len()
}

/// Sign an assurance for `anchor` asserting that `cores` are available.
///
/// Validator `index` signs with `SecretKeyset::trivial(index)`, which is the
/// key the genesis spec carries for it -- the same derivation `keygen` uses
/// for the NUT's own secret, so a node and the harness agree about who holds
/// what.
pub fn sign_assurance(index: u16, anchor: [u8; 32], cores: &[u16]) -> Assurance {
    let mut bitfield = AvailabilityBitfield::new();
    for core in cores {
        bitfield.set(*core);
    }
    let statement = AvailabilityStatement {
        anchor: HeaderHash::from(anchor),
        bitfield,
    };
    let keyset = SecretKeyset::trivial(u32::from(index));
    let signature = keyset
        .ed25519
        .sign(&ed25519::Message::Assurance(statement.hash()));
    Assurance {
        anchor: statement.anchor,
        // The wire carries the bitfield as bytes; the statement that was
        // signed carries it as the engine's type. They are the same bytes,
        // and taking them from the statement rather than rebuilding them is
        // what keeps that true.
        bitfield: jam_types::Encode::encode(&statement.bitfield),
        signature: signature.0.to_bytes(),
    }
}

/// Check an assurance the node sent: shape, anchor, and signature.
///
/// `known_anchors` is every block the harness has seen the node on. The
/// active core count comes from the parameters in force, and the validator's
/// public key from its index, the same way [`sign_assurance`] takes the
/// secret.
pub fn check_assurance(
    assurance: &Assurance,
    index: u16,
    known_anchors: &[[u8; 32]],
) -> Result<(), AssuranceFault> {
    let cores = jam_types::core_count();
    let want = bitfield_len();
    if assurance.bitfield.len() != want {
        return Err(AssuranceFault::BitfieldLength {
            got: assurance.bitfield.len(),
            want,
        });
    }
    // A bit past the active cores claims availability for a core that does
    // not exist, which `simple.md` lists as its own exclusion.
    for bit in cores..(want as u16 * 8) {
        let byte = assurance.bitfield[bit as usize / 8];
        if byte & (1 << (bit % 8)) != 0 {
            return Err(AssuranceFault::BitBeyondCores { bit, cores });
        }
    }
    if !known_anchors.contains(&assurance.anchor.0) {
        return Err(AssuranceFault::WrongAnchor {
            got: assurance.anchor.0,
            known: known_anchors.len(),
        });
    }

    // Rebuilt rather than trusted: the signature is over the *statement*, so
    // checking it means forming the statement the signer should have formed
    // and seeing whether the signature matches that one.
    let statement = statement_of(assurance);
    let public = SecretKeyset::trivial(u32::from(index)).ed25519.public();
    public
        .verify(
            &ed25519::Message::Assurance(statement.hash()),
            &ed25519::Signature(assurance.signature.into()),
        )
        .map_err(|_| AssuranceFault::BadSignature)
}

/// The statement a wire assurance says it is signing.
///
/// Only the first `core_count()` bits are read, so the spare bits a
/// fixed-width bitfield leaves over cannot smuggle a core in. The caller
/// that cares whether any of them were set asks [`check_assurance`], which
/// refuses that separately rather than quietly dropping it here.
fn statement_of(assurance: &Assurance) -> AvailabilityStatement {
    let mut bitfield = AvailabilityBitfield::new();
    for core in 0..jam_types::core_count() {
        let byte = assurance
            .bitfield
            .get(core as usize / 8)
            .copied()
            .unwrap_or(0);
        if byte & (1 << (core % 8)) != 0 {
            bitfield.set(core);
        }
    }
    AvailabilityStatement {
        anchor: assurance.anchor,
        bitfield,
    }
}

/// The engine's form of an assurance that arrived over CE 141.
///
/// `index` comes from the connection rather than the message: CE 141 carries
/// no validator index, so who sent it is the receiver's own knowledge of
/// which peer it is talking to. That is also why a signature by somebody
/// else is a fault the receiver can catch at all -- the statement is sound
/// and only the hand that signed it is wrong.
///
/// No checking here. [`check_assurance`] is the check, and keeping the two
/// apart is what lets a simulated node pool an assurance it should have
/// refused.
pub fn as_received(assurance: &Assurance, index: u16) -> AvailabilityAssurance {
    AvailabilityAssurance {
        statement: statement_of(assurance),
        signature: ValSignature {
            val_index: index,
            signature: ed25519::Signature(assurance.signature.into()),
        },
    }
}

/// Which cores an assurance claims.
pub fn assured_cores(assurance: &Assurance) -> Vec<u16> {
    (0..jam_types::core_count())
        .filter(|core| {
            assurance
                .bitfield
                .get(*core as usize / 8)
                .is_some_and(|byte| byte & (1 << (core % 8)) != 0)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bitfield's width comes from the process-wide parameters, so a
    /// test that does not apply them is grading against the full set's 43
    /// bytes while the run it describes uses one.
    fn tiny() -> u16 {
        jam_types::ProtocolParameters::tiny()
            .apply()
            .expect("the tiny parameters are valid");
        jam_types::core_count()
    }

    #[test]
    fn an_assurance_verifies_against_the_key_that_signed_it() {
        let cores = tiny();
        let anchor = [0x5a; 32];
        let assurance = sign_assurance(3, anchor, &(0..cores).collect::<Vec<_>>());
        assert_eq!(check_assurance(&assurance, 3, &[anchor]), Ok(()));
        assert_eq!(assured_cores(&assurance), (0..cores).collect::<Vec<_>>());
    }

    /// The signature is over the statement, so a bitfield edited on the wire
    /// no longer matches -- which is the property the lane leans on to catch
    /// a node claiming a core it never assured.
    #[test]
    fn editing_the_bitfield_breaks_the_signature() {
        tiny();
        let anchor = [0x5a; 32];
        let mut assurance = sign_assurance(3, anchor, &[0]);
        assert_eq!(assured_cores(&assurance), vec![0]);
        assurance.bitfield[0] |= 0b10;
        assert_eq!(
            check_assurance(&assurance, 3, &[anchor]),
            Err(AssuranceFault::BadSignature)
        );
    }

    #[test]
    fn another_validators_key_does_not_verify() {
        tiny();
        let anchor = [0x5a; 32];
        let assurance = sign_assurance(3, anchor, &[0]);
        assert_eq!(
            check_assurance(&assurance, 4, &[anchor]),
            Err(AssuranceFault::BadSignature)
        );
    }

    #[test]
    fn a_wrong_anchor_is_named_before_the_signature_is_blamed() {
        tiny();
        let assurance = sign_assurance(3, [0x5a; 32], &[0]);
        // The signature is genuine; only the anchor is not the one expected.
        // Reporting `BadSignature` here would send a reader looking at the
        // node's keys instead of at which block it assured.
        assert_eq!(
            check_assurance(&assurance, 3, &[[0x5b; 32]]),
            Err(AssuranceFault::WrongAnchor {
                got: [0x5a; 32],
                known: 1,
            })
        );
    }

    #[test]
    fn a_bitfield_of_the_wrong_length_is_refused() {
        tiny();
        let anchor = [0x5a; 32];
        let want = bitfield_len();
        let mut assurance = sign_assurance(3, anchor, &[0]);
        assurance.bitfield.push(0);
        assert_eq!(
            check_assurance(&assurance, 3, &[anchor]),
            Err(AssuranceFault::BitfieldLength {
                got: want + 1,
                want
            })
        );
    }

    /// Two cores fit in one byte under tiny, so six spare bits ride along.
    /// A bit set in them claims a core that does not exist.
    #[test]
    fn a_bit_past_the_active_cores_is_refused() {
        let cores = tiny();
        assert!(cores < 8, "tiny leaves spare bits in the first byte");
        let anchor = [0x5a; 32];
        let mut assurance = sign_assurance(3, anchor, &[0]);
        assurance.bitfield[0] |= 1 << 7;
        assert_eq!(
            check_assurance(&assurance, 3, &[anchor]),
            Err(AssuranceFault::BitBeyondCores { bit: 7, cores })
        );
    }

    #[test]
    fn the_bitfield_width_is_the_engines_own() {
        let cores = tiny();
        assert_eq!(
            bitfield_len(),
            cores.div_ceil(8) as usize,
            "one byte per eight cores, as the GP says -- but read off the \
             engine's type rather than computed here"
        );
    }

    /// Any block the harness has seen will do. Pinning one expected anchor
    /// would fail an honest node for choosing a different head two seconds
    /// before its slot, which is its own choice to make.
    #[test]
    fn an_anchor_is_judged_against_every_block_the_harness_knows() {
        tiny();
        let anchor = [0x5a; 32];
        let assurance = sign_assurance(3, anchor, &[0]);
        let known = [[0x01; 32], anchor, [0x02; 32]];
        assert_eq!(check_assurance(&assurance, 3, &known), Ok(()));
        assert_eq!(
            check_assurance(&assurance, 3, &[]),
            Err(AssuranceFault::WrongAnchor {
                got: anchor,
                known: 0,
            }),
            "with no blocks to check against, nothing is anchored"
        );
    }

    /// The wire form and the engine form have to be the same assurance.
    ///
    /// Not a formality: [`as_received`] rebuilds the statement from the
    /// bitfield's bytes, and the signature on the wire was made over the
    /// statement the *sender* built. If the two readings of those bytes ever
    /// part company, a node pooling what the harness sent would carry an
    /// assurance whose signature does not verify, and its block would be
    /// refused for a reason nothing in the lane names.
    #[test]
    fn a_signed_assurance_survives_the_trip_into_the_engines_form() {
        let cores = tiny();
        let anchor = [0x5a; 32];
        let wire = sign_assurance(3, anchor, &(0..cores).collect::<Vec<_>>());
        let received = as_received(&wire, 3);
        assert_eq!(received.signature.val_index, 3);
        assert_eq!(received.statement.anchor.0, anchor);
        let public = SecretKeyset::trivial(3).ed25519.public();
        assert!(
            public
                .verify(
                    &ed25519::Message::Assurance(received.statement.hash()),
                    &received.signature.signature,
                )
                .is_ok(),
            "the statement the engine rebuilds must be the one that was signed"
        );
        assert_eq!(
            jam_types::Encode::encode(&received.statement.bitfield),
            wire.bitfield,
            "and its bitfield must be the bytes the wire carried"
        );
    }

    /// The index is the connection's, not the message's.
    #[test]
    fn the_validator_index_comes_from_the_caller() {
        tiny();
        let wire = sign_assurance(3, [0x5a; 32], &[0]);
        // CE 141 carries no index, so nothing in these bytes contradicts a
        // receiver that files them under the wrong validator -- which is
        // exactly how the bad-signature fault is posed.
        assert_eq!(as_received(&wire, 4).signature.val_index, 4);
    }

    /// Two readings of the same rule, and they have to agree.
    ///
    /// `jamnp-s` derives the width from the core count because it is the
    /// independent implementation a node is graded against; this module asks
    /// the engine's own type. Either one alone could drift without anything
    /// noticing, because the wire carries no length to contradict it -- and
    /// a signature read one byte out of place is a `BadSignature` finding
    /// against a node that did nothing wrong.
    #[test]
    fn the_wire_and_the_engine_agree_about_the_width() {
        tiny();
        assert_eq!(
            bitfield_len(),
            jamnp_s::codec::ce141_145::bitfield_len(),
            "the codec and the engine must measure the bitfield alike"
        );
        let assurance = sign_assurance(1, [0x5a; 32], &[0]);
        assert_eq!(
            jam_types::Encode::encode(&assurance).len(),
            32 + bitfield_len() + 64,
            "`Anchor ++ Bitfield ++ Signature`, with nothing in between"
        );
    }
}
