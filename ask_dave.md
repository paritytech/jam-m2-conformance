# Is the work-package size cap binding on the guarantor?

A question about `jam-np` `simple.md` that the M2 conformance harness cannot
settle by measuring. Two of its checks rest on an interpretation the spec
does not state, and they are Hard — so whichever way this is answered
changes whether a conforming node is failed.

Recorded in full as `findings.md` §4; this is the self-contained version.

## The question

`simple.md:362-364`, on CE 133:

> The initial message `Core Index ++ Work-Package` **should be limited** to
> `2 + (200 * 1024)` bytes. This ensures that Guarantors can not be forced
> to download huge work packages, before they can check that the
> Work-Package is actually authorized.

`simple.md:383` says the same thing for CE 146's `Work-Package` message,
with the same rationale and the same `should be limited` wording, against a
cap of `200 * 1024`.

Three things about that sentence drive the question:

1. It is a **should**, not a must.
2. It is phrased as a constraint on **the message** — that is, on the
   builder sending it — not as a duty on the guarantor receiving it.
3. The rationale is that guarantors *cannot be forced to download* huge
   packages. That is a protection offered to guarantors, which reads more
   like a licence to refuse than an obligation to.

So:

1. **Is the cap normative on the receiver, or only on the sender?**
2. **If it binds the receiver, what is a guarantor meant to do** — reset the
   stream, or read and discard? The rationale argues for resetting before
   the body arrives, but the spec does not say.

## What the harness currently asserts

`DESIGN.md` §11 N3's fault column reads:

```
first message > 2+200*1024 bytes -> reset :362-364
```

That is an interpretation this project made, not a quotation. Two checks
depend on it:

| check | asserts |
|---|---|
| `n3_ce133_oversized_reset` | an over-cap CE 133 first message is answered with a stream reset |
| `n3_ce146_oversized_reset` | an over-cap CE 146 work-package message is answered with a stream reset |

Both are **Hard**. They are deliberately consistent with each other rather
than with either answer: whatever settles one settles both, and if the cap
binds only the sender then both are wrong, not one.

## What was measured

Against polkajam, `b1ea8aca4`. The harness puts a deliberately oversized
first message on the wire — **205,076 bytes against the 204,802-byte cap**,
read off the trace rather than inferred. The node accepts it and does not
reset the stream. Both checks fail.

Reproduced across two pins and both protocols:

| when | pin | what failed |
|---|---|---|
| 2026-11-15 | earlier pin | `n3_ce133_oversized_reset` |
| 2026-11-18 | `b1ea8aca4` | `n3_ce133_oversized_reset` and `n3_ce146_oversized_reset` |

The CE 146 failure was predicted by reading the spec before the row existed,
and then observed, which is some evidence the two really are one question.

## What polkajam does, which is not "no limit"

Its CE 133 handler reads the first message with `read_decoded`
(`crates/node/src/chain/guarantors/stream_receiver.rs:326`):

```rust
let WorkPackageWithCore { core, package } = rx.read_decoded().await?;
```

and `read_decoded` caps the read at the type's `max_encoded_len`
(`crates/node/src/net/stream.rs:503`):

```rust
pub async fn read_decoded<D: Decode + MaxEncodedLen>(&mut self) -> Result<D, StreamErr> {
    let message = self
        .read(D::max_encoded_len().try_into().expect("Useless max_encoded_len"))
        .await?;
```

A `WorkPackage`'s `max_encoded_len` is far above 200 KiB. So the node is
bounded — it derives its bound from the type rather than from the spec's
number. That is a defensible reading of a *should*, which is why this is a
question rather than a bug report.

## What each answer implies

| answer | what changes |
|---|---|
| binds the sender only | both rows are wrong. Drop them, or make them Soft and reword them as observations about the builder's side |
| binds the receiver, reset expected | both rows are right as written, and this is a polkajam defect worth filing |
| binds the receiver, read-and-discard allowed | both rows need rewriting to assert "did not act on it" rather than "reset the stream", which is a harder thing to observe from outside |

A fourth possibility worth naming: that the number is advisory and the real
requirement is only that a guarantor bound the read *somehow*, in which case
polkajam already conforms and the rows should assert the existence of a
bound rather than its value.

## Why it matters beyond one node

Every row a node can cause in the harness's N3 and N4 lanes has now been
shown to fail against a deliberately broken client, so the coverage bar for
making those lanes part of a default run is met. These two rows are what
keeps them opt-in: defaulting them would fail every third-party node that
takes the permissive reading, on a **should**, which is the kind of wrong
verdict the project's findings discipline exists to prevent.
