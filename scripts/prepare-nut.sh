#!/usr/bin/env bash
# Prepares the two binaries a real-surface run needs:
#
#   third_party/bin/polkajam    the node under test
#   third_party/bin/m2-oracle   the reference oracle the run grades against
#
# Both are built from one polkajam revision. That is the whole basis for
# trusting a verdict: the oracle's answers are only a standard to grade the
# node by if the two are the same engine. The oracle states the revision it
# was built from in its handshake, and the runner checks it.
#
# The revision is read from oracle/Cargo.toml rather than repeated here --
# a second copy is a second thing to forget to update. The oracle's manifest
# is the source rather than the workspace root's because it is the one that
# survives: the workspace is on its way to having no polkajam dependency at
# all, and the oracle will still have one.
#
# Everything lives in third_party/ which is gitignored: nothing from polkajam
# is committed to this repository.
set -euo pipefail
cd "$(dirname "$0")/.."

REPO=${POLKAJAM_REPO:-ssh://git@github.com/paritytech/polkajam.git}
DEST=third_party/polkajam
BIN=third_party/bin

PINNED=$(sed -n 's/^jam-node = .*rev = "\([0-9a-f]\{40\}\)".*/\1/p' oracle/Cargo.toml | head -1)
if [ -z "$PINNED" ]; then
    echo "could not read the polkajam revision from oracle/Cargo.toml" >&2
    exit 1
fi

# While the workspace still carries its own polkajam dependencies, the two
# pins have to agree: the reference would otherwise be built from one engine
# and the oracle from another, and nothing downstream would notice.
WORKSPACE_PIN=$(sed -n 's/^jam-node = .*rev = "\([0-9a-f]\{40\}\)".*/\1/p' Cargo.toml | head -1)
if [ -n "$WORKSPACE_PIN" ] && [ "$WORKSPACE_PIN" != "$PINNED" ]; then
    echo "the workspace pins polkajam at ${WORKSPACE_PIN} and oracle/Cargo.toml" >&2
    echo "pins ${PINNED}. Re-pin both before building." >&2
    exit 1
fi

REV=${POLKAJAM_REV:-$PINNED}
if [ "$REV" != "$PINNED" ]; then
    echo "WARNING: building the NUT from ${REV}, while the reference oracle is" >&2
    echo "         pinned to ${PINNED}. The node under test and the engine that" >&2
    echo "         grades it will be different builds." >&2
fi

if [ -d "$DEST/.git" ]; then
    echo "reusing existing checkout at $DEST"
    git -C "$DEST" fetch --quiet origin "$REV" 2>/dev/null || git -C "$DEST" fetch --quiet origin
    git -C "$DEST" checkout --quiet --force "$REV"
    git -C "$DEST" clean -qfd
else
    mkdir -p third_party
    rm -rf "$DEST"
    git clone --quiet "$REPO" "$DEST"
    git -C "$DEST" checkout --quiet --force "$REV"
fi
echo "polkajam at $REV"

# polkavm chooses a sandbox at run time, and the Linux one needs userfaultfd.
# Some hosts deny that to unprivileged processes (vm.unprivileged_userfaultfd=0)
# and offer no sudo, which leaves no way to execute a work package. Building the
# generic sandbox in gives POLKAVM_SANDBOX=generic something to select; it is
# off by default because it is slower and most hosts do not need it.
#
# This is a one-line feature flip, made here rather than carried in patches/.
# A patch file pins the polkavm version in its own context and so rots at every
# re-pin -- silently, since the script that applied it was never run in CI.
# That is exactly how the two patches this replaced came to be both stale and
# malformed.
if [ "${POLKAJAM_GENERIC_SANDBOX:-0}" = "1" ]; then
    # `|| true`: grep exits 1 when it matches nothing, and under `set -o pipefail`
    # that would abort the script before the explanation below is printed.
    line=$(grep -n '^polkavm = {.*features = \[\] *}' "$DEST/Cargo.toml" | head -1 | cut -d: -f1 || true)
    if [ -z "$line" ]; then
        echo "no polkavm dependency line to patch in $DEST/Cargo.toml -- upstream" >&2
        echo "changed its shape; update this script rather than skipping the flip" >&2
        exit 1
    fi
    sed -i "${line}s/features = \[\]/features = [\"generic-sandbox\"]/" "$DEST/Cargo.toml"
    echo "enabled polkavm's generic sandbox; run the NUT with POLKAVM_SANDBOX=generic"
fi

cargo build --release --manifest-path "$DEST/Cargo.toml" --bin polkajam

# The oracle is outside the workspace and has its own lockfile and target
# directory, so it is a separate build. It is pinned to $PINNED by its own
# manifest; the agreement with the checkout above was already checked.
echo
echo "building the oracle at $PINNED"
cargo build --release --manifest-path oracle/Cargo.toml --bin m2-oracle

mkdir -p "$BIN"
cp -f "$DEST/target/release/polkajam" "$BIN/polkajam"
cp -f oracle/target/release/m2-oracle "$BIN/m2-oracle"

# Fail here rather than three hours into a run: a binary that cannot say
# which revision it is cannot be trusted to grade one.
STAMPED=$("$BIN/m2-oracle" --revision)
if [ "$STAMPED" != "$PINNED" ]; then
    echo "the oracle reports revision ${STAMPED}, not the pinned ${PINNED}" >&2
    exit 1
fi

echo
echo "both binaries are in $BIN, built from $PINNED:"
echo "  $BIN/polkajam"
echo "  $BIN/m2-oracle"
echo "add it to PATH before a real-surface run:"
echo "  export PATH=\"\$PWD/$BIN:\$PATH\""
