# Running the harness against your node

This is the operator's guide: what to install, how to point the suite at a node
that is not polkajam, and how to read what comes back. `DESIGN.md` says what the
harness is for, `M2-status.md` records what it has found, and `findings.md`
carries the evidence behind every claim either of them makes.

**The harness launches the node itself.** There is no mode that attaches to a
node you already have running: the runner writes the chain spec and the node's
keys, starts it, grades it, and on an N7-only run kills and restarts it. So
"pointing the suite at your node" means giving the runner a command or an image
it can start.

---

## 1. What you need

```sh
cargo build --workspace
./scripts/prepare-nut.sh      # third_party/bin/{polkajam,m2-oracle}
```

`prepare-nut.sh` builds two binaries from **one** polkajam revision, pinned in
`oracle/Cargo.toml`:

- `m2-oracle` — the reference engine. The harness needs it whatever node you are
  grading: it is what builds the chain the node is tested against, and what
  answers "what should this block have looked like". Set `M2_ORACLE_BIN` to
  point at one you built elsewhere.
- `polkajam` — only the node under test for a polkajam run. You do not need it
  to grade your own node, but a first run against it is the cheapest way to
  confirm your checkout works.

Nothing from polkajam is committed here; `third_party/` is gitignored.

**The oracle is polkajam.** A genuine state-transition disagreement between your
node and polkajam surfaces as an N1 state-root failure. That is expected, and it
is why a client should be green on M1 (`davxy/jam-conformance`) before trying
M2.

---

## 2. Three runs, in order

```sh
# 1. No node, no network: the harness against its own expectations.
cargo run -p m2-runner -- --preset mock --dry-run --session-dir /tmp/m2-dry
#    Expect exit 0 and every row a hard pass. If this fails, the harness is
#    broken, not your node.

# 2. A real node you did not write, so a failure is informative.
PATH="$PWD/third_party/bin:$PATH" \
cargo run -p m2-runner -- --preset polkajam --session-dir sessions/pj-1 \
  --seed 1 --validator-index 5 --base-port 40000 \
  --startup-timeout 60 --observe-secs 300 --lanes n0,n1,n2,n3,n4,n6,n7

# 3. Your node.
JAM_M2_IMAGE=ghcr.io/<team>/<client>:<tag> \
cargo run -p m2-runner -- --preset docker --session-dir sessions/<team>-1 \
  --seed 1 --validator-index 5 --base-port 40000 \
  --startup-timeout 60 --observe-secs 300 --lanes n0,n1,n2
```

Start at `--lanes n0,n1,n2` and add lanes as they pass. A lane left out is
neither graded nor exercised, so an early run stays short and its failures stay
readable.

---

## 3. Launching your node

### The docker preset

Host networking, because QUIC is UDP and the node must be able to *initiate*
connections under the preferred-initiator rule. The image comes from the
runner's own `JAM_M2_IMAGE` (default `polkajam`), and the container is given:

| Variable | Meaning |
|---|---|
| `JAM_M2=1` | enable M2 conformance mode |
| `JAM_M2_SPEC` | path to `spec-m2.json`, the M2-standard spec |
| `JAM_M2_ED25519_SECRET` | hex, 32 bytes |
| `JAM_M2_BANDERSNATCH_SECRET` | hex, 32 bytes |
| `JAM_M2_LISTEN` | `[::]:<port>` |
| `JAM_M2_PUBLIC_ADDR` | `<ipv6>:<port>`, as carried in genesis metadata |
| `JAM_M2_DATA_PATH` | writable state directory |
| `JAM_M2_LOG_LEVEL` | log level |

**This preset has never been run against a real image.** Only its command string
is under test; the polkajam preset is the only launch path with live evidence
behind it (`M2-status.md` §5.7). Expect to be its first user and budget for a
round of fixes.

### A local binary instead

`preset_polkajam` in `crates/m2-runner/src/launch.rs` is the worked example of a
command template. The placeholders are `{spec}`, `{m2_spec}`,
`{ed25519_secret}`, `{bandersnatch_secret}`, `{listen}`, `{public_addr}`,
`{data}` and `{log_level}`; the command is split on whitespace and spawned
directly, with no shell, so no quoting, globbing or variable expansion.

### What the harness hands over

Written into the session directory before launch:

| File | Contents |
|---|---|
| `spec-m2.json` | the M2-standard spec: `parameters`, `genesis_header`, `genesis_state` (21 key/values), `bootnodes` |
| `spec.json` | the same chain in polkajam's native format |
| `nut_ed25519.hex`, `nut_bandersnatch.hex` | the node's secrets, hex |
| `seed.seed` | the same Ed25519 secret as raw bytes, polkajam's format, mode 0600 |

Secrets are handed over explicitly rather than as one seed, so no team is forced
onto a derivation scheme. Validator metadata in genesis is
`PeerAddr { ip: [u8;16], port: u16 LE }` (18 bytes, as in jam-np), then the
P-256 id, then filler; IPv4 loopback is written IPv4-mapped
(`::ffff:127.0.0.1`).

---

## 4. The knobs that matter

| Flag | What it does |
|---|---|
| `--lanes` | which lanes to grade; default `n0,n1,n2`. N3, N4, N6 and N7 are opt-in by name. N5 is refused — it is parked on polkajam's CE 144/145 redesign (`findings.md` §32) |
| `--observe-secs` | the observation window. 90 is the floor; 300 is what a full run wants. Too short and rules go unexercised and report soft *not exercised* rows instead of verdicts |
| `--validator-index` | which validator index the node takes. Default 5, **not 0**: index 0 is degenerate for the preferred-initiator rule, so N0's initiation rows can never fire there |
| `--base-port` | validator `i` listens on `base + i`, so the node is on `base + validator_index` and the five emulated validators take the rest of `base ..= base + 5`. Six UDP ports, all free |
| `--seed` | derives keys and the spec. The same seed gives the same chain |
| `--startup-timeout` | seconds to wait for the node's QUIC port. 60 is sane for a container |
| `--compare <dir>` | read finished sessions instead of making one, and print the rows that answered differently |

**N7 is opt-in for a stronger reason than the others.** It deliberately sends
malformed streams, and a node that answers one by closing the connection takes
every other protocol on that connection down with it (`findings.md` §30). The
provocations go out on connections of their own so the fallout is contained.

**N7 kills and restarts the node only when N7 is the only lane selected**
(`--lanes n7`). In a mixed run the restart row reports itself unexercised; the
flood runs either way.

---

## 5. Reading the result

| Exit code | Meaning |
|---|---|
| 0 | every hard check passed, no startup failure |
| 1 | a hard check failed, or the node did not come up in time |
| 2 | internal harness error |

```
<session-dir>/
  report/report.md        coverage table and findings, for a human
  report/findings.json    the same findings, for a machine
  traces/jamnp.bin        the full wire trace
  traces/jamnp.json       the decoded trace
  traces/{tx,rx}/         per-message frames
  logs/nut.{stdout,stderr}.log
```

Every finding cites the trace, so a verdict you disagree with can be re-derived
from the wire rather than argued about.

**Three results, not two.** A row is a *hard* verdict where JAMNP-S states a
rule, a *soft* one where it does not — reported loudly and left to the spec's
author — and `*_not_exercised` where the run never reached the thing the row
grades. The third is not a pass: it is the harness declining to grade something
it did not exercise, and a report full of them means the window was too short or
the lane was not reached, not that the node did well.

A node that implements part of the surface still gets a useful report. What the
run exercises, in order — TLS and ALPN, the preferred-initiator rule, builder
slots, UP 0, CE 128/129, authoring, Safrole tickets, then the opt-in lanes — is
listed in `M2-status.md` §5.6; read the report top-down, because a node that
fails an early stage produces a run that cannot reach the later ones.

### Rotating the index

The node's index decides what it is asked to do, and a row can pass at one index
by luck. Run the same seed at several indices and compare:

```sh
for i in 0 1 2 3 4 5; do
  cargo run -p m2-runner -- --preset docker --validator-index "$i" \
    --session-dir "sessions/rot-$i" --seed 1 --observe-secs 300 --lanes n0,n1,n2
done
cargo run -p m2-runner -- --compare sessions/rot-0 --compare sessions/rot-1 # ...
```

Each report records the index it ran at, so the comparison takes it from the
file rather than from you. This is how `findings.md` §39 was found.

---

## 6. When it goes wrong

| Symptom | Where to look |
|---|---|
| The node never comes up | `logs/nut.stderr.log`, then the spec it was handed. A node that cannot parse `spec-m2.json` fails here |
| Every N0 row fails | the certificate: Ed25519, self-signed, exactly one SAN carrying `e` + base32 of the public key, and the key must match the one in genesis |
| ALPN rows fail | the protocol name is `jamnp-s/1/<first 8 hex of the genesis header hash>`, and a mismatched version must be **refused** |
| The node is up but nothing is graded | the window, or the lane set. Check `--observe-secs` first, and that the lane you care about is named |
| Rows pass that should not | run the same seed at another `--validator-index` and `--compare` the two |
| Everything looks wrong at once | run the dry run again. If it fails, the problem is this checkout |

---

## 7. Limits worth knowing before you start

- **The docker preset is untried live** (§3 above).
- **The oracle is polkajam**, so a state-transition disagreement reads as an N1
  failure (§1 above).
- **There is no capability handshake**, so the report cannot tell *not attempted*
  from *not exercised*.
- **N5 is not implemented** and is refused rather than silently skipped.
- **Three of N7's nine rows are blocked** on things the reference engine cannot
  do — author a fork, follow a validator-set change (`findings.md` §38, §40).

`M2-status.md` §5.7 keeps the full list, including the gaps that have since been
closed and what each one cost before it was.
