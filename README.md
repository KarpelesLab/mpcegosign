# mpcegosign

MPC threshold RSA signing for [EGo](https://github.com/edgelesssys/ego) SGX enclaves.

EGo's `ego sign` relies on a single RSA-3072 private key to sign enclaves. `mpcegosign` replaces this with threshold RSA signing where the private key is split into shares — a configurable number of parties must collaborate to produce a valid signature, but no single party can sign alone.

## Features

- **t-of-n threshold signing** — any t out of n parties can sign (e.g. 2-of-3, 4-of-5)
- **Interactive group-chat keygen** — parties exchange base64 messages via any platform (Slack, Signal, email, etc.)
- **Shares encrypted in transit** — X25519 ECDH + AES-256-GCM, safe to post in group chats
- **EGo-compatible** — delegates MRENCLAVE computation to `ego-oesign` for exact compatibility
- **Pure Go** — no dependencies beyond the Go standard library

## Install

```bash
go install github.com/magicaltux/mpcegosign@latest
```

## Quick Start

### 1. Key Generation Ceremony

All parties join a group chat. One person initiates, others join.

**Initiator** (decides the parameters):
```bash
mpcegosign keygen --parties 3 --threshold 2
```
This outputs an INIT message. Post it to the group chat.

**Each other party** (joiners):
```bash
mpcegosign keygen
```
Paste the INIT message when prompted. This outputs a JOIN message. Post it to the group chat.

**Back to the initiator**: paste each JOIN message as it appears. Once all parties have joined, the tool generates the key, splits it into threshold shares, and outputs a FINALIZE message. Post it to the group chat.

**Each joiner**: paste the FINALIZE message. The tool decrypts your share and saves it locally.

At the end, each party has:
- `share_N.json` — their secret key share (keep secure)
- `public.pem` — the shared RSA public key

Party numbers are auto-assigned: initiator is party 1, joiners are numbered in the order they join.

### 2. Signing an Enclave

There are two signing workflows: **all-at-once** (all shares on one machine) and **distributed** (each party signs independently).

#### All-at-once signing

When t or more parties can provide their shares to a single machine:

```bash
mpcegosign sign \
  --config enclave.json \
  --shares share_1.json,share_2.json \
  --out signed-binary
```

#### Distributed signing

When parties are on separate machines and cannot share their key files:

**Step 1 — Compute the hash** (any party with access to the unsigned binary):
```bash
mpcegosign hash \
  --config enclave.json \
  --pubkey public.pem \
  --out enclave.hash
```
Distribute `enclave.hash` to all signing parties.

**Step 2 — Each signing party computes their partial signature**:
```bash
mpcegosign partial-sign \
  --share share_1.json \
  --hash enclave.hash \
  --out partial_1.sig
```
For threshold shares, specify which subset of parties is signing:
```bash
mpcegosign partial-sign \
  --share share_1.json \
  --hash enclave.hash \
  --subset 1,3 \
  --out partial_1.sig
```
All signing parties must use the same `--subset`.

**Step 3 — Combine partial signatures**:
```bash
mpcegosign combine \
  --partials partial_1.sig,partial_3.sig \
  --hash enclave.hash \
  --enclave unsigned-binary \
  --out signed-binary
```

## Commands

### `keygen`

Interactive distributed key generation via group chat messages.

```
# Initiator: set number of parties and threshold
mpcegosign keygen --parties N [--threshold T] [--out-dir DIR]

# Joiner: join an existing ceremony
mpcegosign keygen [--out-dir DIR]
```

| Flag | Description |
|------|-------------|
| `--parties N` | Total number of parties. Only the initiator sets this. |
| `--threshold T` | Minimum parties required to sign. Default: N (all parties required). |
| `--out-dir DIR` | Directory to save share and public key. Default: current directory. |

If `--parties` is omitted, the tool runs as a joiner and waits for an INIT message.

**Threshold examples:**
| Scheme | Sub-shares per party | Total share sets |
|--------|---------------------|-----------------|
| 2-of-3 | 2 | 3 |
| 3-of-5 | 6 | 10 |
| 4-of-5 | 4 | 5 |
| 5-of-5 | 1 | 1 |

### `sign`

Sign an EGo enclave with all required shares on one machine.

```
mpcegosign sign --config enclave.json --shares s1.json,s2.json [--out output] [--ego /opt/ego]
```

| Flag | Description |
|------|-------------|
| `--config` | Path to EGo `enclave.json`. Default: `enclave.json`. |
| `--shares` | Comma-separated paths to key share files. Must provide at least threshold-many shares. |
| `--out` | Output path for signed binary. Default: overwrites the exe from config. |
| `--ego` | Path to EGo installation. Default: auto-detect (`EGO_PATH` env, then `/opt/ego`). |

### `hash`

Compute MRENCLAVE and produce a digest file for distributed signing.

```
mpcegosign hash --config enclave.json --pubkey public.pem [--out enclave.hash] [--ego /opt/ego]
```

| Flag | Description |
|------|-------------|
| `--config` | Path to EGo `enclave.json`. |
| `--pubkey` | Path to the shared RSA public key PEM. |
| `--out` | Output hash file path. Default: `enclave.hash`. |
| `--ego` | Path to EGo installation. |

### `partial-sign`

Compute a partial signature using one party's share.

```
mpcegosign partial-sign --share share.json --hash enclave.hash [--subset 1,2,4] [--out partial.sig]
```

| Flag | Description |
|------|-------------|
| `--share` | Path to this party's key share JSON. |
| `--hash` | Path to hash file from `hash` command. |
| `--subset` | Which subset of parties is signing. Required for threshold shares unless n-of-n. |
| `--out` | Output path. Default: `partial.sig`. |

### `combine`

Combine partial signatures into a signed enclave binary.

```
mpcegosign combine --partials p1.sig,p2.sig --hash enclave.hash --enclave binary [--out signed]
```

| Flag | Description |
|------|-------------|
| `--partials` | Comma-separated partial signature files. |
| `--hash` | Hash file from `hash` command. |
| `--enclave` | Path to unsigned enclave binary. |
| `--out` | Output path. Default: `<enclave>.signed`. |

### `signerid`

Compute MRSIGNER (SHA-256 of the RSA modulus in little-endian).

```
mpcegosign signerid --key public.pem
mpcegosign signerid --enclave signed-binary
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `EGO_PATH` | Path to EGo installation directory (e.g. `/opt/ego`). Used by `sign` and `hash` commands to locate `ego-oesign` for MRENCLAVE computation. Falls back to `/opt/ego` if unset. |

## How It Works

### Threshold RSA with e=3

SGX requires RSA-3072 with public exponent e=3. Standard threshold RSA (Shoup's scheme) requires gcd(e, n!) = 1, which fails for e=3 when n >= 3.

`mpcegosign` uses **redundant additive sharing** instead:
- For a t-of-n scheme, generate an independent additive share set for each of the C(n,t) possible t-party subsets
- Each party stores one sub-share per subset they belong to
- To sign, any t parties identify their common subset and combine their sub-shares

Additive sharing works because: `m^{d_1} * m^{d_2} * ... * m^{d_t} = m^{d_1 + d_2 + ... + d_t} = m^d mod N`

### SIGSTRUCT

The SGX SIGSTRUCT (1808 bytes) contains the enclave measurement, identity, and RSA signature. `mpcegosign` builds the SIGSTRUCT, computes SHA-256 over the two signed regions (bytes 0-127 and 900-1027), applies PKCS#1 v1.5 padding, and signs with the MPC-combined signature.

### MRENCLAVE

EGo uses a dual-image layout (ego-enclave runtime + Go payload binary) for measurement. `mpcegosign` delegates MRENCLAVE computation to `ego-oesign` to ensure exact compatibility with EGo's signing flow.

## File Formats

### Key Share (`share_N.json`)

```json
{
  "version": 2,
  "party_index": 1,
  "num_parties": 3,
  "threshold": 2,
  "modulus": "<base64 big-endian>",
  "public_exponent": 3,
  "shares": {
    "1,2": "<base64 sub-share>",
    "1,3": "<base64 sub-share>"
  }
}
```

### Hash File (`enclave.hash`)

```json
{
  "version": 1,
  "mrenclave": "<hex>",
  "padded_digest": "<base64, 384 bytes>",
  "sigstruct_unsigned": "<base64, 1808 bytes>",
  "config_hash": "<hex>"
}
```

### Partial Signature (`partial.sig`)

```json
{
  "version": 1,
  "party_index": 1,
  "subset_key": "1,2",
  "partial_signature": "<base64 big-endian>"
}
```

## License

See [LICENSE](LICENSE.md) file.
