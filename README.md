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

Signing also happens via group chat, same as keygen. One party initiates (needs the binary + EGo), others contribute their partial signatures.

**Initiator** (has the unsigned binary, enclave.json, EGo, and their share):
```bash
mpcegosign sign --config enclave.json --share share_1.json --out signed-binary
```
This computes the MRENCLAVE, outputs a SIGN-INIT message to the group, then waits for partial signatures.

**Each other signing party** (has their share):
```bash
mpcegosign sign --share share_3.json
```
Paste the SIGN-INIT message. The tool shows the MRENCLAVE for verification, computes the partial signature, and outputs a SIGN-PARTIAL message to post to the group.

**Back to the initiator**: paste each SIGN-PARTIAL. Once the threshold is reached, the tool combines the partials and writes the signed binary.

Each party independently verifies the MRENCLAVE shown in the SIGN-INIT message. If it doesn't match what they expect, they don't sign.

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

Interactive distributed signing via group chat messages.

```
# Initiator (has binary + config + EGo):
mpcegosign sign --config enclave.json --share share.json [--out signed] [--ego /opt/ego]

# Signer (has their share):
mpcegosign sign --share share.json
```

| Flag | Description |
|------|-------------|
| `--config` | Path to EGo `enclave.json`. Presence of this flag makes you the initiator. |
| `--share` | Path to this party's key share JSON. |
| `--out` | Output signed binary path (initiator only). Default: `<exe>.signed`. |
| `--ego` | Path to EGo installation. Default: auto-detect. |

The initiator computes the MRENCLAVE and posts a SIGN-INIT message. Each signer verifies the MRENCLAVE, computes their partial, and posts a SIGN-PARTIAL message. Once the initiator has enough partials, the tool combines them and writes the signed binary.

### `signerid`

Compute MRSIGNER (SHA-256 of the RSA modulus in little-endian).

```
mpcegosign signerid --key public.pem
mpcegosign signerid --enclave signed-binary
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `EGO_PATH` | Path to EGo installation directory (e.g. `/opt/ego`). Used by `sign` to locate `ego-oesign` for MRENCLAVE computation. Falls back to `/opt/ego` if unset. |

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

The only file that persists between sessions. Each party keeps theirs secure.

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

All other data (hashes, partial signatures, SIGSTRUCT) is exchanged as base64 messages in the group chat during the interactive signing ceremony — no intermediate files needed.

## License

See [LICENSE](LICENSE.md) file.
