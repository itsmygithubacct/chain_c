# chain_c — a C port of the Priscilla BSV chain layer

`chain_c` is a faithful, **byte-exact** C reimplementation of the Priscilla BSV
chain layer — a TypeScript / scrypt-ts codebase for on-chain AI-agent identity
("Tea" contracts), anchored receipts, and Ricardian charters. This repository is
the **standalone C port**; the upstream TypeScript implementation is the
authoritative reference it is verified against (see [Provenance](#provenance)).
The port reproduces every on-chain artifact — receipt preimages, locking scripts,
Rabin signatures, sighash preimages, the Ricardian charter hash — down to the
byte, so a C-built transaction is indistinguishable from one the TypeScript layer
builds.

It links real cryptographic libraries: **libsecp256k1** for ECDSA, **OpenSSL
libcrypto** for SHA/RIPEMD160/BIGNUM/AES, and **libcurl** for HTTPS to
WhatsOnChain. The one exception to "no hand-rolled crypto" is the Rabin
signature *scheme*: its logic (CRT square-roots, prime generation via a
Fermat-style primality test) is implemented in-tree as a faithful port of the
upstream `rabinsig`, but over OpenSSL `BIGNUM` arithmetic — so the bignum math
is library-backed and the secret-exponent path is constant-time
(`BN_FLG_CONSTTIME`); only the Rabin scheme logic itself lives in this repo
rather than in a third-party Rabin library. scrypt-ts contract locking scripts are
**reconstructed from the committed `artifacts/*.json`** rather than recompiled;
ZK proving/verifying shells out to circom/snarkjs and is gated behind a build
option. The build is CMake + CTest with per-module test isolation and labels.

> Status: **complete and green.** All 8 tiers are implemented (80 `src/**/*.c`
> modules + 80 headers, ~29k lines of C), the 9 CLI binaries build, and the
> CTest suite passes — 44 test executables (3 standalone golden harnesses + 39
> `unit` + 2 `zk`), **0 compiler warnings** under `-Wall -Wextra`.
> Byte-exactness is pinned by golden vectors captured from the authoritative TS
> layer, all passing; the headline pins — the `RicardianTea` (50286-hex) /
> `AgentTea` (54528-hex) locking scripts, the cross-language `executeAction`
> receipt hash `cdc6a3e1…`, and **6 full `tx.verify()`-passing deploy/
> executeAction/revoke transactions** — match the TS down to the byte.
> **Live stateful-contract spends are fully implemented:** the CLIs reconstruct
> the contract unlocking scripts byte-for-byte and fund→build→sign→broadcast
> against mainnet WhatsOnChain. Only the ZK proving/pairing-verify path remains
> gated (shelled to snarkjs).

## Prerequisites

| Tool / lib | Why | Notes |
|---|---|---|
| `gcc` (or clang), C11 | compile the core lib + binaries + tests | `-std=c11`, `_GNU_SOURCE` (posix_spawn) |
| `cmake` ≥ 3.16 | build system | native pkg-config + CTest integration |
| `pkg-config` | discover the system libs | |
| **libsecp256k1** | ECDSA sign (RFC6979 low-S), verify, DER | stock `libsecp256k1-dev` is sufficient (no recovery module needed) |
| **libcrypto** (OpenSSL 3.x) | SHA256/512, RIPEMD160, BIGNUM, AES-256-GCM, `RAND_bytes` | RIPEMD160 lives in OpenSSL 3's *legacy* provider — `chain_c` vendors RIPEMD160 instead, so the legacy provider is **not** required |
| **libcurl** | HTTPS GET/POST to WhatsOnChain | wrapped behind an injectable transport vtable so tests run offline |
| `libm`, `pthread` | fee/decay float math; the process-global WoC rate limiter | linked automatically |

Vendored under `third_party/` (no system package needed):

- **cJSON** — JSON parse/serialize for WoC responses, artifacts, sidecars
  (preserves V8 `JSON.stringify` insertion-order + 2-space indent byte-for-byte).
- **Unity** — single-file C unit-test framework (drives the CTest suite).
- **RIPEMD160** — small public-domain implementation for `hash160` / P2PKH
  address derivation, avoiding the OpenSSL 3 legacy-provider dependency.
- **MiMC7 round constants** — the 91 circomlib keccak-seeded constants copied
  verbatim (never re-derived at runtime).

On Debian/Ubuntu:

```sh
sudo apt install build-essential cmake pkg-config \
     libsecp256k1-dev libssl-dev libcurl4-openssl-dev
```

Developed and tested against libsecp256k1 0.5.0, OpenSSL libcrypto 3.5.6, and
libcurl 8.14.1; any reasonably recent versions should work.

## Building, running, testing

```sh
mkdir build && cd build
cmake ..
cmake --build .
ctest --output-on-failure -LE net
```

Remove all build artifacts with `./clean.sh` (`--dry-run` to preview, `--all` to
also sweep stray in-source CMake files).

`-LE net` excludes the live-network tests (the default development run). To run
the live WhatsOnChain tests against mainnet, drop the exclusion:

```sh
ctest --output-on-failure -L net      # only the live-network tests
ctest --output-on-failure             # everything (incl. net + zk if enabled)
```

Useful CMake options (defaults shown):

| Option | Default | Effect |
|---|---|---|
| `BUILD_SHARED_LIBS` | `OFF` | build `libbonsai_chain` shared instead of static |
| `BONSAI_BUILD_BINS` | `ON` | build the `bin/` CLI executables |
| `BONSAI_BUILD_TESTS` | `ON` | build the Unity/CTest suite |
| `BONSAI_ENABLE_ZK` | `OFF` | compile the ZK paths (needs circom/snarkjs) |
| `BONSAI_ASAN` | `OFF` | add `-fsanitize=address,undefined` (Debug) |

```sh
cmake .. -DCMAKE_BUILD_TYPE=Debug -DBONSAI_ASAN=ON      # sanitized debug build
cmake .. -DBONSAI_ENABLE_ZK=ON                          # build ZK + zk-labelled tests
```

## Architecture — dependency tiers

The library is a single `bonsai_chain` target built from `src/**/*.c`
(GLOB'd, so modules drop in incrementally). Public headers under `include/`
are **frozen contracts** that mirror the `src/` layout; everything is layered
so each tier depends only on tiers below it. Each `bin/*_main.c` is a thin
`main()` linking the core lib; the script *body* lives in `src/scripts/*_lib.c`
so it is unit-testable.

| Tier | Theme | Representative modules |
|---|---|---|
| 0 | Foundational primitives (libc/libcrypto leaves only) | `common/{bytes,hex,utf8,error}`, `crypto/{hash,bignum,rand,aes_gcm}`, `json/json`, `bsv/base58`, vendored cJSON / RIPEMD160 / mimc7_consts |
| 1 | Crypto + BSV serialization primitives | `crypto/{ecdsa,rabin}`, `bsv/{varint,num2bin,script,script_utils,address,sighash}`, `zk/mimc7` |
| 2 | Tx model, change/fee math, scrypt codec, HTTP transport, pure policy | `bsv/{tx,tx_builder,tx_change}`, `chain/tx_parse`, `scrypt/{artifact_loader,script_codec,scrypt_contract}`, `chainSources/{http_transport,bsv_fees,utxo_select,woc_rate_limiter}`, `provenance`, `broker/authorization_envelope`, `verifier/stake_policy`, `lib/{merkle_path,blockchain,rabin_verifier,scrypt_state}` |
| 3 | WoC client stack, charter/identity, zk bridge, manifest/key infra | `chainSources/{whats_on_chain,woc_client,throttled_provider}`, `ricardian_charter`, `reputation_indexer`, `zk/{g16,limit_commitment,prover}`, `verifier/{manifest_registry,rabin_attestor,release_anchor_verifier}`, `privacy/{key_vault,enclave}` |
| 4 | Contracts (locking-script reconstruction + in-script assert logic) | `contracts/{rabin_spike,ricardian_tea,zk_hidden_limit}`, `contracts_next/{arp_attest,agent_tea,attestor_tea,publisher_tea}`, `atlas_identity` |
| 5 | Tx builders + broker / identity-chain consumers | `txbuilders/*`, `broker/{identity_chain_view,chain_revocation_oracle,key_broker}` |
| 6 | Attestor, sandbox, high-level orchestration | `attestor/auto_exec_linter`, `sandbox/sandboxed_agent` |
| 7 | Script libraries + CLI binaries | `src/scripts/*_lib.c` + `bin/{agentd,deploy,verify_ricardian,live_agent_smoke,bonsai_third_entry,cpfp,woc,live_smoke,zk_build}_main.c` |
| 8 | Tests + helpers (parallel to their targets) | `tests/helpers/*`, `tests/test_*.c` |

Tiers 0–1 freeze the byte-fragile leaves (the two/three distinct `int2ByteString`
encoders, the Rabin scheme, the sighash preimage) that every higher tier hashes
over; getting them golden-pinned first unblocks the rest.

## scrypt locking-script reconstruction

`chain_c` does **not** recompile the sCrypt contracts. The compiled outputs are
committed under `artifacts/*.json` (the contract hex templates), alongside
`legal/` (the Ricardian prose, hashed verbatim) and `circuits/` (the circom
sources for `zk_build`). The scrypt codec (`src/scrypt/`) loads an artifact JSON, takes
the constructor (and, for stateful contracts, state) argument values, and
**substitutes them into the artifact's hex template** in the fixed argument
order to reproduce `lockingScript.toHex()` byte-for-byte:

- `artifact_loader.c` parses the artifact JSON and flattens struct/array ctor
  args into dotted + subscripted leaf names.
- `script_codec.c` implements `toScriptHex` (the *constructor* int/bytes/bool
  encoders, which use Script-pushdata opcode optimization — `0`→`00`,
  `1..16`→`OP_1..OP_16`, `-1`→`OP_1NEGATE`) and `buildState` for stateful
  contracts (the *state* encoders, which have **no** opcode optimization, plus
  the `num2bin(stateByteLen, 4)` length suffix and the `0x00` version byte).

The constructor encoder, the stateful encoder, and the one-arg minimal
sign-magnitude `int2ByteString` are three different encoders that look
interchangeable; picking the wrong one silently corrupts every receipt hash, so
each is pinned by a golden vector (see below). `atlas_identity.c` reconstructs
the `RicardianTea` instance from its artifact + charter; the `lockingScripts`
golden vector pins both the `RicardianTea` (50286-hex) and `AgentTea`
(54528-hex) outputs.

These compiled artifacts originate from the upstream TypeScript project and are
committed here directly, so the repository builds and verifies on its own.

## ZK — gated behind `BONSAI_ENABLE_ZK`

The zero-knowledge "cost within a secret limit" path (paper §4.3:
`circuits/withinLimit.circom`, `zk/g16`, `contracts/zk_hidden_limit`) is **off by
default**. Building with `-DBONSAI_ENABLE_ZK=ON` compiles the ZK modules and the
`zk`-labelled tests. Proving and trusted-setup are **not** done in C — `zk/prover`
and `bin/zk_build_main.c` `posix_spawn` out to `circom` / `snarkjs` (which must
be on `PATH`, with `artifacts/zk/*.zkey` present). Groth16 proving **and** the
BN254-pairing off-chain *verify* are deliberately **not** hand-ported to C (a
BN254 pairing reimplementation is out of scope per the porting decision); with ZK
disabled the proof-verify entrypoints (`zk/g16`, `contracts/zk_hidden_limit`)
return `BNS_EUNSUPPORTED` cleanly. What **is** native C is the deterministic
field arithmetic everything else depends on: **MiMC7** (`zk/mimc7`, golden-pinned)
and the `commitLimit` commitment (`zk/limit_commitment`). ZK tests carry the `zk`
CTest label and are excluded unless ZK is enabled; the committed keys are a
**local single-contributor setup** (forgeable by their creator — not a production
trusted setup).

## Golden-vector verification

`tests/golden/` holds byte-exact INPUT + OUTPUT strings captured by running the
upstream TypeScript implementation (per-vector provenance in
[`tests/golden/README.md`](tests/golden/README.md)). `golden.json` is the
full pretty-printed set; `tests/golden/by-area/*.json` are per-area copies. The
C tests pin their outputs against these strings rather than re-deriving expected
values, so any byte-level drift fails loudly. Covered areas include
`provenance`, `ricardianCharter`, `intEncoders` (all three encoders),
`rabin`, `mimc7`, `bsvFees`, `txSighashAddress`, `lockingScripts`, and
`reputationIndexer`, all under deterministic fixtures (a fixed `0x01`×32 ECDSA
key, a fixed seeded Rabin key). Decimal-vs-hex serialization and
"SHA256 the *decoded* preimage bytes, not the hex ASCII" are load-bearing — see
the golden README's "Notes for the C port".

## Tests

`tests/CMakeLists.txt` vendors Unity and builds **one executable per
`tests/test_*.c`**, each linking `bonsai_chain` plus a `test_helpers` object lib
GLOB'd from `tests/helpers/*.c`. Each is registered with `add_test()` and a
CTest label:

- **`unit`** (default) — pure, offline, deterministic.
- **`net`** — genuinely live-network tests, opted in by a `_live` filename
  marker; **excluded from the default run** (`-LE net`) and run with `-L net`.
  Offline WoC client tests use mocked transports and remain `unit`.
- **`zk`** — Groth16 / MiMC7 tests (names matching `zk`). These **always build and
  run** in the default suite: with ZK disabled they assert the compiled-out
  `BNS_EUNSUPPORTED` contract and the native MiMC7/`commitLimit` arithmetic, all
  offline. Only the heavy ZK *code paths* (BN254 verify, snarkjs shell-out) are
  gated behind `-DBONSAI_ENABLE_ZK=ON`; the tests themselves are not gated.

The suite is GLOB-driven (empty globs are guarded, so it configures even with no
tests). `test_*_golden.c` are **standalone** byte-exact integration harnesses
(own `main()`, no Unity, labelled `golden`); all other `test_*.c` are Unity
suites mirroring the upstream TypeScript test suite. The default run
(`-LE net`) is currently **44 tests** (39 `unit` + 3 `golden` + 2 `zk`, all
offline) and finishes in a few seconds.

## Layout

```
CMakeLists.txt            top-level build (core lib + bin/ + tests/)
include/                  PUBLIC headers — frozen contracts, mirror src/
src/                      implementation, mirrors include/
bin/                      thin main() entrypoints -> one CLI binary per script
third_party/
  cJSON/                  vendored JSON (MIT)
  unity/                  vendored unit-test framework (MIT)
  ripemd160/              vendored RIPEMD160 (public domain; avoids OpenSSL legacy provider)
  mimc7_consts/           91 circomlib MiMC7 round constants (data), verbatim
tests/
  CMakeLists.txt          one executable per test_*.c, labelled (unit/net/zk/golden)
  helpers/                shared test mocks/fixtures (GLOB'd into test_helpers)
  golden/                 byte-exact captured vectors (golden.json, broadcast.json, by-area/)
  test_*.c                per-module Unity suites + *_golden.c integration harnesses
artifacts/                committed compiled scrypt + zk artifacts (hex templates)
legal/                    ricardian-prose.md (hashed verbatim)
circuits/                 circom sources (for the zk_build shell-out)
LICENSE  NOTICE  SECURITY.md  CONTRIBUTING.md
```

## What's real vs. what's gated (honest status)

**Fully native + byte-exact (golden-pinned):** all the deterministic on-chain
computation — SHA/RIPEMD160/hash160, ECDSA (low-S DER, single-hash charter sig),
the Rabin scheme (`SECURITY_LEVEL=6`), both/all three `int2ByteString` encoders,
varint, base58check, addresses, tx serialize/`txid`, BIP143/FORKID sighash, the
Ricardian charter canonical bytes + `ricardianHash`, provenance hashes, MiMC7,
fee math, the scrypt **locking-script reconstruction** for every contract, the
contract **receipt/attestation preimages** (incl. the `AgentTea` `executeAction`
receipt hash), `reputation_indexer` decay, the broker authorize pipeline, the
release-anchor verifier, the privacy enclave, and the WoC client logic.

**Live network + stateful-contract spends that work:** all read/broadcast paths
go over real libcurl — `bin/live_smoke` hits mainnet and parses the response
end-to-end; `bin/cpfp` builds+signs+(on confirm) broadcasts a real P2PKH child;
`bin/woc` is a full WhatsOnChain CLI. The **stateful-contract spend** path
(`deploy` / `executeAction` / `revoke` for the Tea contracts) is now fully
implemented: the contract **unlocking** script is reconstructed byte-for-byte —
the method args (via the same golden codec), the BIP143/FORKID `SigHashPreimage`,
the change amount/address, the `prevouts` (for `checkInputZero` methods) and the
ABI method selector — and verified against **6 `tx.verify()`-passing golden
transactions** (`tests/test_broadcast_golden.c`, captured in
`tests/golden/broadcast.json`). The `agentd` / `deploy` / `bonsai_third_entry` /
`live_agent_smoke` CLIs fund (WoC UTXO selection) → build → sign → broadcast on
`CONFIRM_MAINNET_BROADCAST=yes`, and remain dry-run by default. (One operational
note: `chain_broadcast` is mainnet-only — it refuses to broadcast a testnet tx to
the mainnet WoC endpoint.)

**Still gated:** only the ZK proving / BN254-pairing verify path
(`BONSAI_ENABLE_ZK`, shelled to circom/snarkjs — see above). The deterministic ZK
field arithmetic (MiMC7, `commitLimit`) is native C.

The authoritative behavior each C module reproduces byte-for-byte is the upstream
TypeScript test suite; the C suite mirrors it and pins against vectors captured
from it.

## Provenance

This is a faithful C port of the Priscilla BSV chain layer, originally written in
TypeScript / scrypt-ts. The compiled contract artifacts under `artifacts/`, the
Ricardian prose under `legal/`, and the circom sources under `circuits/` originate
from that upstream project and are committed here so the repository is
self-contained. The golden vectors in `tests/golden/` were captured from the
upstream implementation and are what guarantee byte-for-byte fidelity.

## Security

These CLIs build and broadcast **real Bitcoin SV mainnet transactions** and read
WIF private keys from key files. Every broadcast is **dry-run by default** and
only sends when `CONFIRM_MAINNET_BROADCAST=yes`. **Never commit a private key.**
See [`SECURITY.md`](SECURITY.md) for the key-handling model and how to report a
vulnerability.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE). Vendored
third-party components under `third_party/` keep their own licenses (cJSON and
Unity: MIT; RIPEMD160: public domain). The MiMC7 round constants in
`third_party/mimc7_consts/` are numerical data from circomlib.
