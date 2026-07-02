# Changelog

All notable changes to this project are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security
- Security/hardening pass: `deploy` now reads the Elder key from a JSON key file
  (`ELDER_KEY_FILE` → `KEY_FILE` → `$BONSAI_NOTARY_HOME/chain/test_bsv.json`),
  with `PRIVATE_KEY` demoted to a deprecated, warning fallback (it leaks the WIF
  via the process environment). WIF buffers are now cleansed after use; the
  tx-parser enforces input/output-count bounds and overflow-safe length checks;
  WhatsOnChain satoshi values are range-validated; the Rabin private-key modular
  exponentiation is now constant-time (`BN_FLG_CONSTTIME`); and the
  crypto-provenance wording in `README.md`/`SECURITY.md` is qualified to note
  the Rabin scheme logic is an in-tree port over OpenSSL `BIGNUM`.
- Follow-up hardening (post-audit verification): fixed a use-after-free/double-free
  on the ephemeral-key error path in `bonsai_third_entry` (the new WIF-cleanse
  helper now NULLs freed pointers before a fall-through re-scrub); the WhatsOnChain
  `unconfirmed` balance is read with a sign-preserving parser (it can legitimately
  be negative) while keeping the 2⁵³ exactness bound.
- Wallet/broadcast money arithmetic now fails closed on recipient-total,
  selected-funding, and prefix-sum overflow instead of relying on unchecked
  `uint64_t` accumulation. The `keygen` CLI also creates key files with `0600`
  permissions from creation time and checked persistence before reporting
  success.

### Added
- `tests/test_tx_parse.c` — adversarial/malformed-input suite for `tx_deserialize`
  (truncated, non-hex, and maliciously oversized-count raw-tx hex), pinning the new
  parser DoS/overflow guards as memory-safe under the ASan/UBSan CI job.
- `tests/test_chain_broadcast.c` and additional `tests/test_spend.c` cases pin
  overflow-safe funding/recipient accumulation in the wallet and shared broadcast
  helper.
- Initial public release of `chain_c` — a faithful, byte-exact C port of the
  Priscilla BSV chain layer (originally TypeScript / scrypt-ts).
- Core library (`bonsai_chain`): crypto (secp256k1 ECDSA, OpenSSL SHA/BIGNUM/AES,
  vendored RIPEMD-160), BSV serialization (varint, num2bin encoders, scripts,
  addresses, tx, BIP143/FORKID sighash), scrypt artifact loader + script codec
  (locking/unlocking-script reconstruction from compiled `artifacts/*.json`),
  WhatsOnChain client, Ricardian charter, the Tea contracts, tx builders,
  brokers, verifiers, privacy enclave, and the MiMC7 / commitLimit ZK helpers.
- 9 CLI binaries: `agentd`, `deploy`, `verify_ricardian`, `bonsai_third_entry`,
  `live_agent_smoke`, `live_smoke`, `cpfp`, `woc`, `zk_build`.
- CMake + CTest build; golden-vector test suite (`tests/golden/`) pinning
  byte-exactness against the upstream TypeScript implementation, including six
  `tx.verify()`-passing deploy/executeAction/revoke transactions.
- Live stateful-contract broadcast (deploy → executeAction → revoke), proven
  end-to-end on BSV mainnet.
- Apache-2.0 license, `NOTICE`, `SECURITY.md`, `CONTRIBUTING.md`, and CI
  (build + `ctest` + an ASan/UBSan job).
