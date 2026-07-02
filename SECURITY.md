# Security

`chain_c` builds, signs, and broadcasts **real Bitcoin SV mainnet transactions**
and reads **WIF private keys** from disk. Read this before running anything that
can touch the network.

## Money-safety model

- **Dry-run by default.** Every CLI that can broadcast (`deploy`, `agentd`,
  `bonsai_third_entry`, `live_agent_smoke`, `cpfp`) prints its plan and does **not**
  broadcast unless `CONFIRM_MAINNET_BROADCAST=yes` is set in the environment.
- **Mainnet only.** The broadcast helper refuses to send to anything but mainnet
  WhatsOnChain — it will not silently push a testnet transaction to mainnet.
- **Real funds move on confirm.** With `CONFIRM_MAINNET_BROADCAST=yes` and a
  funded key, these tools spend real BSV (fees, and the value locked into / paid
  out by the contracts). There is no undo. Verify the printed plan first.
- **Verify before you broadcast.** For contract spends, build the transaction,
  confirm it passes a real script-interpreter check, and only then broadcast.
  Broadcasting an unverified, freshly-built transaction risks burning funds to
  fees or producing an unmineable tx.

## Key handling

- **Never commit a private key.** Key files are JSON `{ "wif": "...", "address":
  "..." }`. They must live **outside** the repository — by convention under
  `$BONSAI_NOTARY_HOME` (default `~/.local/trinote/wallet/keys/`), not in the
  working tree.
- The CLIs read keys only from the paths you pass via the documented environment
  variables (`KEY_FILE`, `ELDER_KEY_FILE`, `AGENT_KEY_FILE`, `FUND_*_KEY_FILE`,
  …). They are not embedded in the binaries or the source.
- **`deploy` reads the Elder key from a JSON key file**, not from an inline
  secret. It resolves `ELDER_KEY_FILE`, then `KEY_FILE`, then defaults to
  `$BONSAI_NOTARY_HOME/chain/test_bsv.json` — consistent with how `agentd`,
  `cpfp`, and `bonsai_third_entry` resolve their keys. `PRIVATE_KEY` is accepted
  only as a **deprecated** fallback (it warns when used) and is discouraged:
  passing a WIF through the environment exposes it via `/proc/<pid>/environ` and
  to any spawned child process. Prefer a key file.
- WIFs are loaded into process memory to sign; they are not logged. Do not run
  these tools on untrusted machines or with untrusted key files.

## Test fixtures are not secrets

`tests/golden/broadcast.json` contains **WIF strings**, but they are
deterministic **testnet** keys used only to reproduce the byte-exact golden
transactions offline. They hold no funds and are not used by any live path. Do
not reuse them for anything real.

`tests/golden/golden.json` (and `by-area/txSighashAddress.json`) additionally
contain a **mainnet** WIF and `1…` address — this is the public, anyone-derivable
constant private key `0x01`×32 (the well-known "privkey = 1"), included only to
pin the mainnet WIF/address-encoding vector. It controls no funds and is not a
secret. Likewise, do not reuse it.

## Cryptography

- ECDSA: `libsecp256k1` (RFC6979 deterministic nonces, low-S, DER).
- Hashing: OpenSSL `libcrypto` (SHA-256/512) + a vendored RIPEMD-160.
- AES-256-GCM (enclave sealing): OpenSSL EVP.
- Rabin signatures: the *scheme* (CRT square-roots, prime generation via a
  Fermat-style primality test) is implemented in-tree as a faithful port of the
  upstream `rabinsig`, but all bignum arithmetic runs over OpenSSL `BIGNUM`.
  In other words, the cryptographic primitives are library-backed; only the
  Rabin scheme logic itself lives in this repo rather than in a third-party
  Rabin library. The secret-exponent modular exponentiation on the Rabin
  private path sets `BN_FLG_CONSTTIME`, so it is constant-time.
- With that one qualification, no hand-rolled cryptographic primitives are used
  on any security-bearing path.

The ZK trusted-setup keys shipped under `artifacts/zk/` are a **local,
single-contributor setup** — forgeable by whoever generated them. They are for
development and testing only and **must not** be relied on as a production
trusted setup.

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue.
Open a [GitHub Security Advisory](../../security/advisories/new) for this
repository (preferred), or contact the maintainers directly. We aim to
acknowledge reports within a few business days. Do not include live private keys
or other secrets in a report.
