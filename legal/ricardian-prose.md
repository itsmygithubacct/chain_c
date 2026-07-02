# Ricardian Constitution — Autonomous Agent "ATLAS-01"

> This is the **Prose** half of the Ricardian contract (Sgantzos & Ferrara 2026,
> Eq. 1: `Contract = {Prose, Parameters, Code, Signatures}`). The **Parameters**
> are not a separate file: the machine-parsable policy block in §2 is the single
> source of truth that `scripts/deploy.ts` reads and feeds directly into both the
> on-chain contract constructor and `ricardianHash`. **Editing one byte of this
> file — prose or parameter — changes the hash and therefore creates a different
> legal-technical identity** (the "Identity Binding" property, Theorem 2.5
> Part 3). Re-derive and check the parsed parameters at any time with
> `ts-node scripts/verifyRicardian.ts`.

## 1. Intent of the Treaty
Agent **ATLAS-01** is authorised by the Issuer (the "Elder") to execute payment
transactions on the BSV ledger on the Issuer's behalf, strictly within the
parameters below. Each payment transfers **real BSV** (`amount`, in satoshis) to
the counterparty, funded from the Agent's operating wallet; the persistent
identity UTXO is not depleted (settlement Model D). Any action outside these
guardrails is, on its face, invalid and unauthorised, and exposes the operating
party to liability.

## 2. Parameters — the single source of truth
The values in the delimited block below **are** the parameters the Code
enforces: `scripts/deploy.ts` parses this block and passes the parsed values
into the contract constructor and into `ricardianHash`. There is no second copy
to drift against. All values are non-negative **integers** in the unit named in
the comment (satoshis, seconds, or a transaction count) — there are no decimal
places.

<!-- ricardian:params:begin -->
```
perTxLimit          = 100000     # satoshis — maximum per single payment
dailyLimit          = 1000000    # satoshis — maximum per rolling window
windowDuration      = 86400      # seconds  — rolling-window length (one day)
graduationThreshold = 10000      # count    — reconciled txs to reach Tier-2 validator standing
validatorThreshold  = 50000      # satoshis — at/above this amount a designated-validator attestation is required
```
<!-- ricardian:params:end -->

## 3. Deployment binding (committed to the identity, supplied at issuance)
The following are not negotiable prose *terms* but cryptographic identities and
an operational policy fixed at deployment. They are serialised canonically and
hashed together with this prose into `ricardianHash`, so the identity commits to
them too — but the Issuer supplies them at deploy time rather than writing
literal values here:

- `agent` — ATLAS-01's Sovereign Key (its own keypair, ideally TEE-held).
- `designatedValidatorPubKey` — the Rabin key of the validator that vouches for
  this agent's high-value (≥ `validatorThreshold`) payments.
- `validatorRabinPubKey` — this identity's own (slashable) attestation key.
- `maxSlashingTarget`, `minSlashConfirmations`, `slashCheckpointHash` — the
  SPV / header-work policy used by `slash()` proofs.

## 4. Parties (Signatures)
- **Issuer / Elder (`owner`)** — human root of trust; may revoke at any time.
- **Agent (`agent`)** — ATLAS-01's own key. Ideally held in a TEE, but the
  framework does **not rely** on that: the key is treated as an ordinary key
  whose protection is the in-script per-tx/window caps + the on-chain revocation
  kill-switch (a TEE is optional hardening, not a load-bearing guarantee —
  `docs/ADHERENCE-PLAN.md` §E).
- **Counterparty** — the genuine independent second party (for a payment, the
  payee; for a metered action, the **resource/API provider** the agent pays,
  which keeps its own books). It co-signs each receipt (the Second Entry); the
  receipt is thus a shared fact between two parties with independent records,
  not one principal signing twice (`docs/ADHERENCE-PLAN.md` §C).

> Signature: at deployment the Issuer (Elder) **cryptographically signs** the
> canonical contract bytes (this prose ‖ the canonical deployment binding) with
> its BSV key; the signature is emitted as the self-contained sidecar
> `legal/ricardian-prose.sig` and re-checked by `scripts/verifyRicardian.ts`.
> The document itself stays the hashed artifact (`ricardianHash`), and the
> sidecar makes it verifiable standalone — the "Signatures" leg of
> `{Prose, Parameters, Code, Signatures}` (`docs/ADHERENCE-PLAN.md` Theme A).

## 5. Dispute resolution
Subjective matters (force majeure, intent, ambiguity) are escalated to the
Elder under the courts of the Issuer's jurisdiction. Objective matters
(signature validity, budget reconciliation) are settled by the Code.
