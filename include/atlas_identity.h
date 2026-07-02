/*
 * atlas_identity.h — the single shared construction path that builds a
 * RicardianTea instance from charter prose + a deployment binding and computes
 * the ricardianHash. Used by deploy and verifyRicardian so the deployed and
 * audited identities can never drift.
 *
 * TS origin: src/atlasIdentity.ts (AtlasDeploymentParams, buildAtlasInstance).
 *
 * ======================  THE 13-ARG RicardianTea CTOR  ======================
 * buildAtlasInstance loads the compiled RicardianTea artifact, parses the
 * charter params from prose, builds the DeploymentBinding by STRINGIFYING the
 * AtlasDeploymentParams fields, computes ricardianHash, and constructs a
 * RicardianTea with the 13 ctor args in this FIXED ORDER (== @prop order):
 *   1 owner(=elderPubKey) 2 agent 3 ricardianHash 4 perTxLimit 5 dailyLimit
 *   6 windowDuration 7 graduationThreshold 8 validatorThreshold
 *   9 designatedValidatorPubKey 10 validatorRabinPubKey 11 maxSlashingTarget
 *   12 minSlashConfirmations 13 initialSlashCheckpointHash
 *
 *  - elderPubKey BECOMES the contract's `owner` (ctor arg 1).
 *  - elderPubKey is EXCLUDED from the DeploymentBinding (the binding has six
 *    fields: agentPubKey, designatedValidatorPubKey, validatorRabinPubKey,
 *    maxSlashingTarget, minSlashConfirmations, initialSlashCheckpointHash — NOT
 *    the elder/owner). The owner is bound implicitly by the prose/charter, not
 *    by the canonical-binding JSON, so it does NOT enter ricardianHash via the
 *    binding. Getting this wrong changes the canonical JSON and the hash.
 *  - RabinPubKey fields stringify to DECIMAL (bigint), pubkeys/Sha256 to hex.
 * ============================================================================
 */
#ifndef BONSAI_ATLAS_IDENTITY_H
#define BONSAI_ATLAS_IDENTITY_H

#include <stddef.h>
#include "common/error.h"
#include "common/bytes.h"
#include "crypto/bignum.h"
#include "ricardian_charter.h"          /* charter_params_t, deployment_binding_t */
#include "contracts/ricardian_tea.h"    /* ricardian_tea_t                        */

/* The per-deployment binding values that the charter §3 declares but does not
 * write as literals. elder/agent PubKeys are 33-byte compressed SEC bytes; the
 * two Rabin pubkeys and two slashing numbers are bn_t; the checkpoint hash is
 * 32 raw bytes. Borrowed by build_atlas_instance (it copies/stringifies what it
 * needs). TS: src/atlasIdentity.ts::AtlasDeploymentParams. */
typedef struct {
    byte_buf_t elder_pubkey;                 /* elderPubKey -> ctor owner; NOT in binding */
    byte_buf_t agent_pubkey;                 /* agentPubKey                               */
    bn_t      *designated_validator_pubkey;  /* designatedValidatorPubKey (Rabin n)       */
    bn_t      *validator_rabin_pubkey;       /* validatorRabinPubKey (Rabin n)            */
    bn_t      *max_slashing_target;          /* maxSlashingTarget                         */
    bn_t      *min_slash_confirmations;      /* minSlashConfirmations                     */
    byte_buf_t initial_slash_checkpoint_hash;/* initialSlashCheckpointHash Sha256 (32B)   */
} atlas_deployment_params_t;

/* The result of build_atlas_instance: the constructed contract instance, the
 * computed ricardianHash (lowercase 64-hex, owned), the deployment binding
 * (owned), and the charter params parsed from prose (owned). Free with
 * atlas_instance_free. TS: { instance, ricardianHash, binding, charter }. */
typedef struct {
    ricardian_tea_t      instance;       /* owned                                */
    char                *ricardian_hash; /* owned lowercase 64-hex               */
    deployment_binding_t binding;        /* owned                                */
    charter_params_t     charter;        /* owned                                */
} atlas_instance_t;

/* Release all owned members (NULL-safe). */
void atlas_instance_free(atlas_instance_t *a);

/* Build the Atlas RicardianTea instance:
 *   1. parse_charter_params(prose) -> charter;
 *   2. stringify `p` into a DeploymentBinding (elderPubKey EXCLUDED; Rabin pubkeys
 *      DECIMAL, pubkeys/Sha256 hex);
 *   3. compute_ricardian_hash(prose, binding);
 *   4. construct a RicardianTea over `artifact` with the 13 ctor args in fixed
 *      order (owner=elderPubKey, ...), genesis state initialized.
 * Fills *out (caller frees via atlas_instance_free). `artifact` is the loaded
 * compiled ricardianTea.json (borrowed; outlives the instance). A pure
 * off-chain verifier that only needs hash+binding+charter may ignore the
 * reconstructed instance's locking script.
 * TS: src/atlasIdentity.ts::buildAtlasInstance.
 * BNS_OK / BNS_EPARSE (bad prose) / BNS_EINVAL / BNS_ENOMEM. */
int build_atlas_instance(const char *prose_text,
                         const atlas_deployment_params_t *p,
                         const scrypt_artifact_t *artifact,
                         atlas_instance_t *out,
                         bonsai_err_ctx *ctx);

#endif /* BONSAI_ATLAS_IDENTITY_H */
