/*
 * atlas_identity.c — build_atlas_instance: the single shared construction path
 * that turns charter prose + an AtlasDeploymentParams binding into a constructed
 * RicardianTea instance plus the computed ricardianHash, binding, and charter.
 *
 * Faithful port of src/atlasIdentity.ts::buildAtlasInstance. The TS function:
 *   1. await RicardianTea.loadArtifact()        -> caller passes the loaded artifact
 *   2. const charter = parseCharterParams(prose)
 *   3. const binding = { agentPubKey, designatedValidatorPubKey,
 *        validatorRabinPubKey, maxSlashingTarget, minSlashConfirmations,
 *        initialSlashCheckpointHash }  (elderPubKey EXCLUDED; .toString() each)
 *   4. const ricardianHash = computeRicardianHash(prose, binding)
 *   5. new RicardianTea(elder, agent, ricardianHash, perTxLimit, dailyLimit,
 *        windowDuration, graduationThreshold, validatorThreshold,
 *        designatedValidatorPubKey, validatorRabinPubKey, maxSlashingTarget,
 *        minSlashConfirmations, initialSlashCheckpointHash)  (13 ctor args)
 *   -> { instance, ricardianHash, binding, charter }
 *
 * Determinism pins reproduced here:
 *  - PubKey / Sha256 binding fields stringify to LOWERCASE HEX (hex_encode_buf).
 *  - RabinPubKey and the two slashing bigints stringify to DECIMAL (bn_to_dec) —
 *    RabinPubKey is a bigint, so its canonical text is decimal NOT hex.
 *  - elderPubKey is the ctor `owner` (arg 1) but is NOT a binding field, so it
 *    does not enter ricardianHash via the canonical binding JSON.
 *  - The 13 ctor args are placed in @prop declaration order (== locking-script
 *    substitution order) so the reconstructed lockingScript matches the chain.
 */
#include <stdlib.h>
#include <string.h>

#include "atlas_identity.h"
#include "common/hex.h"

/* Duplicate a bn_t into a freshly-allocated handle (*dst). On failure leaves
 * *dst == NULL and returns the error code. */
static int dup_bn(const bn_t *src, bn_t **dst, bonsai_err_ctx *ctx)
{
    *dst = NULL;
    if (!src)
        return bns_fail(ctx, BNS_EINVAL, "atlas: missing bignum binding field");
    int rc = bn_dup(src, dst);
    if (rc != BNS_OK)
        return bns_fail(ctx, rc, "atlas: bn_dup failed");
    return BNS_OK;
}

/* Decimal string of a bn_t (DECIMAL canonical form for Rabin/bigint binding). */
static int bn_dec_string(const bn_t *src, char **out, bonsai_err_ctx *ctx)
{
    *out = NULL;
    if (!src)
        return bns_fail(ctx, BNS_EINVAL, "atlas: missing bignum binding field");
    int rc = bn_to_dec(src, out);
    if (rc != BNS_OK)
        return bns_fail(ctx, rc, "atlas: bn_to_dec failed");
    return BNS_OK;
}

/* Lowercase-hex string of a raw byte buffer (PubKey/Sha256 canonical form). */
static int buf_hex_string(const byte_buf_t *src, char **out, bonsai_err_ctx *ctx)
{
    *out = hex_encode_buf(src);
    if (!*out)
        return bns_fail(ctx, BNS_ENOMEM, "atlas: hex_encode_buf OOM");
    return BNS_OK;
}

void atlas_instance_free(atlas_instance_t *a)
{
    if (!a)
        return;
    ricardian_tea_free(&a->instance);
    free(a->ricardian_hash);
    a->ricardian_hash = NULL;
    deployment_binding_free(&a->binding);
    charter_params_free(&a->charter);
}

int build_atlas_instance(const char *prose_text,
                         const atlas_deployment_params_t *p,
                         const scrypt_artifact_t *artifact,
                         atlas_instance_t *out,
                         bonsai_err_ctx *ctx)
{
    if (!prose_text || !p || !artifact || !out)
        return bns_fail(ctx, BNS_EINVAL, "build_atlas_instance: null argument");

    /* Start from a fully-zeroed result so the single error path below can free
     * partial state via atlas_instance_free without touching garbage. */
    memset(out, 0, sizeof(*out));
    byte_buf_init(&out->instance.params.owner);
    byte_buf_init(&out->instance.params.agent);
    byte_buf_init(&out->instance.params.ricardian_hash);
    byte_buf_init(&out->instance.params.initial_slash_checkpoint_hash);
    byte_buf_init(&out->instance.state.slash_checkpoint_hash);

    int rc;

    /* 1. parseCharterParams(prose) — the single source of truth for policy. */
    rc = parse_charter_params(prose_text, &out->charter, ctx);
    if (rc != BNS_OK)
        goto fail;

    /* 2. Build the DeploymentBinding by stringifying p (elderPubKey EXCLUDED).
     *    PubKey/Sha256 -> lowercase hex; RabinPubKey/bigint -> decimal. */
    if ((rc = buf_hex_string(&p->agent_pubkey, &out->binding.agent_pubkey, ctx)) != BNS_OK)
        goto fail;
    if ((rc = bn_dec_string(p->designated_validator_pubkey,
                            &out->binding.designated_validator_pubkey, ctx)) != BNS_OK)
        goto fail;
    if ((rc = bn_dec_string(p->validator_rabin_pubkey,
                            &out->binding.validator_rabin_pubkey, ctx)) != BNS_OK)
        goto fail;
    if ((rc = bn_dec_string(p->max_slashing_target,
                            &out->binding.max_slashing_target, ctx)) != BNS_OK)
        goto fail;
    if ((rc = bn_dec_string(p->min_slash_confirmations,
                            &out->binding.min_slash_confirmations, ctx)) != BNS_OK)
        goto fail;
    if ((rc = buf_hex_string(&p->initial_slash_checkpoint_hash,
                             &out->binding.initial_slash_checkpoint_hash, ctx)) != BNS_OK)
        goto fail;

    /* 3. ricardianHash = computeRicardianHash(prose, binding) — lowercase 64-hex. */
    rc = compute_ricardian_hash(prose_text, &out->binding, &out->ricardian_hash);
    if (rc != BNS_OK) {
        bns_fail(ctx, rc, "atlas: compute_ricardian_hash failed");
        goto fail;
    }

    /* 4. Construct the RicardianTea ctor args in the 13-arg @prop order.
     *    owner = elderPubKey (arg 1); the binding-excluded elder still enters
     *    the contract here as the contract's owner. */
    ricardian_tea_params_t *prm = &out->instance.params;

    /* arg 1: owner = elderPubKey (33B). */
    if ((rc = byte_buf_append_buf(&prm->owner, &p->elder_pubkey)) != BNS_OK) {
        bns_fail(ctx, rc, "atlas: owner copy OOM");
        goto fail;
    }
    /* arg 2: agent = agentPubKey (33B). */
    if ((rc = byte_buf_append_buf(&prm->agent, &p->agent_pubkey)) != BNS_OK) {
        bns_fail(ctx, rc, "atlas: agent copy OOM");
        goto fail;
    }
    /* arg 3: ricardianHash (32 raw bytes decoded from the lowercase hex). */
    if ((rc = hex_decode(out->ricardian_hash, &prm->ricardian_hash)) != BNS_OK) {
        bns_fail(ctx, rc, "atlas: ricardianHash hex decode failed");
        goto fail;
    }
    /* args 4-8: charter policy bigints (perTxLimit, dailyLimit, windowDuration,
     *           graduationThreshold, validatorThreshold). */
    if ((rc = dup_bn(out->charter.per_tx_limit, &prm->per_tx_limit, ctx)) != BNS_OK)
        goto fail;
    if ((rc = dup_bn(out->charter.daily_limit, &prm->daily_limit, ctx)) != BNS_OK)
        goto fail;
    if ((rc = dup_bn(out->charter.window_duration, &prm->window_duration, ctx)) != BNS_OK)
        goto fail;
    if ((rc = dup_bn(out->charter.graduation_threshold, &prm->graduation_threshold, ctx)) != BNS_OK)
        goto fail;
    if ((rc = dup_bn(out->charter.validator_threshold, &prm->validator_threshold, ctx)) != BNS_OK)
        goto fail;
    /* args 9-10: the two Rabin pubkeys (bigint n). */
    if ((rc = dup_bn(p->designated_validator_pubkey, &prm->designated_validator_pubkey, ctx)) != BNS_OK)
        goto fail;
    if ((rc = dup_bn(p->validator_rabin_pubkey, &prm->validator_rabin_pubkey, ctx)) != BNS_OK)
        goto fail;
    /* args 11-12: slashing policy bigints. */
    if ((rc = dup_bn(p->max_slashing_target, &prm->max_slashing_target, ctx)) != BNS_OK)
        goto fail;
    if ((rc = dup_bn(p->min_slash_confirmations, &prm->min_slash_confirmations, ctx)) != BNS_OK)
        goto fail;
    /* arg 13: initialSlashCheckpointHash (32 raw bytes). */
    if ((rc = byte_buf_append_buf(&prm->initial_slash_checkpoint_hash,
                                  &p->initial_slash_checkpoint_hash)) != BNS_OK) {
        bns_fail(ctx, rc, "atlas: initialSlashCheckpointHash copy OOM");
        goto fail;
    }

    /* Bind the (borrowed) compiled artifact and initialise genesis state
     * (txCount/spentInWindow/windowStart=0, tier=1, checkpoint=initial). */
    out->instance.artifact = artifact;
    rc = ricardian_tea_genesis_state(prm, &out->instance.state);
    if (rc != BNS_OK) {
        bns_fail(ctx, rc, "atlas: genesis state init failed");
        goto fail;
    }

    return BNS_OK;

fail:
    atlas_instance_free(out);
    memset(out, 0, sizeof(*out));
    return rc;
}
