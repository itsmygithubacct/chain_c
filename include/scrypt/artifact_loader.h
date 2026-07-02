/*
 * artifact_loader.h — parse a scryptlib compiled-artifact JSON into a
 * scrypt_artifact_t, and flatten an ordered constructor-argument value list
 * into the leaf sequence scryptlib uses to substitute the <name> placeholders.
 *
 * scryptlib substitutes constructor args into the hex template by FLATTENING
 * compound args (structs and FixedArrays) into ordered scalar "leaves", each
 * with a dotted/subscripted name (e.g. "sig.s", "sig.padding", "proof[0].hash",
 * "proof[0].pos"). The flatten ORDER and the leaf naming MUST match scryptlib so
 * the reconstructed locking script is byte-identical to the deployed one.
 *
 * TS origin: scryptlib `loadArtifact` / `Contract.fromArtifact`, the
 * flattenSha256/flattenStruct/flattenArray leaf expansion in scryptlib's
 * abiCoder; src/scripts/verifyRicardian.ts artifact load,
 * src/atlasIdentity.ts constructor-arg ordering.
 */
#ifndef BONSAI_SCRYPT_ARTIFACT_LOADER_H
#define BONSAI_SCRYPT_ARTIFACT_LOADER_H

#include <stddef.h>
#include "common/error.h"
#include "common/bytes.h"
#include "scrypt/scrypt_contract.h"

/* One flattened scalar leaf produced from a (possibly compound) ctor argument.
 * `name` is the dotted/subscripted scryptlib path; `value` is a BORROWED pointer
 * into the originating scrypt_arg_t tree (valid only while that tree lives) and
 * is always a scalar tag (INT/BOOL/BYTES/PUBKEY/SHA256/RIPEMD160/RABIN_PUBKEY).
 * TS: scryptlib flattened ABI leaf {name, type, value}. */
typedef struct {
    char               *name;  /* owned dotted/subscript path (e.g. "proof[0].hash") */
    const scrypt_arg_t *value; /* borrowed scalar leaf value                          */
} scrypt_leaf_t;

/* An ordered, owned list of flattened leaves. flat_args_free releases `name`s
 * and the array (the borrowed `value`s are NOT freed). */
typedef struct {
    scrypt_leaf_t *leaves;   /* owned array                                          */
    size_t         count;
} scrypt_leaves_t;

/* ---- artifact load ------------------------------------------------------ */

/* Parse a scryptlib artifact JSON file at `json_path` into *out (caller frees
 * via scrypt_artifact_free). Reads "contract", "hex", "abi"[constructor].params,
 * "structs", and "stateProps"; resolves each param's scrypt type string to a
 * scrypt_type_t (and records type_name for struct/array). Sets `stateful`.
 * TS: scryptlib loadArtifact(path). BNS_OK / BNS_EPARSE (bad JSON/shape) /
 * BNS_EPERSIST (cannot read file) / BNS_ENOMEM. */
int load_artifact(const char *json_path, scrypt_artifact_t *out);

/* Parse an already-read artifact JSON string (same semantics as load_artifact
 * but from memory; used by tests/embedded artifacts).
 * BNS_OK / BNS_EPARSE / BNS_ENOMEM. */
int load_artifact_from_json(const char *json_text, scrypt_artifact_t *out);

/* ---- argument flattening ------------------------------------------------ */

/* Flatten an ordered ctor argument list (`values`/`num_values`, parallel to
 * artifact->ctor_params) into the scryptlib leaf sequence in *out (caller frees
 * via flat_args_free). Compound args expand depth-first in declaration order:
 *   struct  -> one leaf per field, name = "<param>.<field>" (recursing);
 *   FixedArray -> one leaf per element, name = "<param>[<i>]" (recursing).
 * Scalars produce a single leaf named "<param>". The resulting leaf ORDER is the
 * order in which script_codec substitutes <name> placeholders in the template.
 * TS: scryptlib abiCoder flatten of constructor params. BNS_OK /
 * BNS_EINVAL (arity/type mismatch vs ctor_params) / BNS_ENOMEM. */
int flatten_args(const scrypt_artifact_t *artifact,
                 const scrypt_arg_t *values, size_t num_values,
                 scrypt_leaves_t *out);

/* Release an owned leaf list (NULL-safe). Does not free borrowed leaf values. */
void flat_args_free(scrypt_leaves_t *leaves);

#endif /* BONSAI_SCRYPT_ARTIFACT_LOADER_H */
