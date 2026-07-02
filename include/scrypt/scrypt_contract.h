/*
 * scrypt_contract.h — the parsed scryptlib compiled-artifact model + the typed
 * constructor-argument value type used to reconstruct a contract's locking
 * script.
 *
 * A scryptlib "artifact" (e.g. chain/artifacts/ricardianTea.json) carries the
 * compiled-script HEX TEMPLATE (with <paramName> placeholders), the ordered
 * constructor parameter list (name + scrypt type), a structs table (for struct
 * and FixedArray argument flattening), and — for stateful contracts — a
 * stateProps list describing the on-chain mutable state appended after the code
 * part. This header models all of that as C structs plus a typed value union
 * (scrypt_arg_t) for each constructor argument.
 *
 * TS origin: scryptlib `ContractArtifact` (abi[].type=='constructor'.params,
 * structs[], stateProps[], hex), scrypt-ts `SmartContract` instance args;
 * src/atlasIdentity.ts new RicardianTea(...) (13-arg ctor) and
 * src/contracts (*.ts) contract instances; src/scripts/verifyRicardian.ts
 * artifact load.
 *
 * NOTE: this header models PARSED ARTIFACT DATA and TYPED VALUES only. The two
 * (actually three) integer encoders and the locking-script reconstruction live
 * in scrypt/script_codec.h; the JSON->scrypt_artifact_t parse + ctor-arg
 * flattening live in scrypt/artifact_loader.h. Keep this split: callers should
 * never hand-roll an encoder.
 */
#ifndef BONSAI_SCRYPT_SCRYPT_CONTRACT_H
#define BONSAI_SCRYPT_SCRYPT_CONTRACT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common/error.h"
#include "common/bytes.h"
#include "crypto/bignum.h"

/* The scrypt parameter/value type tag. Mirrors the `type` strings scryptlib
 * emits in artifact param/struct/stateProps entries ("int", "bool", "bytes",
 * "PubKey", "Sha256", "Ripemd160", "RabinPubKey"), plus the two compound kinds
 * (FixedArray, struct) discovered via the structs table / alias resolution.
 * TS: scryptlib basic types + struct/array aliases. */
typedef enum {
    SCRYPT_TYPE_INT,         /* scrypt `int`        -> bn_t value (ctor: opcode-optimized; state: int2hex) */
    SCRYPT_TYPE_BOOL,        /* scrypt `bool`       -> bool value (OP_0/OP_1)                               */
    SCRYPT_TYPE_BYTES,       /* scrypt `bytes`/ByteString -> raw bytes (pushdata)                          */
    SCRYPT_TYPE_PUBKEY,      /* scrypt `PubKey`     -> 33-byte compressed SEC bytes (pushdata)             */
    SCRYPT_TYPE_SHA256,      /* scrypt `Sha256`     -> 32-byte hash bytes (pushdata)                       */
    SCRYPT_TYPE_RIPEMD160,   /* scrypt `Ripemd160`  -> 20-byte hash bytes (pushdata)                       */
    SCRYPT_TYPE_RABIN_PUBKEY,/* scrypt `RabinPubKey`(== int alias) -> bn_t value (decimal wire / int enc)  */
    SCRYPT_TYPE_FIXED_ARRAY, /* scrypt `T[N]`       -> ordered element list (flattened with [i] subscripts) */
    SCRYPT_TYPE_STRUCT       /* scrypt struct       -> named field list (flattened with .field dotted names) */
} scrypt_type_t;

/* One named (param.name, param.type) entry as it appears in an artifact's
 * constructor params, a struct's params, or stateProps. For FixedArray/struct
 * entries `type_name` carries the scrypt type string (e.g. "RabinSig",
 * "int[3]") so the loader can resolve elements/fields against the structs table.
 * TS: scryptlib ParamEntity { name: string; type: string }. */
typedef struct {
    char         *name;      /* owned param name (e.g. "oraclePubKey", "txCount")  */
    scrypt_type_t type;      /* resolved basic/compound type tag                   */
    char         *type_name; /* owned raw scrypt type string (for struct/array)    */
} scrypt_param_t;

/* A struct definition from the artifact's `structs` table: a named ordered list
 * of fields. Used to flatten struct-typed ctor args into dotted leaves.
 * TS: scryptlib StructEntity { name; params[] }. */
typedef struct {
    char           *name;       /* owned struct name (e.g. "RabinSig", "BlockHeader") */
    scrypt_param_t *fields;     /* owned array of field entries                       */
    size_t          num_fields;
} scrypt_struct_t;

/* A typed constructor-argument value (a tagged union). The `tag` selects the
 * active member. `int_val`/`rabin_val` are owned bn_t handles; `bytes_val`
 * (covers bytes/PubKey/Sha256/Ripemd160 raw payloads) is an owned buffer;
 * `elems` (FixedArray) / `fields` (struct) are owned arrays of child values.
 * TS: a single scrypt-ts constructor argument (Int/Bool/ByteString/PubKey/
 * Sha256/Ripemd160/RabinPubKey/FixedArray/struct literal). */
typedef struct scrypt_arg_s scrypt_arg_t;
struct scrypt_arg_s {
    scrypt_type_t tag;
    union {
        bn_t       *int_val;    /* SCRYPT_TYPE_INT (owned)                          */
        bool        bool_val;   /* SCRYPT_TYPE_BOOL                                 */
        byte_buf_t  bytes_val;  /* BYTES/PUBKEY/SHA256/RIPEMD160 raw payload (owned)*/
        bn_t       *rabin_val;  /* SCRYPT_TYPE_RABIN_PUBKEY (owned)                 */
        struct {                /* SCRYPT_TYPE_FIXED_ARRAY                          */
            scrypt_arg_t *elems;    /* owned array of N element values              */
            size_t        count;
        } array;
        struct {                /* SCRYPT_TYPE_STRUCT                              */
            char         *struct_name; /* owned struct name (matches structs table)*/
            scrypt_arg_t *fields;      /* owned array, parallel to struct fields    */
            size_t        num_fields;
        } st;
    } as;
};

/* A parsed scryptlib compiled artifact. Owns all nested arrays/strings.
 * TS: scryptlib ContractArtifact (the loaded .json). */
typedef struct {
    char            *contract;     /* owned contract name (artifact "contract")     */
    char            *hex_template; /* owned compiled script hex with <name> markers  */
    scrypt_param_t  *ctor_params;  /* owned constructor params, in declaration order */
    size_t           num_ctor_params;
    scrypt_struct_t *structs;      /* owned structs table                            */
    size_t           num_structs;
    scrypt_param_t  *state_props;  /* owned stateProps (empty array => stateless)    */
    size_t           num_state_props;
    bool             stateful;     /* true iff num_state_props > 0                   */
} scrypt_artifact_t;

/* A live contract instance: a loaded artifact bound to a specific ordered set of
 * constructor argument values (and, for stateful contracts, the current state
 * values). This is the handle passed to script_codec reconstruct_locking_script.
 * TS: an instantiated scrypt-ts SmartContract object. */
typedef struct {
    const scrypt_artifact_t *artifact;   /* borrowed; not owned by the instance      */
    scrypt_arg_t            *ctor_values;/* owned, parallel to artifact->ctor_params  */
    size_t                   num_ctor_values;
    scrypt_arg_t            *state_values;/* owned, parallel to stateProps (or NULL)  */
    size_t                   num_state_values;
} scrypt_instance_t;

/* ---- lifecycle ---------------------------------------------------------- */

/* Release all owned members of an artifact and zero it (NULL-safe). */
void scrypt_artifact_free(scrypt_artifact_t *art);

/* Release a single typed value's owned members recursively (NULL-safe). */
void scrypt_arg_free(scrypt_arg_t *arg);

/* Release an instance's owned ctor/state value arrays (does NOT free the
 * borrowed artifact). NULL-safe. */
void scrypt_instance_free(scrypt_instance_t *inst);

#endif /* BONSAI_SCRYPT_SCRYPT_CONTRACT_H */
