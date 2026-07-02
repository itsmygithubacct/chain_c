/*
 * scrypt_contract.c — lifecycle / free routines for the parsed scryptlib
 * compiled-artifact model and the typed constructor-argument value tree.
 *
 * This file owns ONLY the deallocation discipline for scrypt_artifact_t,
 * scrypt_arg_t (recursive), and scrypt_instance_t. The JSON->artifact parse and
 * ctor-arg flattening live in artifact_loader.c; the encoders/script
 * reconstruction live in script_codec.c. Keeping the free logic here matches the
 * header split and ensures every owner frees its own tree consistently.
 */
#include "scrypt/scrypt_contract.h"
#include "crypto/bignum.h"

#include <stdlib.h>
#include <string.h>

/* ---- param / struct internal free helpers ------------------------------- */

static void param_free_one(scrypt_param_t *p)
{
    if (!p) return;
    free(p->name);
    free(p->type_name);
    p->name = NULL;
    p->type_name = NULL;
}

static void params_free(scrypt_param_t *arr, size_t n)
{
    if (!arr) return;
    for (size_t i = 0; i < n; i++) param_free_one(&arr[i]);
    free(arr);
}

static void structs_free(scrypt_struct_t *arr, size_t n)
{
    if (!arr) return;
    for (size_t i = 0; i < n; i++) {
        free(arr[i].name);
        params_free(arr[i].fields, arr[i].num_fields);
    }
    free(arr);
}

/* ---- scrypt_artifact_t --------------------------------------------------- */

void scrypt_artifact_free(scrypt_artifact_t *art)
{
    if (!art) return;
    free(art->contract);
    free(art->hex_template);
    params_free(art->ctor_params, art->num_ctor_params);
    structs_free(art->structs, art->num_structs);
    params_free(art->state_props, art->num_state_props);
    memset(art, 0, sizeof(*art));
}

/* ---- scrypt_arg_t (recursive) ------------------------------------------- */

void scrypt_arg_free(scrypt_arg_t *arg)
{
    if (!arg) return;
    switch (arg->tag) {
    case SCRYPT_TYPE_INT:
        bn_free(arg->as.int_val);
        arg->as.int_val = NULL;
        break;
    case SCRYPT_TYPE_RABIN_PUBKEY:
        bn_free(arg->as.rabin_val);
        arg->as.rabin_val = NULL;
        break;
    case SCRYPT_TYPE_BOOL:
        break;
    case SCRYPT_TYPE_BYTES:
    case SCRYPT_TYPE_PUBKEY:
    case SCRYPT_TYPE_SHA256:
    case SCRYPT_TYPE_RIPEMD160:
        byte_buf_free(&arg->as.bytes_val);
        break;
    case SCRYPT_TYPE_FIXED_ARRAY:
        if (arg->as.array.elems) {
            for (size_t i = 0; i < arg->as.array.count; i++)
                scrypt_arg_free(&arg->as.array.elems[i]);
            free(arg->as.array.elems);
        }
        arg->as.array.elems = NULL;
        arg->as.array.count = 0;
        break;
    case SCRYPT_TYPE_STRUCT:
        free(arg->as.st.struct_name);
        if (arg->as.st.fields) {
            for (size_t i = 0; i < arg->as.st.num_fields; i++)
                scrypt_arg_free(&arg->as.st.fields[i]);
            free(arg->as.st.fields);
        }
        arg->as.st.struct_name = NULL;
        arg->as.st.fields = NULL;
        arg->as.st.num_fields = 0;
        break;
    }
}

/* ---- scrypt_instance_t --------------------------------------------------- */

void scrypt_instance_free(scrypt_instance_t *inst)
{
    if (!inst) return;
    if (inst->ctor_values) {
        for (size_t i = 0; i < inst->num_ctor_values; i++)
            scrypt_arg_free(&inst->ctor_values[i]);
        free(inst->ctor_values);
    }
    if (inst->state_values) {
        for (size_t i = 0; i < inst->num_state_values; i++)
            scrypt_arg_free(&inst->state_values[i]);
        free(inst->state_values);
    }
    inst->ctor_values = NULL;
    inst->num_ctor_values = 0;
    inst->state_values = NULL;
    inst->num_state_values = 0;
    inst->artifact = NULL;
}
