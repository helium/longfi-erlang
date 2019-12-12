/*
 * Copyright 2018 Helium Systems Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "cursor/cursor.h"
#include "erl_nif.h"
#include "lfc/fingerprint.h"
#include "lfc/lfc.h"
#include "lfc/priv/lfc_dg_ser.h"
#include <stdbool.h>
#include <string.h>

static ERL_NIF_TERM ATOM_TRUE;
static ERL_NIF_TERM ATOM_FALSE;

static ERL_NIF_TERM
erl_lfc_dg_monolithic_serialize(ErlNifEnv *        env,
                                int                argc,
                                const ERL_NIF_TERM argv[]) {
    struct lfc_dg_monolithic dg = {{0}};

    if (!enif_get_uint(env, argv[0], &dg.oui)) {
        return enif_make_badarg(env);
    }

    if (!enif_get_uint(env, argv[1], &dg.did)) {
        return enif_make_badarg(env);
    }

    if (!enif_get_uint(env, argv[2], &dg.seq)) {
        return enif_make_badarg(env);
    }

    if (!enif_get_uint(env, argv[3], &dg.fp)) {
        return enif_make_badarg(env);
    }

    ErlNifBinary payload;
    if (!enif_inspect_binary(env, argv[4], &payload)) {
        return enif_make_badarg(env);
    }
    if (payload.size > LFC_DG_CONSTANTS_MAX_PAY_LEN) {
        return enif_make_badarg(env);
    }
    memcpy(dg.pay, payload.data, payload.size);
    dg.pay_len = payload.size;

    // TODO: how to (need to?) handle allocation failure in NIFs?
    ErlNifBinary des_bin;
    enif_alloc_binary(256, &des_bin);

    struct cursor csr = cursor_new(des_bin.data, des_bin.size);
    if (lfc_dg_monolithic__ser(&dg, &csr) != lfc_res_ok) {
        enif_release_binary(&des_bin);
        return enif_make_badarg(env);
    }
    // TODO: see above todo
    enif_realloc_binary(&des_bin, csr.pos);

    return enif_make_binary(env, &des_bin);
}

static ERL_NIF_TERM
erl_lfc_fingerprint_monolithic(ErlNifEnv *        env,
                               int                argc,
                               const ERL_NIF_TERM argv[]) {
    ErlNifBinary key, payload;
    int          tmpint;

    uint16_t hdr;
    uint32_t oui;
    uint32_t did;
    uint32_t seq;
    uint32_t fp;

    if (!enif_inspect_binary(env, argv[0], &key)) {
        return enif_make_badarg(env);
    }

    if (!enif_get_int(env, argv[1], &tmpint)) {
        return enif_make_badarg(env);
    }
    hdr = (uint16_t)tmpint;

    if (!enif_get_int(env, argv[2], &tmpint)) {
        return enif_make_badarg(env);
    }
    oui = (uint32_t)tmpint;

    if (!enif_get_int(env, argv[3], &tmpint)) {
        return enif_make_badarg(env);
    }
    did = (uint32_t)tmpint;

    if (!enif_get_int(env, argv[4], &tmpint)) {
        return enif_make_badarg(env);
    }
    seq = (uint32_t)tmpint;

    if (!enif_inspect_binary(env, argv[5], &payload)) {
        return enif_make_badarg(env);
    }

    if (lfc_fingerprint_monolithic(
            key.data, key.size, hdr, oui, did, seq, payload.data, payload.size, &fp)
        == lfc_res_ok) {
        return enif_make_uint(env, fp);
    }
    return enif_make_badarg(env);
}


#define ATOM(Id, Value)                                                        \
    { Id = enif_make_atom(env, Value); }

static ErlNifFunc nif_funcs[] = {
    {"fingerprint_monolithic", 6, erl_lfc_fingerprint_monolithic, 0},
    {"serialize_monolithic", 5, erl_lfc_dg_monolithic_serialize, 0}};

static int
load(ErlNifEnv * env, void ** priv_data, ERL_NIF_TERM load_info) {
    (void)priv_data;
    (void)load_info;

    ATOM(ATOM_TRUE, "true");
    ATOM(ATOM_FALSE, "false");

    return 0;
}

ERL_NIF_INIT(longfi, nif_funcs, load, NULL, NULL, NULL);
