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
#include "lfc/priv/lfc_dg_des.h"
#include "lfc/priv/lfc_dg_ser.h"
#include <stdbool.h>
#include <string.h>


static ERL_NIF_TERM ATOM_OK;
static ERL_NIF_TERM ATOM_ERROR;
static ERL_NIF_TERM ATOM_TRUE;
static ERL_NIF_TERM ATOM_FALSE;
static ERL_NIF_TERM ATOM_ACK;
static ERL_NIF_TERM ATOM_ACK_FLAGS;
static ERL_NIF_TERM ATOM_FRAME_DATA;
static ERL_NIF_TERM ATOM_FRAME_DATA_FLAGS;
static ERL_NIF_TERM ATOM_FRAME_START;
static ERL_NIF_TERM ATOM_FRAME_START_FLAGS;
static ERL_NIF_TERM ATOM_MONOLITHIC;
static ERL_NIF_TERM ATOM_MONOLITHIC_FLAGS;

static ERL_NIF_TERM
bool_to_term(bool val) {
    return val ? ATOM_TRUE : ATOM_FALSE;
}

static int
term_to_bool(ErlNifEnv * env, ERL_NIF_TERM term, bool * bp) {
    if (enif_is_identical(term, ATOM_TRUE)) {
        *bp = true;
        return 1;
    } else if (enif_is_identical(term, ATOM_FALSE)) {
        *bp = false;
        return 1;
    } else {
        return 0;
    }
}

#define GET_UINT(env__, term__, dst__)                                         \
    do {                                                                       \
        if (!enif_get_uint(env__, term__, dst__)) {                            \
            return enif_make_badarg(env);                                      \
        }                                                                      \
    } while (0);

#define GET_BOOL(env__, term__, dst__)                                         \
    do {                                                                       \
        if (!term_to_bool(env__, term__, dst__)) {                             \
            return enif_make_badarg(env);                                      \
        }                                                                      \
    } while (0);

static ERL_NIF_TERM
erl_lfc_dg_monolithic_to_term(ErlNifEnv *                      env,
                              struct lfc_dg_monolithic const * dg) {
    ERL_NIF_TERM flags = enif_make_tuple6(env,
                                          ATOM_MONOLITHIC_FLAGS,
                                          bool_to_term(dg->flags.downlink),
                                          bool_to_term(dg->flags.should_ack),
                                          bool_to_term(dg->flags.cts_rts),
                                          bool_to_term(dg->flags.priority),
                                          bool_to_term(dg->flags.ldpc));
    ERL_NIF_TERM oui   = enif_make_int(env, dg->oui);
    ERL_NIF_TERM did   = enif_make_int(env, dg->did);
    ERL_NIF_TERM seq   = enif_make_int(env, dg->seq);
    ERL_NIF_TERM fp    = enif_make_int(env, dg->fp);
    ERL_NIF_TERM payload;
    void *       p = enif_make_new_binary(env, dg->pay_len, &payload);
    memcpy(p, dg->pay, dg->pay_len);
    return enif_make_tuple7(env, ATOM_MONOLITHIC, flags, oui, did, seq, fp, payload);
}

static ERL_NIF_TERM
erl_lfc_dg_ack_to_term(ErlNifEnv * env, struct lfc_dg_ack const * dg) {
    ERL_NIF_TERM flags = enif_make_tuple6(env,
                                          ATOM_ACK_FLAGS,
                                          bool_to_term(dg->flags.failure),
                                          bool_to_term(dg->flags.session_expired),
                                          bool_to_term(dg->flags.cts_rts),
                                          bool_to_term(dg->flags.retransmit),
                                          bool_to_term(dg->flags.ldpc));
    ERL_NIF_TERM oui   = enif_make_int(env, dg->oui);
    ERL_NIF_TERM did   = enif_make_int(env, dg->did);
    ERL_NIF_TERM fp    = enif_make_int(env, dg->fp);
    ERL_NIF_TERM seq   = enif_make_int(env, dg->seq);
    ERL_NIF_TERM payload;
    void *       p = enif_make_new_binary(env, dg->pay_len, &payload);
    memcpy(p, dg->pay, dg->pay_len);
    return enif_make_tuple7(env, ATOM_MONOLITHIC, flags, oui, did, seq, fp, payload);
}

static ERL_NIF_TERM
erl_lfc_dg_frame_start_to_term(ErlNifEnv *                       env,
                               struct lfc_dg_frame_start const * dg) {
    ERL_NIF_TERM flags = enif_make_tuple6(env,
                                          ATOM_FRAME_START_FLAGS,
                                          bool_to_term(dg->flags.downlink),
                                          bool_to_term(dg->flags.should_ack),
                                          bool_to_term(dg->flags.cts_rts),
                                          bool_to_term(dg->flags.priority),
                                          bool_to_term(dg->flags.ldpc));
    ERL_NIF_TERM oui   = enif_make_int(env, dg->oui);
    ERL_NIF_TERM did   = enif_make_int(env, dg->did);
    ERL_NIF_TERM seq   = enif_make_int(env, dg->seq);
    ERL_NIF_TERM fp    = enif_make_int(env, dg->fp);
    ERL_NIF_TERM payload;
    void *       p = enif_make_new_binary(env, dg->pay_len, &payload);
    memcpy(p, dg->pay, dg->pay_len);
    return enif_make_tuple7(env, ATOM_FRAME_START, flags, oui, did, seq, fp, payload);
}

static ERL_NIF_TERM
erl_lfc_dg_frame_data_to_term(ErlNifEnv *                      env,
                              struct lfc_dg_frame_data const * dg) {
    ERL_NIF_TERM flags = bool_to_term(
        enif_make_tuple2(env, ATOM_FRAME_DATA_FLAGS, dg->flags.ldpc));
    ERL_NIF_TERM oui = enif_make_int(env, dg->oui);
    ERL_NIF_TERM did = enif_make_int(env, dg->did);
    ERL_NIF_TERM seq = enif_make_int(env, dg->fragment);
    ERL_NIF_TERM fp  = enif_make_int(env, dg->fp);
    ERL_NIF_TERM payload;
    void *       p = enif_make_new_binary(env, dg->pay_len, &payload);
    memcpy(p, dg->pay, dg->pay_len);
    return enif_make_tuple7(env, ATOM_FRAME_DATA, flags, oui, did, seq, fp, payload);
}

static ERL_NIF_TERM
erl_lfc_dg_monolithic_serialize(ErlNifEnv *        env,
                                int                argc,
                                const ERL_NIF_TERM argv[]) {
    struct lfc_dg_monolithic dg = {{0}};

    GET_BOOL(env, argv[0], &dg.flags.downlink);
    GET_BOOL(env, argv[1], &dg.flags.should_ack);
    GET_BOOL(env, argv[2], &dg.flags.cts_rts);
    GET_BOOL(env, argv[3], &dg.flags.priority);
    GET_BOOL(env, argv[4], &dg.flags.ldpc);
    GET_UINT(env, argv[5], &dg.oui);
    GET_UINT(env, argv[6], &dg.did);
    GET_UINT(env, argv[7], &dg.seq);
    GET_UINT(env, argv[8], &dg.fp);

    ErlNifBinary payload;
    if (!enif_inspect_binary(env, argv[9], &payload)) {
        return enif_make_badarg(env);
    }
    if (payload.size > LFC_DG_CONSTANTS_MAX_PAY_LEN) {
        return enif_make_badarg(env);
    }
    memcpy(dg.pay, payload.data, payload.size);
    dg.pay_len = payload.size;

    // TODO: how to (need to) handle allocation failure in NIFs?
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
erl_lfc_dg_deserialize(ErlNifEnv * env, int argc, const ERL_NIF_TERM argv[]) {
    ErlNifBinary bin;

    if (!enif_inspect_binary(env, argv[0], &bin)) {
        return enif_make_badarg(env);
    }

    struct cursor     csr = cursor_new(bin.data, bin.size);
    struct lfc_dg_des dg;
    if (lfc_dg__des(&dg, &csr) != lfc_res_ok) {
        return ATOM_ERROR;
    }

    switch (dg.type) {
    case lfc_dg_type_monolithic:
        return enif_make_tuple2(
            env, ATOM_OK, erl_lfc_dg_monolithic_to_term(env, &dg.monolithic));
        break;
    case lfc_dg_type_frame_start:
        return enif_make_tuple2(
            env, ATOM_OK, erl_lfc_dg_frame_start_to_term(env, &dg.frame_start));
        break;
    case lfc_dg_type_frame_data:
        return enif_make_tuple2(
            env, ATOM_OK, erl_lfc_dg_frame_data_to_term(env, &dg.frame_data));
        break;
    case lfc_dg_type_ack:
        return enif_make_tuple2(env,
                                ATOM_OK,
                                erl_lfc_dg_ack_to_term(env, &dg.ack));
        break;
    default:
        break;
    }
    return ATOM_ERROR;
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
    {"serialize_monolithic", 10, erl_lfc_dg_monolithic_serialize, 0},
    {"deserialize", 1, erl_lfc_dg_deserialize, 0}};

static int
load(ErlNifEnv * env, void ** priv_data, ERL_NIF_TERM load_info) {
    (void)priv_data;
    (void)load_info;

    ATOM(ATOM_TRUE, "true");
    ATOM(ATOM_FALSE, "false");
    ATOM(ATOM_OK, "ok");
    ATOM(ATOM_ERROR, "error");
    ATOM(ATOM_ACK, "ack");
    ATOM(ATOM_ACK_FLAGS, "ack_flags");
    ATOM(ATOM_FRAME_DATA, "frame_data");
    ATOM(ATOM_FRAME_DATA_FLAGS, "frame_data_flags");
    ATOM(ATOM_FRAME_START, "frame_start");
    ATOM(ATOM_FRAME_START_FLAGS, "frame_start_flags");
    ATOM(ATOM_MONOLITHIC, "monolithic");
    ATOM(ATOM_MONOLITHIC_FLAGS, "monolithic_flags");

    return 0;
}

ERL_NIF_INIT(longfi, nif_funcs, load, NULL, NULL, NULL);
