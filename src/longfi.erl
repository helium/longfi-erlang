-module(longfi).

-export([get_fingerprint/2]).
-export([serialize/5]).
-export([deserialize/1]).

-on_load(init/0).

-record(monolithic_flags, {downlink,
                           should_ack,
                           cts_rts,
                           priority,
                           ldpc}).

-record(monolithic, {flags,
                     oui,
                     did,
                     fp,
                     seq,
                     payload}).

-record(ack_flags, {failure,
                    session_expired,
                    cts_rts,
                    retransmit,
                    ldpc}).

-record(ack, {flags,
              oui,
              did,
              fp,
              seq,
              payload}).

-record(frame_start_flags, {downlink,
                            should_ack,
                            cts_rts,
                            priority}).

-record(frame_start, {flags,
                      oui,
                      did,
                      fp,
                      seq,
                      fragments,
                      payload}).

-record(frame_data_flags, { ldpc }).

-record(frame_data, {flags,
                     oui,
                     did,
                     fp,
                     fragment,
                     payload}).

-include_lib("helium_proto/src/pb/helium_longfi_pb.hrl").

-define(APPNAME, longfi).
-define(LIBNAME, 'longfi').

-spec get_fingerprint(#helium_LongFiRxPacket_pb{}, binary()) -> non_neg_integer().
get_fingerprint(#helium_LongFiRxPacket_pb{tag_bits=Header, oui=OUI, device_id=DID, sequence=Sequence, payload=Payload}, Key) ->
    fingerprint_monolithic(Key, Header, OUI, DID, Sequence, Payload).

fingerprint_monolithic(_Key, _Header, _OUI, _DID, _Sequence, _Payload) ->
    not_loaded(?LINE).

-spec serialize(non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer(), binary()) ->binary().
serialize(OUI, DID, Sequence, Fingerprint, Payload) ->
    serialize_monolithic(OUI, DID, Sequence, Fingerprint, Payload).

serialize_monolithic(_OUI, _DID, _Sequence, _Fingerprint, _Payload) ->
    not_loaded(?LINE).

-spec deserialize(binary()) -> error | {ok, #monolithic{} | #ack{} | #frame_start{} | #frame_data{}}.
deserialize(_Bin) ->
    not_loaded(?LINE).

init() ->
    SoName = case code:priv_dir(?APPNAME) of
                 {error, bad_name} ->
                     case filelib:is_dir(filename:join(["..", priv])) of
                         true ->
                             filename:join(["..", priv, ?LIBNAME]);
                         _ ->
                             filename:join([priv, ?LIBNAME])
                     end;
                 Dir ->
                     filename:join(Dir, ?LIBNAME)
             end,
    erlang:load_nif(SoName, 0).

not_loaded(Line) ->
    erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, Line}]}).
