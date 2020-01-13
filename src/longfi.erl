-module(longfi).

-export([deserialize/1,
         get_fingerprint/2,
         serialize/5]).

-on_load(init/0).

-include_lib("helium_proto/src/pb/helium_longfi_pb.hrl").


-record(monolithic_flags, {downlink :: boolean(),
                           should_ack :: boolean(),
                           cts_rts :: boolean(),
                           priority :: boolean(),
                           ldpc :: boolean()}).

-record(monolithic, {flags :: #monolithic_flags{},
                     oui :: non_neg_integer(),
                     did :: non_neg_integer(),
                     fp :: non_neg_integer(),
                     seq :: non_neg_integer(),
                     payload :: binary()}).


-record(ack_flags, {failure :: boolean(),
                    session_expired :: boolean(),
                    cts_rts :: boolean(),
                    retransmit :: boolean(),
                    ldpc :: boolean()}).

-record(ack, {flags :: #ack_flags{},
              oui :: non_neg_integer(),
              did :: non_neg_integer(),
              fp :: non_neg_integer(),
              seq :: non_neg_integer(),
              payload :: binary()}).


-record(frame_start_flags, {downlink :: boolean(),
                            should_ack :: boolean(),
                            cts_rts :: boolean(),
                            priority :: boolean()}).

-record(frame_start, {flags :: #frame_start_flags{},
                      oui :: non_neg_integer(),
                      did :: non_neg_integer(),
                      fp :: non_neg_integer(),
                      seq :: non_neg_integer(),
                      fragments :: non_neg_integer(),
                      payload :: binary()}).


-record(frame_data_flags, { ldpc :: boolean() }).

-record(frame_data, {flags :: #frame_data_flags{},
                     oui :: non_neg_integer(),
                     did :: non_neg_integer(),
                     fp :: non_neg_integer(),
                     fragment :: non_neg_integer(),
                     payload :: binary()}).




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




-define(APPNAME, longfi).
-define(LIBNAME, 'longfi').

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
