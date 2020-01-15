-module(longfi).

-export([deserialize/1,
         get_fingerprint/2,
         serialize/1]).

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


-spec serialize(#monolithic{} | #ack{} | #frame_start{} | #frame_data{}) -> binary().
serialize(#monolithic{flags = #monolithic_flags{downlink = Downlink, should_ack = ShouldAck, cts_rts = CtsRts, priority = Priority, ldpc = LDPC}, oui=OUI, did=DID, seq=Sequence, fp=Fingerprint, payload=Payload}) ->
    serialize_monolithic(Downlink, ShouldAck, CtsRts, Priority, LDPC, OUI, DID, Sequence, Fingerprint, Payload);
serialize(#ack{flags = #ack_flags{failure = Failure, session_expired = SessionExpired, cts_rts = CtsRts, retransmit = Retransmit, ldpc = LDPC}, oui=OUI, did=DID, seq=Sequence, fp=Fingerprint, payload=Payload}) ->
    serialize_ack(Failure, SessionExpired, CtsRts, Retransmit, LDPC, OUI, DID, Sequence, Fingerprint, Payload);
serialize(#frame_start{flags = #frame_start_flags{downlink = Downlink, should_ack = ShouldAck, cts_rts = CtsRts, priority = Priority}, oui=OUI, did=DID, seq=Sequence, fragments=Fragments, fp=Fingerprint, payload=Payload}) ->
    serialize_frame_start(Downlink, ShouldAck, CtsRts, Priority, OUI, DID, Sequence, Fragments, Fingerprint, Payload);
serialize(#frame_data{flags = #frame_data_flags{ldpc = LDPC}, oui=OUI, did=DID, fragment=Fragment, fp=Fingerprint, payload=Payload}) ->
    serialize_frame_data(LDPC, OUI, DID, Fragment, Fingerprint, Payload).


serialize_monolithic(_Downlink, _ShouldAck, _CtsRts, _Priority, _LDPC, _OUI, _DID, _Sequence, _Fingerprint, _Payload) ->
    not_loaded(?LINE).


serialize_ack(_Failure, _SessionExpired, _CtsRts, _Retransmit, _LDPC, _OUI, _DID, _Sequence, _Fingerprint, _Payload) ->
    not_loaded(?LINE).


serialize_frame_start(_Downlink, _ShouldAck, _CtsRts, _Priority, _OUI, _DID, _Sequence, _Fragments, _Fingerprint, _Payload) ->
    not_loaded(?LINE).


serialize_frame_data(_LDPC, _OUI, _DID, _Fragment, _Fingerprint, _Payload) ->
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
