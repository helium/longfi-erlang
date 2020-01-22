-module(longfi).

-export([new/6,
         deserialize/1,
         get_fingerprint/2,
         serialize/2,
         type/1,
         oui/1,
         oui/2,
         device_id/1,
         device_id/2,
         sequence_number/1,
         sequence_number/2,
         fingerprint/1,
         payload/1,
         payload/2,
         flags/1,
         flags/2
        ]).

-on_load(init/0).

-include_lib("helium_proto/src/pb/helium_longfi_pb.hrl").


-record(monolithic_flags, {downlink = false :: boolean(),
                           should_ack = false :: boolean(),
                           cts_rts = false :: boolean(),
                           priority = false :: boolean(),
                           ldpc = false :: boolean()}).

-record(monolithic, {flags = #monolithic_flags{} :: #monolithic_flags{},
                     oui = 0 :: non_neg_integer(),
                     did = 0 :: non_neg_integer(),
                     fp = 0 :: non_neg_integer(),
                     seq = 0 :: non_neg_integer(),
                     payload = <<>> :: binary()}).


-record(ack_flags, {failure = false :: boolean(),
                    session_expired = false :: boolean(),
                    cts_rts = false :: boolean(),
                    retransmit = false :: boolean(),
                    ldpc = false :: boolean()}).

-record(ack, {flags = #ack_flags{} :: #ack_flags{},
              oui = 0 :: non_neg_integer(),
              did = 0 :: non_neg_integer(),
              fp = 0 :: non_neg_integer(),
              seq = 0 :: non_neg_integer(),
              payload = <<>> :: binary()}).


-record(frame_start_flags, {downlink = false :: boolean(),
                            should_ack = false :: boolean(),
                            cts_rts = false :: boolean(),
                            priority = false :: boolean()}).

-record(frame_start, {flags = #frame_start_flags{} :: #frame_start_flags{},
                      oui = 0 :: non_neg_integer(),
                      did = 0:: non_neg_integer(),
                      fp = 0 :: non_neg_integer(),
                      seq = 0 :: non_neg_integer(),
                      fragments = 0 :: non_neg_integer(),
                      payload = <<>> :: binary()}).


-record(frame_data_flags, { ldpc = false :: boolean() }).

-record(frame_data, {flags = #frame_data_flags{} :: #frame_data_flags{},
                     oui = 0 :: non_neg_integer(),
                     did = 0 :: non_neg_integer(),
                     fp = 0 :: non_neg_integer(),
                     fragment = 0 :: non_neg_integer(),
                     payload = <<>> :: binary()}).

-type packet() :: #monolithic{} | #ack{} | #frame_start{} | #frame_data{}.

new(Type, OUI, DID, Seq, Payload, Flags) ->
    Packet = case Type of
                 monolithic -> #monolithic{};
                 ack -> #ack{}
             end,
    oui(OUI, device_id(DID, sequence_number(Seq, payload(Payload, flags(Flags, Packet))))).

-spec get_fingerprint(#helium_LongFiRxPacket_pb{}, binary()) -> non_neg_integer().
get_fingerprint(#helium_LongFiRxPacket_pb{tag_bits=Header, oui=OUI, device_id=DID, sequence=Sequence, payload=Payload}, Key) ->
    fingerprint_monolithic(Key, Header, OUI, DID, Sequence, Payload).


fingerprint_monolithic(_Key, _Header, _OUI, _DID, _Sequence, _Payload) ->
    not_loaded(?LINE).


-spec serialize(binary(), packet()) -> binary().
serialize(Key, #monolithic{flags = #monolithic_flags{downlink = Downlink, should_ack = ShouldAck, cts_rts = CtsRts, priority = Priority, ldpc = LDPC}, oui=OUI, did=DID, seq=Sequence, payload=Payload}) ->
    serialize_monolithic(Key, Downlink, ShouldAck, CtsRts, Priority, LDPC, OUI, DID, Sequence, Payload);
serialize(_, #ack{flags = #ack_flags{failure = Failure, session_expired = SessionExpired, cts_rts = CtsRts, retransmit = Retransmit, ldpc = LDPC}, oui=OUI, did=DID, seq=Sequence, fp=Fingerprint, payload=Payload}) ->
    serialize_ack(Failure, SessionExpired, CtsRts, Retransmit, LDPC, OUI, DID, Sequence, Fingerprint, Payload);
serialize(_, #frame_start{flags = #frame_start_flags{downlink = Downlink, should_ack = ShouldAck, cts_rts = CtsRts, priority = Priority}, oui=OUI, did=DID, seq=Sequence, fragments=Fragments, fp=Fingerprint, payload=Payload}) ->
    serialize_frame_start(Downlink, ShouldAck, CtsRts, Priority, OUI, DID, Sequence, Fragments, Fingerprint, Payload);
serialize(_, #frame_data{flags = #frame_data_flags{ldpc = LDPC}, oui=OUI, did=DID, fragment=Fragment, fp=Fingerprint, payload=Payload}) ->
    serialize_frame_data(LDPC, OUI, DID, Fragment, Fingerprint, Payload).


serialize_monolithic(_Downlink, _ShouldAck, _CtsRts, _Priority, _LDPC, _OUI, _DID, _Sequence, _Fingerprint, _Payload) ->
    not_loaded(?LINE).


serialize_ack(_Failure, _SessionExpired, _CtsRts, _Retransmit, _LDPC, _OUI, _DID, _Sequence, _Fingerprint, _Payload) ->
    not_loaded(?LINE).


serialize_frame_start(_Downlink, _ShouldAck, _CtsRts, _Priority, _OUI, _DID, _Sequence, _Fragments, _Fingerprint, _Payload) ->
    not_loaded(?LINE).


serialize_frame_data(_LDPC, _OUI, _DID, _Fragment, _Fingerprint, _Payload) ->
    not_loaded(?LINE).


-spec deserialize(binary()) -> error | {ok, packet()}.
deserialize(_Bin) ->
    not_loaded(?LINE).


-spec type(Packet :: packet()) -> 'monolithic' | 'ack' | 'frame_start' | 'frame_data'.
type(#monolithic{}) -> monolithic;
type(#ack{}) -> ack;
type(#frame_start{}) -> frame_start;
type(#frame_data{}) -> frame_data.

-spec oui(Packet :: packet()) -> non_neg_integer().
oui(#monolithic{oui=OUI}) -> OUI;
oui(#ack{oui=OUI}) -> OUI;
oui(#frame_start{oui=OUI}) -> OUI;
oui(#frame_data{oui=OUI}) -> OUI.

-spec oui(OUI :: non_neg_integer(), Packet :: packet()) -> packet().
oui(OUI, Packet=#monolithic{}) -> Packet#monolithic{oui=OUI};
oui(OUI, Packet=#ack{}) -> Packet#ack{oui=OUI};
oui(OUI, Packet=#frame_start{}) -> Packet#frame_start{oui=OUI};
oui(OUI, Packet=#frame_data{}) -> Packet#frame_data{oui=OUI}.

-spec device_id(Packet :: packet()) -> non_neg_integer().
device_id(#monolithic{did=DID}) -> DID;
device_id(#ack{did=DID}) -> DID;
device_id(#frame_start{did=DID}) -> DID;
device_id(#frame_data{did=DID}) -> DID.

-spec device_id(DID :: non_neg_integer(), Packet :: packet()) -> packet().
device_id(DID, Packet=#monolithic{}) -> Packet#monolithic{did=DID};
device_id(DID, Packet=#ack{}) -> Packet#ack{did=DID};
device_id(DID, Packet=#frame_start{}) -> Packet#frame_start{did=DID};
device_id(DID, Packet=#frame_data{}) -> Packet#frame_data{did=DID}.

-spec sequence_number(Packet :: packet()) -> non_neg_integer().
sequence_number(#monolithic{seq=Seq}) -> Seq;
sequence_number(#ack{seq=Seq}) -> Seq;
sequence_number(#frame_start{seq=Seq}) -> Seq.

-spec sequence_number(Seq :: non_neg_integer(), Packet :: packet()) -> packet().
sequence_number(Seq, Packet=#monolithic{}) -> Packet#monolithic{seq=Seq};
sequence_number(Seq, Packet=#ack{}) -> Packet#ack{seq=Seq};
sequence_number(Seq, Packet=#frame_start{}) -> Packet#frame_start{seq=Seq}.

-spec fingerprint(Packet :: packet()) -> non_neg_integer().
fingerprint(#monolithic{fp=Fp}) -> Fp;
fingerprint(#ack{fp=Fp}) -> Fp;
fingerprint(#frame_start{fp=Fp}) -> Fp;
fingerprint(#frame_data{fp=Fp}) -> Fp.

-spec payload(Packet :: packet()) -> binary().
payload(#monolithic{payload=Payload}) -> Payload;
payload(#ack{payload=Payload}) -> Payload;
payload(#frame_start{payload=Payload}) -> Payload;
payload(#frame_data{payload=Payload}) -> Payload.

-spec payload(Payload :: binary(), Packet :: packet()) -> packet().
payload(Payload, Packet=#monolithic{}) -> Packet#monolithic{payload=Payload};
payload(Payload, Packet=#ack{}) -> Packet#ack{payload=Payload};
payload(Payload, Packet=#frame_start{}) -> Packet#frame_start{payload=Payload};
payload(Payload, Packet=#frame_data{}) -> Packet#frame_data{payload=Payload}.

-spec flags(Packet :: packet()) -> map().
flags(#monolithic{flags=#monolithic_flags{downlink=Downlink, should_ack=ShouldAck, cts_rts=CTSRTS, priority=Priority, ldpc=LDPC}}) ->
    #{downlink => Downlink,
      should_ack => ShouldAck,
      cts_rts => CTSRTS,
      priority => Priority,
      ldpc => LDPC};
flags(#ack{flags=Flags}) ->
    #{failure => Flags#ack_flags.failure,
      session_expired => Flags#ack_flags.session_expired,
      cts_rts => Flags#ack_flags.cts_rts,
      restransmit => Flags#ack_flags.retransmit,
      ldpc => Flags#ack_flags.ldpc};
flags(#frame_start{flags=Flags}) ->
    #{downlink => Flags#frame_start_flags.downlink,
      should_ack => Flags#frame_start_flags.should_ack,
      cts_rts => Flags#frame_start_flags.cts_rts,
      priority => Flags#frame_start_flags.priority};
flags(#frame_data{flags=Flags}) ->
    #{ldpc => Flags#frame_data_flags.ldpc}.

flags(Flags, #monolithic{}=Packet) ->
    Packet#monolithic{flags=#monolithic_flags{
                               downlink=maps:get(downlink, Flags, false) == true,
                               should_ack=maps:get(should_ack, Flags, false) == true,
                               cts_rts=maps:get(cts_rts, Flags, false) == true,
                               priority=maps:get(priority, Flags, false) == true,
                               ldpc=maps:get(ldpc, Flags, false) == true}};
flags(Flags, #ack{}=Packet) ->
    Packet#ack{flags=#ack_flags{
                        failure=maps:get(failure, Flags, false) == true,
                        session_expired=maps:get(session_expired, Flags, false) == true,
                        cts_rts=maps:get(cts_rts, Flags, false) == true,
                        retransmit=maps:get(retransmit, Flags, false) == true,
                        ldpc=maps:get(ldpc, Flags, false) == true }}.
%% TODO other flag types

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
