-module(longfi).

-export([get_fingerprint/2]).

-on_load(init/0).

-include_lib("helium_proto/src/pb/helium_longfi_pb.hrl").

-define(APPNAME, longfi).
-define(LIBNAME, 'longfi').

-spec get_fingerprint(#helium_LongFiRxPacket_pb{}, binary()) -> non_neg_integer().
get_fingerprint(#helium_LongFiRxPacket_pb{tag_bits=Header, oui=OUI, device_id=DID, sequence=Sequence, payload=Payload}, Key) ->
    fingerprint_monolithic(Key, Header, OUI, DID, Sequence, Payload).

fingerprint_monolithic(_Key, _Header, _OUI, _DID, _Sequence, _Payload) ->
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
