-module(custom_verify_resource).

-behaviour(gen_mod).

-include("mongoose.hrl").
-include("jlib.hrl").

% gen_mod callbacks
-export([start/2, stop/1, user_send_message/3]).

start(HostType, _Opts) ->
    gen_hook:add_handlers(hooks(HostType)).

stop(HostType) ->
    gen_hook:delete_hanlders(hooks(HostType)).


hooks(HostType) ->
    [
        {user_send_message, HostType, fun ?MODULE:user_send_message/3, #{}, 88}
    ].


-spec user_send_message(mongoose_acc:t(), mongoose_c2s_hooks:params(), gen_hook:extra()) ->
      mongoose_c2s_hooks:result().
user_send_message(Acc, Params, _) ->
    {From, To, Packet} = mongoose_acc:packet(Acc),
    % ?LOG_NOTICE(#{what => testing, pack => Packet, params => Params}),
    verify_rid(From, To, Packet, Acc).


verify_rid(From, To, Packet, Acc) ->
    Rid = exml_query:path(Packet, 
        [{element, <<"encrypted">>}, 
         {element, <<"header">>}, {element, <<"key">>}, {attr, <<"rid">>}], <<>>),     
    {jid, LUser, LServer, _} = To,    
    % ?LOG_NOTICE(#{what => testing, to => To, rid => Rid, luser => LUser, lserver => LServer}),
    case Rid of
        <<>> -> {ok, Acc};
        _ -> 
            Payloads = mod_pubsub_db_backend:get_user_payloads(LUser, LServer),
            % ?LOG_NOTICE(#{what => testing, payloads => Payloads}),
            case Payloads of
                [[<<"eu.siacs.conversations.axolotl.devicelist">>, _, DeviceList] | _] ->
                    % ?LOG_NOTICE(#{what => testing, devicelist => DeviceList}),
                    {ok, DeviceListXML} = exml:parse(DeviceList),
                    DeviceElements = exml_query:subelements(DeviceListXML, <<"device">>),
                    DeviceIDs = [exml_query:attr(Device, <<"id">>, undefined) || Device <- DeviceElements],
                    case lists:member(Rid, DeviceIDs) of
                        true -> {ok, Acc};
                        _ ->
                            ErrorStanza = mongoose_xmpp_errors:item_not_found(<<"en">>, 
                                    <<"Incorrect Device ID">>),
                            ejabberd_router:route(server_jid(From), From, ErrorStanza),     
                            {stop, Acc}   
                    end;
                _ -> 
                    ErrorStanza = mongoose_xmpp_errors:item_not_found(<<"en">>, 
                                    <<"Device list not found for this user">>),
                    ejabberd_router:route(server_jid(From), From, ErrorStanza),     
                    {stop, Acc}   
            end
    end.

server_jid(#jid{lserver = Host}) ->
    jid:from_binary(Host).