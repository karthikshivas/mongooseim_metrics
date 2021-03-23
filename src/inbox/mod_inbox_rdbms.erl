%%%-------------------------------------------------------------------
%%% @author ludwikbukowski
%%% @copyright (C) 2018, Erlang Solutions Ltd.
%%% @doc
%%%
%%% @end
%%% Created : 30. Jan 2018 16:59
%%%-------------------------------------------------------------------
-module(mod_inbox_rdbms).
-author("ludwikbukowski").
-include("jlib.hrl").
-include("mongoose.hrl").
-include("mod_inbox.hrl").

-behaviour(mod_inbox).

%% API
-export([get_inbox/3,
         init/2,
         set_inbox/7,
         set_inbox_incr_unread/6,
         reset_unread/4,
         remove_inbox/3,
         clear_inbox/1,
         clear_inbox/2,
         get_inbox_unread/3,
         get_entry_properties/2,
         set_entry_properties/3]).

%% For specific backends
-export([esc_string/1, esc_int/1]).


-type db_return() :: {username(),
                      binary(),
                      count_bin(),
                      non_neg_integer() | binary(),
                      binary(),
                      binary()}.

%% ----------------------------------------------------------------------
%% API
%% ----------------------------------------------------------------------

init(VHost, _Options) ->
    rdbms_queries:prepare_upsert(VHost, inbox_upsert, inbox,
                                 [<<"luser">>, <<"lserver">>, <<"remote_bare_jid">>,
                                  <<"content">>, <<"unread_count">>, <<"msg_id">>, <<"timestamp">>],
                                 [<<"content">>, <<"unread_count">>, <<"msg_id">>, <<"timestamp">>],
                                 [<<"luser">>, <<"lserver">>, <<"remote_bare_jid">>]),
    ok.

-spec get_inbox(LUsername :: jid:luser(),
                LServer :: jid:lserver(),
                Params :: mod_inbox:get_inbox_params()) -> get_inbox_res().
get_inbox(LUsername, LServer, Params) ->
    case get_inbox_rdbms(LUsername, LServer, Params) of
        {selected, []} ->
            [];
        {selected, Res} ->
            [decode_row(LServer, R) || R <- Res]
    end.


-spec get_inbox_rdbms(LUser :: jid:luser(),
                      LServer :: jid:lserver(),
                      Params :: mod_inbox:get_inbox_params()) ->
    mongoose_rdbms:query_result().
get_inbox_rdbms(LUser, LServer, #{ order := Order } = Params) ->
    OrderSQL = order_to_sql(Order),
    LimitSQL = sql_and_where_limit(maps:get(limit, Params, undefined)),
    BeginSQL = sql_and_where_timestamp(">=", maps:get(start, Params, undefined)),
    EndSQL = sql_and_where_timestamp("<=", maps:get('end', Params, undefined)),
    HiddenSQL = sql_and_where_unread_count(maps:get(hidden_read, Params, false)),
    Archive = sql_and_where_archive(maps:get(archive, Params, undefined)),
    Query = ["SELECT remote_bare_jid, content, unread_count, timestamp, archive, muted_until "
             " FROM inbox "
                 "WHERE luser=", esc_string(LUser),
                 " AND lserver=", esc_string(LServer),
                 BeginSQL, EndSQL, HiddenSQL, Archive,
                 " ORDER BY timestamp ", OrderSQL,
                 LimitSQL, ";"],
    mongoose_rdbms:sql_query(LServer, Query).

get_inbox_unread(Username, Server, InterlocutorJID) ->
    RemBareJIDBin = jid:to_binary(jid:to_lus(InterlocutorJID)),
    Res = mongoose_rdbms:sql_query(Server,
                                   ["select unread_count from inbox "
                                    "WHERE luser=", esc_string(Username),
                                      "AND lserver=", esc_string(Server),
                                      "AND remote_bare_jid=", esc_string(RemBareJIDBin),
                                    ";"]),
    {ok, Val} = check_result(Res),
    %% We read unread_count value when the message is sent and is not yet in receiver inbox
    %% so we have to add +1
    {ok, Val + 1}.

-spec set_inbox(Username, Server, ToBareJid, Content,
                Count, MsgId, Timestamp) -> inbox_write_res() when
                Username :: jid:luser(),
                Server :: jid:lserver(),
                ToBareJid :: binary(),
                Content :: binary(),
                Count :: integer(),
                MsgId :: binary(),
                Timestamp :: integer().
set_inbox(Username, Server, ToBareJid, Content, Count, MsgId, Timestamp) ->
    LUsername = jid:nodeprep(Username),
    LServer = jid:nameprep(Server),
    LToBareJid = jid:nameprep(ToBareJid),
    InsertParams = [LUsername, LServer, LToBareJid,
                    Content, Count, MsgId, Timestamp],
    UpdateParams = [Content, Count, MsgId, Timestamp],
    UniqueKeyValues  = [LUsername, LServer, LToBareJid],
    Res = rdbms_queries:execute_upsert(Server, inbox_upsert,
                                       InsertParams, UpdateParams, UniqueKeyValues),
    %% MySQL returns 1 when an upsert is an insert
    %% and 2, when an upsert acts as update
    ok = check_result(Res, [1, 2]).

-spec remove_inbox(User :: binary(),
    Server :: binary(),
    ToBareJid :: binary()) -> ok.
remove_inbox(Username, Server, ToBareJid) ->
    LUsername = jid:nodeprep(Username),
    LServer = jid:nameprep(Server),
    LToBareJid = jid:nameprep(ToBareJid),
    Res = remove_inbox_rdbms(LUsername, LServer, LToBareJid),
    check_result(Res).

-spec remove_inbox_rdbms(Username :: jid:luser(),
                         Server :: jid:lserver(),
                         ToBareJid :: binary()) -> mongoose_rdbms:query_result().
remove_inbox_rdbms(Username, Server, ToBareJid) ->
    mongoose_rdbms:sql_query(Server, ["delete from inbox where luser=",
        esc_string(Username), " and lserver=", esc_string(Server),
        " and remote_bare_jid=",
        esc_string(ToBareJid), ";"]).

%% This function was not refatorected to use the generic upsert helper
%% becase this helper doesn't support parametrized queries for incremental change
-spec set_inbox_incr_unread(Username :: binary(),
                            Server :: binary(),
                            ToBareJid :: binary(),
                            Content :: binary(),
                            MsgId :: binary(),
                            Timestamp :: integer()) -> ok | {ok, integer()}.
set_inbox_incr_unread(Username, Server, ToBareJid, Content, MsgId, Timestamp) ->
    LUsername = jid:nodeprep(Username),
    LServer = jid:nameprep(Server),
    LToBareJid = jid:nameprep(ToBareJid),
    BackendModule = rdbms_specific_backend(Server),
    Res = BackendModule:set_inbox_incr_unread(LUsername, LServer, LToBareJid,
                                              Content, MsgId, Timestamp),
    %% psql will return {updated, {[UnreadCount]}}
    %% mssql and mysql will return {selected, {[Val]}}
    check_result(Res).

-spec reset_unread(User :: binary(),
                   Server :: binary(),
                   BareJid :: binary(),
                   MsgId :: binary() | undefined) -> ok.
reset_unread(Username, Server, ToBareJid, MsgId) ->
    LUsername = jid:nodeprep(Username),
    LServer = jid:nameprep(Server),
    LToBareJid = jid:nameprep(ToBareJid),
    Res = reset_inbox_unread_rdbms(LUsername, LServer, LToBareJid, MsgId),
    check_result(Res).

-spec reset_inbox_unread_rdbms(Username :: jid:luser(),
                               Server :: jid:lserver(),
                               ToBareJid :: binary(),
                               MsgId :: binary() | undefined) -> mongoose_rdbms:query_result().
reset_inbox_unread_rdbms(Username, Server, ToBareJid, undefined) ->
    mongoose_rdbms:sql_query(Server, ["update inbox set unread_count=0",
        " where luser=", esc_string(Username),
        " and lserver=", esc_string(Server),
        " and remote_bare_jid=", esc_string(ToBareJid), ";"]);
reset_inbox_unread_rdbms(Username, Server, ToBareJid, MsgId) ->
    mongoose_rdbms:sql_query(Server, ["update inbox set unread_count=0 where luser=",
        esc_string(Username), " and lserver=", esc_string(Server), " and remote_bare_jid=",
        esc_string(ToBareJid), " and msg_id=", esc_string(MsgId), ";"]).

-spec clear_inbox(Username :: binary(), Server :: binary()) -> inbox_write_res().
clear_inbox(Username, Server) ->
    LUsername = jid:nodeprep(Username),
    LServer = jid:nameprep(Server),
    Res = clear_inbox_rdbms(LUsername, LServer),
    check_result(Res).

-spec clear_inbox(Server :: binary()) -> inbox_write_res().
clear_inbox( Server) ->
    LServer = jid:nameprep(Server),
    Res = clear_inbox_rdbms(LServer),
    check_result(Res).


-spec get_entry_properties(jid:jid(), binary()) ->
    {binary(), binary(), binary()}.
get_entry_properties(From, BinEntryJID) ->
    {LUser, LServer} = jid:to_lus(From),
    Query = ["SELECT archive, unread_count, muted_until ",
             "FROM inbox "
             "WHERE luser = ", esc_string(LUser), " AND "
                   "lserver = ", esc_string(LServer), " AND "
                   "remote_bare_jid = ", esc_string(BinEntryJID)],
    case mongoose_rdbms:sql_query(LServer, Query) of
        {selected, []} ->
            [];
        {selected, [Selected]} ->
            Selected
    end.

-spec set_entry_properties(jid:jid(), binary(), entry_props_params()) ->
    entry_properties() | {error, binary()}.
set_entry_properties(From, BinEntryJID, Params) ->
    {LUser, LServer} = jid:to_lus(From),
    UnreadCount = sql_set_unread_count(maps:get(unread_count, Params, undefined)),
    MutedUntil = sql_set_muted_until(maps:get(muted_until, Params, undefined)),
    Archive = sql_set_archive(maps:get(archive, Params, undefined)),
    Returning = returning_properties(mongoose_rdbms:db_engine(LServer), From, BinEntryJID),
    Query = ["UPDATE inbox ",
             "SET ", lists:droplast(lists:append([UnreadCount, MutedUntil, Archive])),
             " WHERE "
                 "luser=", esc_string(LUser), " AND "
                 "lserver=", esc_string(LServer), " AND "
                 "remote_bare_jid=", esc_string(BinEntryJID),
             Returning],
    case mongoose_rdbms:sql_query(LServer, Query) of
        {error, Msg} when is_list(Msg) ->
            {error, list_to_binary(Msg)};
        {error, Msg} ->
            {error, Msg};
        {updated, 0, []} ->
            {error, <<"item-not-found">>};
        {updated, 1, [Result]} ->
            Result;
        {selected, []} ->
            {error, <<"item-not-found">>};
        {selected, [Result]} ->
            Result
    end.

returning_properties(pgsql, _, _) ->
    ["RETURNING archive, unread_count, muted_until;"];
returning_properties(mysql, From, BinEntryJID) ->
    {LUser, LServer} = jid:to_lus(From),
    ["; SELECT archive, unread_count, muted_until"
        " FROM inbox"
        " WHERE "
            "luser=", esc_string(LUser), " AND "
            "lserver=", esc_string(LServer), " AND "
            "remote_bare_jid=", esc_string(BinEntryJID), ";"];
returning_properties(odbc, _, _) ->
    ["OUTPUT inserted.archive, inserted.unread_count, inserted.muted_until;"].

sql_set_archive(undefined) ->
    [];
sql_set_archive(true) ->
    ["archive=true", ","];
sql_set_archive(false) ->
    ["archive=false", ","].

sql_set_unread_count(undefined) ->
    [];
sql_set_unread_count(0) ->
    ["unread_count=0", ","];
sql_set_unread_count(1) ->
    ["unread_count = CASE unread_count WHEN 0 THEN 1 ELSE unread_count END", ","].

sql_set_muted_until(undefined) ->
    [];
sql_set_muted_until(0) ->
    ["muted_until=0", ","];
sql_set_muted_until(Int) ->
    ["muted_until=", esc_int(Int), ","].

-spec esc_string(binary() | string()) -> mongoose_rdbms:sql_query_part().
esc_string(String) ->
    mongoose_rdbms:use_escaped_string(mongoose_rdbms:escape_string(String)).

-spec esc_int(integer()) -> mongoose_rdbms:sql_query_part().
esc_int(Integer) ->
    mongoose_rdbms:use_escaped_integer(mongoose_rdbms:escape_integer(Integer)).


%% ----------------------------------------------------------------------
%% Internal functions
%% ----------------------------------------------------------------------

-spec order_to_sql(Order :: asc | desc) -> binary().
order_to_sql(asc) -> <<"ASC">>;
order_to_sql(desc) -> <<"DESC">>.

-spec sql_and_where_limit(boolean() | undefined) -> iolist().
sql_and_where_limit(undefined) ->
    [];
sql_and_where_limit(N) ->
    [" LIMIT ", esc_int(N), " "].

-spec sql_and_where_timestamp(Operator :: string(), Timestamp :: integer()) -> iolist().
sql_and_where_timestamp(_Operator, undefined) ->
    [];
sql_and_where_timestamp(Operator, NumericTimestamp) ->
    [" AND timestamp ", Operator, esc_int(NumericTimestamp)].

-spec sql_and_where_unread_count(HiddenRead :: boolean()) -> iolist().
sql_and_where_unread_count(true) ->
    [" AND  unread_count ", " > ", <<"0">>];
sql_and_where_unread_count(_) ->
    [].

-spec sql_and_where_archive(boolean() | undefined) -> iolist().
sql_and_where_archive(true) ->
    [" AND archive = true "];
sql_and_where_archive(false) ->
    [" AND archive = false "];
sql_and_where_archive(undefined) ->
    [].

-spec clear_inbox_rdbms(Username :: jid:luser(), Server :: jid:lserver()) -> mongoose_rdbms:query_result().
clear_inbox_rdbms(Username, Server) ->
    mongoose_rdbms:sql_query(Server, ["delete from inbox where luser=",
        esc_string(Username), " and lserver=", esc_string(Server), ";"]).

-spec clear_inbox_rdbms(Server :: jid:lserver()) -> mongoose_rdbms:query_result().
clear_inbox_rdbms(Server) ->
    mongoose_rdbms:sql_query(Server, ["delete from inbox;"]).

-spec decode_row(host(), db_return()) -> inbox_res().
decode_row(LServer, {Username, Content, Count, Timestamp, Archive, MutedUntil}) ->
    Data = mongoose_rdbms:unescape_binary(LServer, Content),
    BCount = count_to_bin(Count),
    NumericTimestamp = mongoose_rdbms:result_to_integer(Timestamp),
    BoolArchive = mod_inbox_utils:expand_bin_bool(Archive),
    MaybeMutedUntil = mod_inbox_utils:maybe_muted_until(mongoose_rdbms:result_to_integer(MutedUntil)),
    #{remote_jid => Username,
      msg => Data,
      unread_count => BCount,
      timestamp => NumericTimestamp,
      archive => BoolArchive,
      muted_until => MaybeMutedUntil}.

rdbms_specific_backend(Host) ->
    case {mongoose_rdbms:db_engine(Host), mongoose_rdbms_type:get()} of
        {mysql, _} -> mod_inbox_rdbms_mysql;
        {pgsql, _} -> mod_inbox_rdbms_pgsql;
        {odbc, mssql} -> mod_inbox_rdbms_mssql;
        NotSupported -> erlang:error({rdbms_not_supported, NotSupported})
    end.

count_to_bin(Count) when is_integer(Count) -> integer_to_binary(Count);
count_to_bin(Count) when is_binary(Count) -> Count.

check_result({updated, Val}, ValList) when is_list(ValList) ->
    case lists:member(Val, ValList) of
        true ->
            ok;
        _ ->
            {error, {expected_does_not_match, Val, ValList}}
    end;
check_result(Result, _) ->
    {error, {bad_result, Result}}.

check_result({selected, []}) ->
    {ok, 0};

check_result({selected, [{Val}]}) ->
    parse_result(Val);
check_result({updated, _, [{Val}]}) ->
    parse_result(Val);
check_result({updated, _}) ->
    ok;
check_result(Result) ->
    {error, {bad_result, Result}}.

parse_result(Value) when is_integer(Value) ->
    {ok, Value};
parse_result(Value) when is_binary(Value) ->
    {ok, binary_to_integer(Value)};
parse_result(null) ->
    {ok, 0};
parse_result(Value) ->
    {error, {unknown_result_value_type, Value}}.
