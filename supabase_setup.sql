-- ============================================================
-- CrossForge crossword app: Supabase setup.
-- Run ONCE in Supabase Dashboard > SQL Editor > New query > Run.
-- Safe to re-run. It creates NEW tables prefixed cw_ (does not touch your existing tables).
-- The browser only uses the publishable key. Tables are locked (RLS, no policies);
-- everything goes through the functions below which check username/password or admin password.
-- ============================================================
create extension if not exists pgcrypto with schema extensions;

create table if not exists cw_config (key text primary key, value text not null);

create table if not exists cw_users (
  id uuid primary key default gen_random_uuid(),
  username text not null unique,
  pass_hash text not null,
  cw_count int not null default 0,
  last_word_id bigint,
  last_active timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists cw_words (
  id bigint generated always as identity primary key,
  word text not null,
  definition text not null,
  created_at timestamptz not null default now()
);
alter table cw_words add column if not exists key_definition text;
alter table cw_words add column if not exists source text;
alter table cw_words add column if not exists set_id text;
create unique index if not exists cw_words_word_uq on cw_words (lower(word));

create table if not exists cw_progress (
  user_id uuid not null references cw_users(id) on delete cascade,
  word_id bigint not null references cw_words(id) on delete cascade,
  is_done boolean not null default false,
  done_at timestamptz,
  used_count int not null default 0,
  primary key (user_id, word_id)
);

create table if not exists cw_sessions (
  token text primary key,
  user_id uuid not null references cw_users(id) on delete cascade,
  created_at timestamptz not null default now()
);
create index if not exists cw_sessions_user_idx on cw_sessions (user_id);
alter table cw_sessions enable row level security;
revoke all on cw_sessions from anon, authenticated;

alter table cw_config   enable row level security;
alter table cw_users    enable row level security;
alter table cw_words    enable row level security;
alter table cw_progress enable row level security;
revoke all on cw_config, cw_users, cw_words, cw_progress from anon, authenticated;

-- Admin password (change the text below if you want a different one, then re-run)
insert into cw_config (key, value)
values ('admin_hash', extensions.crypt('162811', extensions.gen_salt('bf')))
on conflict (key) do update set value = excluded.value;

-- ---------- helpers (not callable from the browser) ----------
-- Fast path: a login token (random, stored in cw_sessions) avoids slow bcrypt on every request.
create or replace function cw_auth(p_user text, p_pass text) returns uuid
language plpgsql security definer set search_path = public, extensions as $$
declare v_id uuid;
begin
  select u.id into v_id from cw_users u join cw_sessions s on s.user_id = u.id
   where u.username = lower(trim(p_user)) and s.token = p_pass;
  if v_id is not null then return v_id; end if;
  select id into v_id from cw_users
   where username = lower(trim(p_user)) and pass_hash = crypt(p_pass, pass_hash);
  if v_id is null then raise exception 'Invalid username or password'; end if;
  return v_id;
end $$;

create or replace function cw_admin_guard(p_admin text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not exists (select 1 from cw_config where key='admin_hash' and value = crypt(coalesce(p_admin,''), value)) then
    raise exception 'Wrong admin password';
  end if;
end $$;

-- ---------- learner functions ----------
create or replace function cw_login(p_user text, p_pass text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare v_id uuid; v_token text;
begin
  select id into v_id from cw_users
   where username = lower(trim(p_user)) and pass_hash = crypt(p_pass, pass_hash);
  if v_id is null then raise exception 'Invalid username or password'; end if;
  v_token := replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', '');
  insert into cw_sessions (token, user_id) values (v_token, v_id);
  delete from cw_sessions where user_id = v_id and created_at < now() - interval '60 days';
  update cw_users set last_active = now() where id = v_id;
  return jsonb_build_object('ok', true, 'username', lower(trim(p_user)), 'token', v_token);
end $$;

create or replace function cw_state(p_user text, p_pass text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare v_id uuid; v_words jsonb; v_last bigint;
begin
  v_id := cw_auth(p_user, p_pass);
  select last_word_id into v_last from cw_users where id = v_id;
  select coalesce(jsonb_agg(jsonb_build_object(
           'id', w.id, 'word', w.word, 'definition', w.definition, 'key_definition', w.key_definition,
           'is_done', coalesce(p.is_done, false), 'used_count', coalesce(p.used_count, 0)
         ) order by w.id), '[]'::jsonb)
    into v_words
    from cw_words w left join cw_progress p on p.word_id = w.id and p.user_id = v_id;
  return jsonb_build_object('words', v_words, 'last_word_id', v_last);
end $$;

create or replace function cw_set_done(p_user text, p_pass text, p_word_id bigint, p_done boolean) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare v_id uuid;
begin
  v_id := cw_auth(p_user, p_pass);
  insert into cw_progress (user_id, word_id, is_done, done_at)
  values (v_id, p_word_id, p_done, case when p_done then now() end)
  on conflict (user_id, word_id)
  do update set is_done = excluded.is_done, done_at = excluded.done_at;
  update cw_users set last_active = now() where id = v_id;
end $$;

create or replace function cw_set_last(p_user text, p_pass text, p_word_id bigint) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare v_id uuid;
begin
  v_id := cw_auth(p_user, p_pass);
  update cw_users set last_word_id = p_word_id, last_active = now() where id = v_id;
end $$;

create or replace function cw_mark_used(p_user text, p_pass text, p_answers text[]) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare v_id uuid;
begin
  v_id := cw_auth(p_user, p_pass);
  update cw_progress pr set used_count = used_count + 1
    from cw_words w
   where pr.user_id = v_id and pr.word_id = w.id
     and regexp_replace(upper(w.word), '[^A-Z]', '', 'g') = any (p_answers);
  update cw_users set cw_count = cw_count + 1, last_active = now() where id = v_id;
end $$;

create or replace function cw_reset_used(p_user text, p_pass text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare v_id uuid;
begin
  v_id := cw_auth(p_user, p_pass);
  update cw_progress set used_count = 0 where user_id = v_id;
end $$;

-- ---------- admin functions ----------
create or replace function cw_admin_check(p_admin text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
begin perform cw_admin_guard(p_admin); return jsonb_build_object('ok', true); end $$;

create or replace function cw_admin_import(p_admin text, p_items jsonb) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare v_item jsonb; v_added int := 0; v_skipped int := 0; v_n int;
begin
  perform cw_admin_guard(p_admin);
  for v_item in select * from jsonb_array_elements(p_items) loop
    if coalesce(trim(v_item->>'word'), '') = '' or coalesce(trim(v_item->>'definition'), '') = '' then
      v_skipped := v_skipped + 1; continue;
    end if;
    insert into cw_words (word, definition, key_definition, source, set_id)
    values (trim(v_item->>'word'), trim(v_item->>'definition'),
            nullif(trim(coalesce(v_item->>'key_definition','')), ''), nullif(trim(coalesce(v_item->>'source','')), ''), nullif(trim(coalesce(v_item->>'set_id','')), ''))
    on conflict (lower(word)) do update set
      key_definition = coalesce(excluded.key_definition, cw_words.key_definition),
      source = coalesce(excluded.source, cw_words.source),
      definition = excluded.definition;
    get diagnostics v_n = row_count;
    if v_n > 0 then v_added := v_added + 1; else v_skipped := v_skipped + 1; end if;
  end loop;
  return jsonb_build_object('added', v_added, 'skipped', v_skipped);
end $$;

create or replace function cw_admin_words(p_admin text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform cw_admin_guard(p_admin);
  return (select coalesce(jsonb_agg(jsonb_build_object('id', id, 'word', word, 'definition', definition, 'key_definition', key_definition, 'source', source, 'set_id', set_id) order by id), '[]'::jsonb) from cw_words);
end $$;

create or replace function cw_admin_delete_word(p_admin text, p_word_id bigint) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin perform cw_admin_guard(p_admin); delete from cw_words where id = p_word_id; end $$;

create or replace function cw_admin_delete_set(p_admin text, p_set_id text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare v_n int;
begin
  perform cw_admin_guard(p_admin);
  delete from cw_words where set_id = p_set_id;
  get diagnostics v_n = row_count;
  return jsonb_build_object('deleted', v_n);
end $$;

create or replace function cw_admin_clear_words(p_admin text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin perform cw_admin_guard(p_admin); delete from cw_words where true; end $$;

create or replace function cw_admin_users(p_admin text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform cw_admin_guard(p_admin);
  return (select coalesce(jsonb_agg(jsonb_build_object(
      'id', u.id, 'username', u.username, 'created_at', u.created_at, 'last_active', u.last_active,
      'cw_count', u.cw_count,
      'done', (select count(*) from cw_progress p where p.user_id = u.id and p.is_done),
      'total', (select count(*) from cw_words),
      'current_word', (select w.word from cw_words w where w.id = u.last_word_id)
    ) order by u.created_at), '[]'::jsonb) from cw_users u);
end $$;

create or replace function cw_admin_create_user(p_admin text, p_username text, p_password text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform cw_admin_guard(p_admin);
  if length(trim(p_username)) < 2 or length(coalesce(p_password,'')) < 3 then
    raise exception 'Username (2+ chars) and password (3+ chars) required';
  end if;
  insert into cw_users (username, pass_hash) values (lower(trim(p_username)), crypt(p_password, gen_salt('bf')));
exception when unique_violation then raise exception 'That username already exists';
end $$;

create or replace function cw_admin_set_password(p_admin text, p_user_id uuid, p_password text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform cw_admin_guard(p_admin);
  if length(coalesce(p_password,'')) < 3 then raise exception 'Password needs 3+ chars'; end if;
  update cw_users set pass_hash = crypt(p_password, gen_salt('bf')) where id = p_user_id;
  delete from cw_sessions where user_id = p_user_id;
end $$;

create or replace function cw_admin_delete_user(p_admin text, p_user_id uuid) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin perform cw_admin_guard(p_admin); delete from cw_users where id = p_user_id; end $$;

-- ---------- permissions: browser (anon) may only call the public functions ----------
revoke all on function cw_auth(text,text), cw_admin_guard(text) from public, anon, authenticated;
grant execute on function
  cw_login(text,text), cw_state(text,text), cw_set_done(text,text,bigint,boolean),
  cw_set_last(text,text,bigint), cw_mark_used(text,text,text[]), cw_reset_used(text,text),
  cw_admin_check(text), cw_admin_import(text,jsonb), cw_admin_words(text),
  cw_admin_delete_word(text,bigint), cw_admin_delete_set(text,text), cw_admin_clear_words(text), cw_admin_users(text),
  cw_admin_create_user(text,text,text), cw_admin_set_password(text,uuid,text),
  cw_admin_delete_user(text,uuid)
to anon, authenticated;

notify pgrst, 'reload schema';

