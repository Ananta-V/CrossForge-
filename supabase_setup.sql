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
alter table cw_users add column if not exists scratch_points int not null default 0;
alter table cw_users add column if not exists scratch_count int not null default 0;
alter table cw_users add column if not exists last_seen_at timestamptz;
alter table cw_users add column if not exists active_today_seconds int not null default 0;
alter table cw_users add column if not exists active_today_date date not null default current_date;
alter table cw_users add column if not exists total_time_seconds int not null default 0;
create unique index if not exists cw_words_word_uq on cw_words (lower(word));

create table if not exists cw_crosswords (
  id bigint generated always as identity primary key,
  user_id uuid not null references cw_users(id) on delete cascade,
  crossword_type text not null default 'normal',
  title text,
  rows int not null,
  cols int not null,
  grid jsonb not null,
  entries jsonb not null,
  user_inputs jsonb,
  word_count int not null default 0,
  words_correct int not null default 0,
  words_attempted int not null default 0,
  letters_correct int not null default 0,
  letters_wrong int not null default 0,
  letters_unattempted int not null default 0,
  total_letters int not null default 0,
  time_taken_seconds int not null default 0,
  time_left_seconds int not null default 0,
  word_score_pct int not null default 0,
  letter_accuracy_pct int not null default 0,
  points int not null default 0,
  submitted_at timestamptz not null default now()
);
create index if not exists cw_crosswords_user_idx on cw_crosswords(user_id, submitted_at desc);
create index if not exists cw_crosswords_type_idx on cw_crosswords(user_id, crossword_type);
alter table cw_crosswords enable row level security;
revoke all on cw_crosswords from anon, authenticated;

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

-- ---------- leaderboard & scratch points ----------
create or replace function cw_record_scratch_score(p_user text, p_pass text, p_points int) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare v_id uuid; v_total int;
begin
  v_id := cw_auth(p_user, p_pass);
  update cw_users
     set scratch_points = scratch_points + greatest(0, p_points),
         scratch_count = scratch_count + 1,
         last_active = now()
   where id = v_id
   returning scratch_points into v_total;
  return jsonb_build_object('ok', true, 'total_points', v_total);
end $$;

create or replace function cw_leaderboard() returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
begin
  return (select coalesce(jsonb_agg(jsonb_build_object(
    'username', u.username,
    'points', coalesce(u.scratch_points, 0),
    'games', coalesce(u.scratch_count, 0),
    'last_active', u.last_active
  ) order by coalesce(u.scratch_points, 0) desc, coalesce(u.scratch_count, 0) asc, u.created_at asc), '[]'::jsonb)
  from cw_users u);
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

create or replace function cw_ping(p_user text, p_pass text, p_seconds int default 30) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_id uuid;
  v_today date := current_date;
  v_sec int := greatest(0, least(120, coalesce(p_seconds, 30)));
begin
  v_id := cw_auth(p_user, p_pass);
  update cw_users
     set last_seen_at = now(),
         last_active = now(),
         active_today_seconds = case
           when active_today_date = v_today then active_today_seconds + v_sec
           else v_sec
         end,
         active_today_date = v_today,
         total_time_seconds = total_time_seconds + v_sec
   where id = v_id;
  return jsonb_build_object('ok', true);
end $$;

create or replace function cw_save_crossword(
  p_user text,
  p_pass text,
  p_type text,
  p_rows int,
  p_cols int,
  p_grid jsonb,
  p_entries jsonb,
  p_user_inputs jsonb,
  p_words_correct int,
  p_words_total int,
  p_words_attempted int,
  p_letters_correct int,
  p_letters_wrong int,
  p_letters_unattempted int,
  p_total_letters int,
  p_time_taken_seconds int,
  p_time_left_seconds int,
  p_word_score_pct int,
  p_letter_accuracy_pct int,
  p_points int default 0
) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_id uuid;
  v_cw_id bigint;
  v_type text := case when lower(p_type) = 'scratch' then 'scratch' else 'normal' end;
  v_title text;
begin
  v_id := cw_auth(p_user, p_pass);
  v_title := case when v_type = 'scratch' then 'Scratch Crossword Challenge' else 'Practice Crossword' end;

  insert into cw_crosswords (
    user_id, crossword_type, title, rows, cols, grid, entries, user_inputs,
    word_count, words_correct, words_attempted,
    letters_correct, letters_wrong, letters_unattempted, total_letters,
    time_taken_seconds, time_left_seconds,
    word_score_pct, letter_accuracy_pct, points, submitted_at
  ) values (
    v_id, v_type, v_title, p_rows, p_cols, p_grid, p_entries, p_user_inputs,
    p_words_total, p_words_correct, p_words_attempted,
    p_letters_correct, p_letters_wrong, p_letters_unattempted, p_total_letters,
    p_time_taken_seconds, p_time_left_seconds,
    p_word_score_pct, p_letter_accuracy_pct, greatest(0, coalesce(p_points, 0)), now()
  ) returning id into v_cw_id;

  update cw_users
     set last_active = now(),
         last_seen_at = now()
   where id = v_id;

  return jsonb_build_object('ok', true, 'crossword_id', v_cw_id);
end $$;

create or replace function cw_admin_users(p_admin text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_today date := current_date;
begin
  perform cw_admin_guard(p_admin);
  return (
    select coalesce(jsonb_agg(jsonb_build_object(
      'id', u.id,
      'username', u.username,
      'created_at', u.created_at,
      'last_active', u.last_active,
      'last_seen_at', u.last_seen_at,
      'is_online', (u.last_seen_at is not null and u.last_seen_at >= (now() - interval '90 seconds')),
      'time_today_seconds', case when u.active_today_date = v_today then coalesce(u.active_today_seconds, 0) else 0 end,
      'total_time_seconds', coalesce(u.total_time_seconds, 0),
      'cw_count', u.cw_count,
      'scratch_points', coalesce(u.scratch_points, 0),
      'scratch_count', coalesce(u.scratch_count, 0),
      'done', (select count(*) from cw_progress p where p.user_id = u.id and p.is_done),
      'total', (select count(*) from cw_words),
      'current_word', (select w.word from cw_words w where w.id = u.last_word_id)
    ) order by
      (u.last_seen_at is not null and u.last_seen_at >= (now() - interval '90 seconds')) desc,
      coalesce(u.scratch_points, 0) desc,
      u.created_at asc
    ), '[]'::jsonb)
    from cw_users u
  );
end $$;

create or replace function cw_admin_user_detail(p_admin text, p_user_id uuid) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_user record;
  v_today date := current_date;
  v_total_words int;
  v_done_words int;
  v_used_words int;
  v_normal_count int;
  v_scratch_count int;
  v_avg_word_score int;
  v_avg_letter_acc int;
  v_total_letters_correct int;
  v_total_mistakes int;
  v_recent_crosswords jsonb;
  v_done_list jsonb;
begin
  perform cw_admin_guard(p_admin);

  select * into v_user from cw_users where id = p_user_id;
  if v_user.id is null then raise exception 'User not found'; end if;

  select count(*) into v_total_words from cw_words;
  select count(*) into v_done_words from cw_progress where user_id = p_user_id and is_done;
  select count(*) into v_used_words from cw_progress where user_id = p_user_id and used_count > 0;

  select count(*) filter (where crossword_type = 'normal'),
         count(*) filter (where crossword_type = 'scratch'),
         coalesce(round(avg(word_score_pct)), 0),
         coalesce(round(avg(letter_accuracy_pct)), 0),
         coalesce(sum(letters_correct), 0),
         coalesce(sum(letters_wrong + letters_unattempted), 0)
    into v_normal_count, v_scratch_count, v_avg_word_score, v_avg_letter_acc, v_total_letters_correct, v_total_mistakes
    from cw_crosswords
   where user_id = p_user_id;

  select coalesce(jsonb_agg(jsonb_build_object(
    'id', c.id,
    'crossword_type', c.crossword_type,
    'title', c.title,
    'rows', c.rows,
    'cols', c.cols,
    'word_count', c.word_count,
    'words_correct', c.words_correct,
    'word_score_pct', c.word_score_pct,
    'letter_accuracy_pct', c.letter_accuracy_pct,
    'points', c.points,
    'time_taken_seconds', c.time_taken_seconds,
    'submitted_at', c.submitted_at
  ) order by c.submitted_at desc), '[]'::jsonb)
  into v_recent_crosswords
  from (select * from cw_crosswords where user_id = p_user_id order by submitted_at desc limit 100) c;

  select coalesce(jsonb_agg(jsonb_build_object(
    'word', w.word,
    'definition', w.definition,
    'key_definition', w.key_definition,
    'done_at', p.done_at,
    'used_count', p.used_count
  ) order by p.done_at desc nulls last limit 50), '[]'::jsonb)
  into v_done_list
  from cw_progress p
  join cw_words w on w.id = p.word_id
  where p.user_id = p_user_id and p.is_done;

  return jsonb_build_object(
    'user', jsonb_build_object(
      'id', v_user.id,
      'username', v_user.username,
      'created_at', v_user.created_at,
      'last_active', v_user.last_active,
      'last_seen_at', v_user.last_seen_at,
      'is_online', (v_user.last_seen_at is not null and v_user.last_seen_at >= (now() - interval '90 seconds')),
      'time_today_seconds', case when v_user.active_today_date = v_today then coalesce(v_user.active_today_seconds, 0) else 0 end,
      'total_time_seconds', coalesce(v_user.total_time_seconds, 0),
      'scratch_points', coalesce(v_user.scratch_points, 0),
      'scratch_count', coalesce(v_user.scratch_count, 0),
      'cw_count', v_user.cw_count
    ),
    'analytics', jsonb_build_object(
      'total_curriculum_words', v_total_words,
      'done_words', v_done_words,
      'used_words', v_used_words,
      'completion_pct', case when v_total_words > 0 then round((v_done_words::numeric / v_total_words) * 100) else 0 end,
      'total_crosswords', coalesce(v_normal_count, 0) + coalesce(v_scratch_count, 0),
      'normal_count', coalesce(v_normal_count, 0),
      'scratch_count', coalesce(v_scratch_count, 0),
      'avg_word_score', v_avg_word_score,
      'avg_letter_acc', v_avg_letter_acc,
      'total_letters_correct', v_total_letters_correct,
      'total_mistakes', v_total_mistakes
    ),
    'crosswords', v_recent_crosswords,
    'mastered_words', v_done_list
  );
end $$;

create or replace function cw_admin_crossword_detail(p_admin text, p_crossword_id bigint) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_cw record;
  v_user text;
begin
  perform cw_admin_guard(p_admin);

  select c.*, u.username into v_cw
    from cw_crosswords c
    join cw_users u on u.id = c.user_id
   where c.id = p_crossword_id;

  if v_cw.id is null then raise exception 'Crossword not found'; end if;

  return jsonb_build_object(
    'id', v_cw.id,
    'username', v_cw.username,
    'crossword_type', v_cw.crossword_type,
    'title', v_cw.title,
    'rows', v_cw.rows,
    'cols', v_cw.cols,
    'grid', v_cw.grid,
    'entries', v_cw.entries,
    'user_inputs', v_cw.user_inputs,
    'word_count', v_cw.word_count,
    'words_correct', v_cw.words_correct,
    'words_attempted', v_cw.words_attempted,
    'letters_correct', v_cw.letters_correct,
    'letters_wrong', v_cw.letters_wrong,
    'letters_unattempted', v_cw.letters_unattempted,
    'total_letters', v_cw.total_letters,
    'time_taken_seconds', v_cw.time_taken_seconds,
    'time_left_seconds', v_cw.time_left_seconds,
    'word_score_pct', v_cw.word_score_pct,
    'letter_accuracy_pct', v_cw.letter_accuracy_pct,
    'points', v_cw.points,
    'submitted_at', v_cw.submitted_at
  );
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
  cw_admin_delete_user(text,uuid),
  cw_record_scratch_score(text,text,int), cw_leaderboard(),
  cw_ping(text,text,int),
  cw_save_crossword(text,text,text,int,int,jsonb,jsonb,jsonb,int,int,int,int,int,int,int,int,int,int,int,int),
  cw_admin_user_detail(text,uuid),
  cw_admin_crossword_detail(text,bigint)
to anon, authenticated;

notify pgrst, 'reload schema';

