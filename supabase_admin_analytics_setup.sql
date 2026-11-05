-- ============================================================
-- CrossForge: Admin Detailed Analytics, Presence & Crossword History
-- Run this in Supabase Dashboard > SQL Editor > New query > Run.
-- ============================================================

-- 1. Add presence and time tracking columns to cw_users
alter table cw_users add column if not exists last_seen_at timestamptz;
alter table cw_users add column if not exists active_today_seconds int not null default 0;
alter table cw_users add column if not exists active_today_date date not null default current_date;
alter table cw_users add column if not exists total_time_seconds int not null default 0;
alter table cw_users add column if not exists scratch_points int not null default 0;
alter table cw_users add column if not exists scratch_count int not null default 0;

-- 2. Create cw_crosswords table for storing submitted puzzles
create table if not exists cw_crosswords (
  id bigint generated always as identity primary key,
  user_id uuid not null references cw_users(id) on delete cascade,
  crossword_type text not null default 'normal', -- 'normal' or 'scratch'
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

-- 3. Heartbeat presence ping from active learner sessions
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

-- 4. Learner function to submit/record a completed crossword
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

-- 5. Updated cw_admin_users: returns online status and today's active time
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

-- 6. Detailed user analytics query for admin
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

-- 7. Crossword inspection query: retrieves complete puzzle details for admin
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

-- 8. Grant permissions
grant execute on function
  cw_ping(text,text,int),
  cw_save_crossword(text,text,text,int,int,jsonb,jsonb,jsonb,int,int,int,int,int,int,int,int,int,int,int,int),
  cw_admin_users(text),
  cw_admin_user_detail(text,uuid),
  cw_admin_crossword_detail(text,bigint)
to anon, authenticated;

notify pgrst, 'reload schema';
