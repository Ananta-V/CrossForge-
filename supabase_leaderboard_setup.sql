-- ============================================================
-- CrossForge: Leaderboard & Scratch Crossword Scoring Migration
-- Run this in Supabase Dashboard > SQL Editor > New query > Run.
-- ============================================================

-- 1. Add scratch points and count to users table
alter table cw_users add column if not exists scratch_points int not null default 0;
alter table cw_users add column if not exists scratch_count int not null default 0;

-- 2. Function to record scratch crossword points
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

-- 3. Function to query the public leaderboard (ranked by points)
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

-- 4. Update cw_admin_users to also report scratch points
create or replace function cw_admin_users(p_admin text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform cw_admin_guard(p_admin);
  return (select coalesce(jsonb_agg(jsonb_build_object(
      'id', u.id, 'username', u.username, 'created_at', u.created_at, 'last_active', u.last_active,
      'cw_count', u.cw_count,
      'scratch_points', coalesce(u.scratch_points, 0),
      'scratch_count', coalesce(u.scratch_count, 0),
      'done', (select count(*) from cw_progress p where p.user_id = u.id and p.is_done),
      'total', (select count(*) from cw_words),
      'current_word', (select w.word from cw_words w where w.id = u.last_word_id)
    ) order by coalesce(u.scratch_points, 0) desc, u.created_at asc), '[]'::jsonb) from cw_users u);
end $$;

-- 5. Grant execute permissions to anon and authenticated
grant execute on function cw_record_scratch_score(text,text,int), cw_leaderboard() to anon, authenticated;

notify pgrst, 'reload schema';
