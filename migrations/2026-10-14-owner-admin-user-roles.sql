-- Applied 2026-10-14 via Supabase connector (project ahgrdvxrxaghnjqudwib).
-- Role model: hidden owner flag (app_private.owners, stored role 'admin'), admin, user, pending.
create table if not exists app_private.owners (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);
revoke all on app_private.owners from anon, authenticated;
create or replace function app_private.is_owner() returns boolean language sql stable security definer set search_path = '' as $$
  select exists (select 1 from app_private.owners o where o.user_id = (select auth.uid()));
$$;
revoke all on function app_private.is_owner() from anon, authenticated, public;
update public.profiles set role = 'user' where role in ('manager','staff','viewer');
alter table public.profiles drop constraint if exists profiles_role_check;
alter table public.profiles add constraint profiles_role_check_v2 check (role = any (array['admin','user','pending']));
create or replace function app_private.can_write() returns boolean language sql stable security definer set search_path = '' as $$
  select coalesce(app_private.my_role() in ('admin','user'), false);
$$;
create or replace function app_private.is_member() returns boolean language sql stable security definer set search_path = '' as $$
  select coalesce(app_private.my_role() in ('admin','user'), false);
$$;
create or replace function public.handle_new_user() returns trigger language plpgsql security definer set search_path = '' as $$
declare v_code text; v_role text := 'pending';
begin
  select s.value into v_code from public.app_settings s where s.key = 'invite_code';
  if v_code is not null and v_code <> '' and coalesce(new.raw_user_meta_data->>'invite_code', '') = v_code then v_role := 'user'; end if;
  insert into public.profiles (id, email, full_name, role) values (new.id, new.email, coalesce(new.raw_user_meta_data->>'full_name', ''), v_role) on conflict (id) do nothing;
  return new;
end; $$;
create or replace function app_private.profiles_role_guard() returns trigger language plpgsql security definer set search_path = '' as $$
declare v_owner boolean := app_private.is_owner(); v_target_owner boolean := exists (select 1 from app_private.owners o where o.user_id = new.id);
begin
  if new.role is distinct from old.role then
    if v_target_owner and not v_owner then raise exception 'This change is not permitted.' using errcode = '42501'; end if;
    if v_target_owner then new.role := 'admin'; end if;
    if (new.role = 'admin' or old.role = 'admin') and not v_owner then raise exception 'This change is not permitted.' using errcode = '42501'; end if;
  end if;
  return new;
end; $$;
drop trigger if exists trg_profiles_role_guard on public.profiles;
create trigger trg_profiles_role_guard before update of role on public.profiles for each row execute function app_private.profiles_role_guard();
create or replace function public.my_access() returns jsonb language sql stable security definer set search_path = '' as $$
  select jsonb_build_object('role', app_private.my_role(), 'extended', app_private.is_owner());
$$;
revoke all on function public.my_access() from anon, public;
grant execute on function public.my_access() to authenticated;
-- Owner registered by user id (roscoebloomfield89@gmail.com).
