-- Run this once in the Supabase SQL Editor for the D&E Soundsource project.
-- The browser app uses Supabase Auth and the public publishable key only.

create table if not exists public.profiles (
    id uuid primary key references auth.users(id) on delete cascade,
    email text not null unique,
    first_name text not null default '',
    last_name text not null default '',
    phone text not null default '',
    address text not null default '',
    image text not null default '',
    is_active boolean not null default true,
    created_at timestamptz not null default now()
);

create table if not exists public.shop_state (
    scope_id text not null,
    key text not null,
    value jsonb not null,
    updated_at timestamptz not null default now(),
    primary key (scope_id, key)
);

alter table public.profiles enable row level security;
alter table public.shop_state enable row level security;

create or replace function public.is_active_store_user()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select exists (
        select 1
        from public.profiles p
        where p.id = (select auth.uid())
          and p.is_active
    );
$$;

create or replace function public.is_store_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select exists (
        select 1
        from auth.users u
        join public.profiles p on p.id = u.id
        where u.id = (select auth.uid())
          and lower(u.email) = 'daveuganap211@gmail.com'
          and u.email_confirmed_at is not null
          and p.is_active
    );
$$;

create or replace function public.create_store_profile()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
    insert into public.profiles (id, email, first_name, last_name)
    values (
        new.id,
        lower(new.email),
        coalesce(new.raw_user_meta_data ->> 'first_name', ''),
        coalesce(new.raw_user_meta_data ->> 'last_name', '')
    )
    on conflict (id) do update
    set email = excluded.email;
    return new;
end;
$$;

drop trigger if exists on_auth_user_created_store_profile on auth.users;
create trigger on_auth_user_created_store_profile
after insert on auth.users
for each row execute function public.create_store_profile();

insert into public.profiles (id, email, first_name, last_name)
select
    u.id,
    lower(u.email),
    coalesce(u.raw_user_meta_data ->> 'first_name', ''),
    coalesce(u.raw_user_meta_data ->> 'last_name', '')
from auth.users u
where u.email is not null
on conflict (id) do update
set email = excluded.email;

create or replace function public.sync_store_profile_email()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
    update public.profiles
    set email = lower(new.email)
    where id = new.id;
    return new;
end;
$$;

create or replace function public.deactivate_store_user(target_user_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
    if not (select public.is_store_admin()) then
        raise exception 'Administrator access required';
    end if;

    update public.profiles
    set is_active = false
    where id = target_user_id;
end;
$$;

drop trigger if exists on_auth_user_email_updated_store_profile on auth.users;
create trigger on_auth_user_email_updated_store_profile
after update of email on auth.users
for each row
when (old.email is distinct from new.email)
execute function public.sync_store_profile_email();

drop policy if exists "Users read own profile; admin reads all" on public.profiles;
create policy "Users read own profile; admin reads all"
on public.profiles for select to authenticated
using (id = (select auth.uid()) or (select public.is_store_admin()));

drop policy if exists "Users update own profile; admin updates all" on public.profiles;
create policy "Users update own profile; admin updates all"
on public.profiles for update to authenticated
using (id = (select auth.uid()) or (select public.is_store_admin()))
with check (id = (select auth.uid()) or (select public.is_store_admin()));

drop policy if exists "Active users read own and shared shop state" on public.shop_state;
drop policy if exists "Active users read own and shared stock state" on public.shop_state;
create policy "Active users read own and shared shop state"
on public.shop_state for select to authenticated
using (
    (select public.is_store_admin())
    or (
        (select public.is_active_store_user())
        and (
            scope_id = (select auth.uid())::text
            or (
                scope_id = 'global'
                and key in ('deSoundsource_stock', 'deSoundsource_products')
            )
        )
    )
);

drop policy if exists "Active users write own state; admin writes all" on public.shop_state;
create policy "Active users write own state; admin writes all"
on public.shop_state for insert to authenticated
with check (
    (select public.is_store_admin())
    or (
        (select public.is_active_store_user())
        and scope_id = (select auth.uid())::text
    )
);

drop policy if exists "Active users update own state; admin updates all" on public.shop_state;
create policy "Active users update own state; admin updates all"
on public.shop_state for update to authenticated
using (
    (select public.is_store_admin())
    or (
        (select public.is_active_store_user())
        and scope_id = (select auth.uid())::text
    )
)
with check (
    (select public.is_store_admin())
    or (
        (select public.is_active_store_user())
        and scope_id = (select auth.uid())::text
    )
);

drop policy if exists "Active users delete own state; admin deletes all" on public.shop_state;
create policy "Active users delete own state; admin deletes all"
on public.shop_state for delete to authenticated
using (
    (select public.is_store_admin())
    or (
        (select public.is_active_store_user())
        and scope_id = (select auth.uid())::text
    )
);

grant select on public.profiles to authenticated;
grant update (first_name, last_name, phone, address, image)
on public.profiles to authenticated;
grant select, insert, update, delete on public.shop_state to authenticated;

revoke all on public.profiles from anon;
revoke all on public.shop_state from anon;
revoke execute on function public.is_active_store_user() from public, anon;
revoke execute on function public.is_store_admin() from public, anon;
revoke execute on function public.deactivate_store_user(uuid) from public, anon;
grant execute on function public.is_active_store_user() to authenticated;
grant execute on function public.is_store_admin() to authenticated;
grant execute on function public.deactivate_store_user(uuid) to authenticated;
