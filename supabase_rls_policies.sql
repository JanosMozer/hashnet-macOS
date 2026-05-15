-- Run this in Supabase Studio > SQL Editor

-- Because you are using Clerk Auth, your users do not exist in Supabase's native `users` or `auth.users` tables.
-- Clerk User IDs are Strings (e.g. "user_2oFm..."), so we MUST change the `user_id` columns from `uuid` to `text`.
ALTER TABLE public.devices DROP CONSTRAINT IF EXISTS devices_user_id_fkey;
ALTER TABLE public.devices ALTER COLUMN user_id TYPE text USING user_id::text;

-- If you have other tables like connections or key_broker referencing user_id, alter them too:
ALTER TABLE public.key_broker ALTER COLUMN user_id TYPE text USING user_id::text;
ALTER TABLE public.key_broker ALTER COLUMN target_user_id TYPE text USING target_user_id::text;
ALTER TABLE public.connections ALTER COLUMN initiator_user_id TYPE text USING initiator_user_id::text;
ALTER TABLE public.connections ALTER COLUMN target_user_id TYPE text USING target_user_id::text;

-- devices: allow anon to insert and read
alter table public.devices enable row level security;

drop policy if exists "anon can insert devices" on public.devices;
create policy "anon can insert devices"
  on public.devices for insert
  to anon
  with check (true);

drop policy if exists "anon can read devices" on public.devices;
create policy "anon can read devices"
  on public.devices for select
  to anon
  using (true);

-- key_broker: allow anon to insert and read
alter table public.key_broker enable row level security;

drop policy if exists "anon can insert key_broker" on public.key_broker;
create policy "anon can insert key_broker"
  on public.key_broker for insert
  to anon
  with check (true);

drop policy if exists "anon can read key_broker" on public.key_broker;
create policy "anon can read key_broker"
  on public.key_broker for select
  to anon
  using (true);

-- connections: allow anon to read
alter table public.connections enable row level security;

drop policy if exists "anon can read connections" on public.connections;
create policy "anon can read connections"
  on public.connections for select
  to anon
  using (true);
