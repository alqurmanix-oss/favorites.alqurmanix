create table if not exists public.aqx_favorites_guest_devices (
  id uuid primary key default gen_random_uuid(),
  guest_id uuid not null references public.aqx_favorites_guest_sessions(guest_id) on delete cascade,
  device_token_hash_hex text not null unique check (device_token_hash_hex ~ '^[a-f0-9]{64}$'),
  device_label text not null default 'جهاز جديد' check (char_length(device_label) between 1 and 120),
  created_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  trusted_at timestamptz not null default now(),
  revoked_at timestamptz
);
create index if not exists aqx_favorites_guest_devices_guest_idx
  on public.aqx_favorites_guest_devices (guest_id, created_at desc);
create index if not exists aqx_favorites_guest_devices_active_idx
  on public.aqx_favorites_guest_devices (guest_id, last_seen_at desc)
  where revoked_at is null;
alter table public.aqx_favorites_guest_devices enable row level security;
revoke all on table public.aqx_favorites_guest_devices from anon, authenticated;
grant all on table public.aqx_favorites_guest_devices to service_role;
