-- AQX Favorites guest WebAuthn credentials. Public keys only; no raw hardware serials.
create table if not exists public.aqx_favorites_guest_webauthn_credentials (
 credential_id text primary key,
 guest_id uuid not null,
 public_key_b64 text not null,
 sign_count bigint not null default 0,
 transports text[] not null default '{}',
 device_type text,
 backed_up boolean not null default false,
 created_at timestamptz not null default now(),
 last_used_at timestamptz,
 revoked_at timestamptz
);
create index if not exists aqx_favorites_guest_webauthn_guest_idx on public.aqx_favorites_guest_webauthn_credentials(guest_id) where revoked_at is null;
create table if not exists public.aqx_favorites_webauthn_challenges (
 id uuid primary key default gen_random_uuid(),
 challenge text not null,
 purpose text not null check (purpose in ('register','authenticate')),
 guest_id uuid,
 created_at timestamptz not null default now(),
 expires_at timestamptz not null,
 consumed_at timestamptz
);
create index if not exists aqx_favorites_webauthn_challenge_expiry_idx on public.aqx_favorites_webauthn_challenges(expires_at);
alter table public.aqx_favorites_guest_webauthn_credentials enable row level security;
alter table public.aqx_favorites_webauthn_challenges enable row level security;
revoke all on public.aqx_favorites_guest_webauthn_credentials from anon, authenticated;
revoke all on public.aqx_favorites_webauthn_challenges from anon, authenticated;
grant all on public.aqx_favorites_guest_webauthn_credentials to service_role;
grant all on public.aqx_favorites_webauthn_challenges to service_role;