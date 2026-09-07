create extension if not exists pgcrypto;

create table if not exists channels (
  id uuid primary key default gen_random_uuid(),
  channel_code varchar(64) not null unique,
  name varchar(80) not null,
  password_hash text,
  creator_session_hash char(64) not null,
  expires_at timestamptz,
  created_at timestamptz not null default now(),
  deleted_at timestamptz,
  constraint channel_code_format check (channel_code ~ '^[A-Za-z0-9_-]{3,64}$')
);
create index if not exists channels_expiry_idx on channels(expires_at) where deleted_at is null;

create table if not exists messages (
  id uuid primary key default gen_random_uuid(),
  channel_id uuid not null references channels(id) on delete cascade,
  session_hash char(64) not null,
  display_name varchar(40) not null,
  ciphertext bytea not null,
  nonce bytea not null,
  created_at timestamptz not null default now()
);
create index if not exists messages_channel_created_idx on messages(channel_id, created_at);

create table if not exists admin_audit_logs (
  id bigserial primary key,
  action varchar(80) not null,
  actor varchar(80) not null,
  ip inet,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists security_events (
  id bigserial primary key,
  event_type varchar(80) not null,
  ip inet,
  session_hash char(64),
  detail jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists blocked_ips (
  ip inet primary key,
  reason text,
  created_at timestamptz not null default now()
);

alter table channels enable row level security;
alter table messages enable row level security;
alter table admin_audit_logs enable row level security;
alter table security_events enable row level security;
alter table blocked_ips enable row level security;
-- The Flask service uses the Supabase service-role connection server-side; never expose it to browsers.
