create extension if not exists pgcrypto;

create table if not exists public.licenses (
  id uuid primary key default gen_random_uuid(),
  key text not null unique,
  client_name text not null default 'Novo cliente',
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  status text not null default 'active' check (status in ('active','blocked')),
  hwid text,
  activated_at timestamptz,
  last_ip text,
  last_login timestamptz,
  os text
);

create table if not exists public.logs (
  id uuid primary key default gen_random_uuid(),
  type text not null,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists licenses_key_upper_idx on public.licenses (upper(key));
create index if not exists logs_created_at_idx on public.logs (created_at desc);

alter table public.licenses enable row level security;
alter table public.logs enable row level security;

-- Nenhuma policy pública: o navegador nunca acessa estas tabelas diretamente.
-- A API da Vercel usa SUPABASE_SECRET_KEY somente no servidor.

insert into public.licenses (key, client_name, expires_at, status)
values ('PRECISION-DEMO-2026', 'Usuário Demo', now() + interval '365 days', 'active')
on conflict (key) do update set
  client_name = excluded.client_name,
  expires_at = greatest(public.licenses.expires_at, excluded.expires_at),
  status = 'active';
