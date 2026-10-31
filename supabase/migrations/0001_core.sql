-- maas.AI GRC Hub core schema.
-- Rule: facts that prove something (scans, evidence, attestations, domain verification)
-- are written only by the server with the service role. Members can read them, never forge them.

create extension if not exists pgcrypto with schema extensions;
create schema if not exists private;
grant usage on schema private to authenticated;

create type public.member_role as enum ('owner', 'admin', 'analyst', 'viewer');
create type public.risk_status as enum ('Open', 'In Progress', 'Closed', 'Accepted');
create type public.risk_strategy as enum ('Mitigate', 'Accept', 'Transfer', 'Avoid');
create type public.answer_status as enum ('yes', 'partial', 'no', 'na');
create type public.policy_status as enum ('draft', 'approved', 'retired');

create table public.orgs (
  id uuid primary key default gen_random_uuid(),
  slug text not null unique check (slug ~ '^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$'),
  name text not null check (char_length(name) between 2 and 120),
  profile jsonb not null,
  trust_enabled boolean not null default false,
  risk_counter integer not null default 0,
  created_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now()
);

create table public.members (
  org_id uuid not null references public.orgs (id) on delete cascade,
  user_id uuid not null references auth.users (id) on delete cascade,
  email text not null,
  role public.member_role not null,
  created_at timestamptz not null default now(),
  primary key (org_id, user_id)
);
create index members_user_idx on public.members (user_id);

create table public.invites (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs (id) on delete cascade,
  email text not null,
  role public.member_role not null check (role <> 'owner'),
  token_hash text not null unique,
  created_by uuid references auth.users (id) on delete set null,
  expires_at timestamptz not null default now() + interval '7 days',
  accepted_at timestamptz,
  created_at timestamptz not null default now()
);
create index invites_org_idx on public.invites (org_id);

create table public.risks (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs (id) on delete cascade,
  seq integer not null,
  source_ref text,
  date_identified date not null default current_date,
  description text not null check (char_length(description) between 3 and 2000),
  consequence text not null default '' check (char_length(consequence) <= 2000),
  category text not null default 'Security' check (char_length(category) <= 40),
  likelihood smallint not null check (likelihood between 1 and 5),
  impact smallint not null check (impact between 1 and 5),
  inherent_score smallint generated always as (likelihood * impact) stored,
  inherent_level text generated always as (
    case when likelihood * impact >= 15 then 'High' when likelihood * impact >= 8 then 'Medium' else 'Low' end
  ) stored,
  existing_controls text not null default '' check (char_length(existing_controls) <= 2000),
  strategy public.risk_strategy not null default 'Mitigate',
  mitigation text not null default '' check (char_length(mitigation) <= 2000),
  owner text not null default '' check (char_length(owner) <= 120),
  target_date date,
  status public.risk_status not null default 'Open',
  residual_likelihood smallint check (residual_likelihood between 1 and 5),
  residual_impact smallint check (residual_impact between 1 and 5),
  residual_score smallint generated always as (residual_likelihood * residual_impact) stored,
  residual_level text generated always as (
    case when residual_likelihood * residual_impact >= 15 then 'High'
         when residual_likelihood * residual_impact >= 8 then 'Medium'
         when residual_likelihood * residual_impact >= 1 then 'Low' end
  ) stored,
  last_reviewed date,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (org_id, seq),
  unique (org_id, source_ref)
);

create table public.answers (
  org_id uuid not null references public.orgs (id) on delete cascade,
  control_id text not null check (control_id ~ '^[A-Z]{2,3}-[0-9]{2}$'),
  status public.answer_status not null,
  note text not null default '' check (char_length(note) <= 2000),
  answered_by uuid references auth.users (id) on delete set null,
  updated_at timestamptz not null default now(),
  primary key (org_id, control_id)
);

create table public.evidence (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs (id) on delete cascade,
  control_id text not null check (control_id ~ '^[A-Z]{2,3}-[0-9]{2}$'),
  name text not null check (char_length(name) <= 200),
  storage_path text not null unique,
  sha256 text not null check (sha256 ~ '^[0-9a-f]{64}$'),
  size_bytes integer not null,
  uploaded_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now()
);
create index evidence_org_control_idx on public.evidence (org_id, control_id);

create table public.domains (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs (id) on delete cascade,
  domain text not null check (domain ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'),
  token text not null default encode(extensions.gen_random_bytes(16), 'hex'),
  verified_at timestamptz,
  created_at timestamptz not null default now(),
  unique (org_id, domain)
);

create table public.scans (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs (id) on delete cascade,
  domain_id uuid not null references public.domains (id) on delete cascade,
  domain text not null,
  score smallint not null check (score between 0 and 100),
  results jsonb not null,
  started_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now()
);
create index scans_org_time_idx on public.scans (org_id, created_at desc);

create table public.policies (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs (id) on delete cascade,
  template_id text not null,
  title text not null,
  version integer not null default 1,
  status public.policy_status not null default 'draft',
  body jsonb not null,
  content_sha256 text,
  approved_by uuid references auth.users (id) on delete set null,
  approved_by_email text,
  approved_at timestamptz,
  review_due date,
  created_at timestamptz not null default now(),
  unique (org_id, template_id, version)
);

create table public.attestations (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs (id) on delete cascade,
  slug text not null,
  payload jsonb not null,
  canonical text not null,
  signature text not null,
  key_id text not null,
  published boolean not null default false,
  issued_at timestamptz not null default now(),
  expires_at timestamptz not null
);
create index attestations_slug_idx on public.attestations (slug, issued_at desc);

create table public.ledger (
  org_id uuid not null references public.orgs (id) on delete cascade,
  seq bigint not null,
  event text not null,
  subject text not null,
  actor uuid,
  payload_hash text not null,
  prev_hash text not null,
  hash text not null,
  created_at timestamptz not null default now(),
  primary key (org_id, seq)
);

-- Access helpers ---------------------------------------------------------------------------

-- A user with a verified TOTP factor counts as a member only in an aal2 session.
create function private.role_in(p_org uuid) returns public.member_role
language sql stable security definer set search_path = '' as $$
  select m.role from public.members m
  where m.org_id = p_org and m.user_id = auth.uid()
    and (coalesce(auth.jwt() ->> 'aal', 'aal1') = 'aal2'
         or not exists (select 1 from auth.mfa_factors f where f.user_id = auth.uid() and f.status = 'verified'))
$$;

create function private.is_member(p_org uuid) returns boolean
language sql stable security definer set search_path = '' as $$ select private.role_in(p_org) is not null $$;

create function private.can_write(p_org uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select private.role_in(p_org) in ('owner', 'admin', 'analyst') is true
$$;

create function private.is_admin(p_org uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select private.role_in(p_org) in ('owner', 'admin') is true
$$;

revoke all on function private.role_in(uuid), private.is_member(uuid), private.can_write(uuid), private.is_admin(uuid) from public;
grant execute on function private.role_in(uuid), private.is_member(uuid), private.can_write(uuid), private.is_admin(uuid) to authenticated, service_role;

-- Tamper-evident ledger --------------------------------------------------------------------

create function private.ledger_append(p_org uuid, p_event text, p_subject text, p_payload jsonb) returns void
language plpgsql security definer set search_path = '' as $$
declare
  v_prev public.ledger%rowtype;
  v_seq bigint;
  v_prev_hash text;
  v_payload_hash text := encode(extensions.digest(p_payload::text, 'sha256'), 'hex');
  v_now timestamptz := clock_timestamp();
begin
  perform pg_advisory_xact_lock(hashtextextended(p_org::text, 0));
  select * into v_prev from public.ledger where org_id = p_org order by seq desc limit 1;
  v_seq := coalesce(v_prev.seq, 0) + 1;
  v_prev_hash := coalesce(v_prev.hash, repeat('0', 64));
  insert into public.ledger (org_id, seq, event, subject, actor, payload_hash, prev_hash, hash, created_at)
  values (p_org, v_seq, p_event, p_subject, auth.uid(), v_payload_hash, v_prev_hash,
          private.ledger_hash(p_org, v_seq, p_event, p_subject, auth.uid(), v_payload_hash, v_prev_hash, v_now), v_now);
end $$;

create function private.ledger_hash(p_org uuid, p_seq bigint, p_event text, p_subject text, p_actor uuid,
                                    p_payload_hash text, p_prev_hash text, p_at timestamptz) returns text
language sql immutable set search_path = '' as $$
  select encode(extensions.digest(concat_ws('|', p_org, p_seq, p_event, p_subject, coalesce(p_actor::text, '-'),
    p_payload_hash, p_prev_hash, extract(epoch from p_at)::numeric(20, 6)), 'sha256'), 'hex')
$$;

create function private.ledger_forbid_change() returns trigger
language plpgsql as $$
begin
  -- Cascade from deleting a whole org is the only way a row may go.
  if tg_op = 'DELETE' and not exists (select 1 from public.orgs where id = old.org_id) then return old; end if;
  raise exception 'ledger is append-only';
end $$;
create trigger ledger_no_update before update or delete on public.ledger
  for each row execute function private.ledger_forbid_change();

create function private.ledger_row() returns trigger
language plpgsql security definer set search_path = '' as $$
declare
  v_row jsonb;
  v_subject text;
begin
  if tg_op = 'DELETE' then v_row := to_jsonb(old); else v_row := to_jsonb(new); end if;
  -- Deleting a whole org cascades here after the org row has gone.
  if not exists (select 1 from public.orgs where id = (v_row ->> 'org_id')::uuid) then return null; end if;
  v_subject := coalesce(v_row ->> 'control_id', v_row ->> 'domain', v_row ->> 'template_id', v_row ->> 'id', v_row ->> 'user_id', '');
  if tg_table_name = 'risks' then v_subject := 'RISK-' || lpad(v_row ->> 'seq', 3, '0'); end if;
  perform private.ledger_append((v_row ->> 'org_id')::uuid, tg_table_name || '.' || lower(tg_op), v_subject, v_row);
  return null;
end $$;

do $$
declare t text;
begin
  foreach t in array array['risks', 'answers', 'evidence', 'domains', 'scans', 'policies', 'attestations', 'members'] loop
    execute format('create trigger ledger_%1$s after insert or update or delete on public.%1$I
      for each row execute function private.ledger_row()', t);
  end loop;
end $$;

-- Recomputes the whole chain, so a row edited outside the app shows up here.
create function public.verify_ledger(p_org uuid) returns table (ok boolean, entries bigint, head text, broken_at bigint)
language plpgsql stable security definer set search_path = '' as $$
declare
  r public.ledger%rowtype;
  v_prev text := repeat('0', 64);
  v_count bigint := 0;
  v_anchor jsonb;
begin
  if not private.is_member(p_org) then raise exception 'not a member'; end if;
  for r in select * from public.ledger l where l.org_id = p_org order by l.seq loop
    v_count := v_count + 1;
    if r.seq <> v_count or r.prev_hash <> v_prev
       or r.hash <> private.ledger_hash(r.org_id, r.seq, r.event, r.subject, r.actor, r.payload_hash, r.prev_hash, r.created_at) then
      return query select false, v_count, v_prev, r.seq;
      return;
    end if;
    v_prev := r.hash;
  end loop;
  -- A chain cut short still adds up, so it must also contain the last signed head.
  select a.payload -> 'ledger' into v_anchor from public.attestations a where a.org_id = p_org order by a.issued_at desc limit 1;
  if v_anchor is not null and not exists (
    select 1 from public.ledger l where l.org_id = p_org and l.seq = (v_anchor ->> 'entries')::bigint and l.hash = v_anchor ->> 'head'
  ) then
    return query select false, v_count, v_prev, (v_anchor ->> 'entries')::bigint;
    return;
  end if;
  return query select true, v_count, v_prev, null::bigint;
end $$;

-- Risk numbering and timestamps --------------------------------------------------------------

create function private.risk_before_insert() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  -- A counter, not max(seq), so a RISK id is never reissued after a delete.
  update public.orgs set risk_counter = risk_counter + 1 where id = new.org_id returning risk_counter into new.seq;
  return new;
end $$;
create trigger risks_seq before insert on public.risks for each row execute function private.risk_before_insert();

create function private.touch() returns trigger language plpgsql as $$
begin new.updated_at := now(); return new; end $$;
create trigger risks_touch before update on public.risks for each row execute function private.touch();

-- Tenant onboarding and invites --------------------------------------------------------------

create function public.create_org(p_name text, p_profile jsonb) returns text
language plpgsql security definer set search_path = '' as $$
declare
  v_id uuid;
  v_base text := trim(both '-' from left(regexp_replace(lower(p_name), '[^a-z0-9]+', '-', 'g'), 40));
  v_slug text;
  v_email text := auth.jwt() ->> 'email';
begin
  if auth.uid() is null then raise exception 'sign in first'; end if;
  if (select count(*) from public.members where user_id = auth.uid() and role = 'owner') >= 10 then
    raise exception 'organization limit reached';
  end if;
  if char_length(v_base) < 3 then v_base := 'org-' || v_base; end if;
  v_slug := trim(both '-' from v_base);
  while char_length(v_slug) < 3 or exists (select 1 from public.orgs where slug = v_slug) loop
    v_slug := v_base || '-' || substr(md5(random()::text), 1, 5);
  end loop;
  insert into public.orgs (slug, name, profile, created_by) values (v_slug, p_name, p_profile, auth.uid()) returning id into v_id;
  insert into public.members (org_id, user_id, email, role) values (v_id, auth.uid(), coalesce(v_email, ''), 'owner');
  return v_slug;
end $$;

create function public.accept_invite(p_token text) returns text
language plpgsql security definer set search_path = '' as $$
declare
  v_invite public.invites%rowtype;
  v_slug text;
  v_email text := lower(auth.jwt() ->> 'email');
begin
  if auth.uid() is null then raise exception 'sign in first'; end if;
  select * into v_invite from public.invites
  where token_hash = encode(extensions.digest(p_token, 'sha256'), 'hex')
    and accepted_at is null and expires_at > now()
  for update;
  if not found or v_email is null or lower(v_invite.email) <> v_email then raise exception 'invite not valid for this account'; end if;
  insert into public.members (org_id, user_id, email, role) values (v_invite.org_id, auth.uid(), v_email, v_invite.role)
    on conflict (org_id, user_id) do nothing;
  update public.invites set accepted_at = now() where id = v_invite.id;
  select slug into v_slug from public.orgs where id = v_invite.org_id;
  return v_slug;
end $$;

revoke all on function public.create_org(text, jsonb), public.accept_invite(text), public.verify_ledger(uuid) from public, anon;
grant execute on function public.create_org(text, jsonb), public.accept_invite(text), public.verify_ledger(uuid) to authenticated;
revoke all on function private.ledger_append(uuid, text, text, jsonb), private.ledger_hash(uuid, bigint, text, text, uuid, text, text, timestamptz),
  private.ledger_forbid_change(), private.ledger_row(), private.risk_before_insert(), private.touch() from public;

-- Row level security ---------------------------------------------------------------------------

alter table public.orgs enable row level security;
alter table public.members enable row level security;
alter table public.invites enable row level security;
alter table public.risks enable row level security;
alter table public.answers enable row level security;
alter table public.evidence enable row level security;
alter table public.domains enable row level security;
alter table public.scans enable row level security;
alter table public.policies enable row level security;
alter table public.attestations enable row level security;
alter table public.ledger enable row level security;

create policy orgs_read on public.orgs for select to authenticated using (private.is_member(id));
create policy orgs_update on public.orgs for update to authenticated using (private.is_admin(id)) with check (private.is_admin(id));

create policy members_read on public.members for select to authenticated using (private.is_member(org_id));
create policy members_update on public.members for update to authenticated
  using (private.is_admin(org_id) and role <> 'owner') with check (private.is_admin(org_id) and role <> 'owner');
create policy members_delete on public.members for delete to authenticated
  using (private.is_admin(org_id) and role <> 'owner');

create policy invites_admin on public.invites for all to authenticated
  using (private.is_admin(org_id)) with check (private.is_admin(org_id));

create policy risks_read on public.risks for select to authenticated using (private.is_member(org_id));
create policy risks_insert on public.risks for insert to authenticated with check (private.can_write(org_id));
create policy risks_update on public.risks for update to authenticated using (private.can_write(org_id)) with check (private.can_write(org_id));
create policy risks_delete on public.risks for delete to authenticated using (private.is_admin(org_id));

create policy answers_read on public.answers for select to authenticated using (private.is_member(org_id));
create policy answers_insert on public.answers for insert to authenticated with check (private.can_write(org_id));
create policy answers_update on public.answers for update to authenticated using (private.can_write(org_id)) with check (private.can_write(org_id));

create policy evidence_read on public.evidence for select to authenticated using (private.is_member(org_id));
create policy domains_read on public.domains for select to authenticated using (private.is_member(org_id));
create policy domains_insert on public.domains for insert to authenticated with check (private.is_admin(org_id) and verified_at is null);
create policy domains_delete on public.domains for delete to authenticated using (private.is_admin(org_id));
create policy scans_read on public.scans for select to authenticated using (private.is_member(org_id));

create policy policies_read on public.policies for select to authenticated using (private.is_member(org_id));
create policy policies_insert on public.policies for insert to authenticated
  with check (private.can_write(org_id) and status = 'draft' and approved_at is null);

create policy attestations_read on public.attestations for select to authenticated using (private.is_member(org_id));
create policy attestations_public on public.attestations for select to anon, authenticated using (published);

create policy ledger_read on public.ledger for select to authenticated using (private.is_member(org_id));

create policy attestations_publish on public.attestations for update to authenticated
  using (private.is_admin(org_id)) with check (private.is_admin(org_id));

-- Privileges -----------------------------------------------------------------------------------
-- Explicit, so this works on projects without Supabase's automatic grants. It also removes
-- TRUNCATE, which would skip RLS and the ledger, and limits updates to the columns meant to change.

revoke all on all tables in schema public from anon, authenticated;
grant all on all tables in schema public to service_role;

grant select on public.orgs, public.members, public.evidence, public.scans, public.ledger, public.attestations, public.policies to authenticated;
grant update (name, profile, trust_enabled) on public.orgs to authenticated;
grant update (role), delete on public.members to authenticated;
grant select, insert, update, delete on public.invites, public.risks to authenticated;
grant select, insert, update on public.answers to authenticated;
grant select, delete on public.domains to authenticated;
grant insert (org_id, domain) on public.domains to authenticated;
grant insert on public.policies to authenticated;
grant update (published) on public.attestations to authenticated;
grant select on public.attestations to anon;

-- Evidence files ---------------------------------------------------------------------------

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('evidence', 'evidence', false, 10485760, array[
  'application/pdf', 'image/png', 'image/jpeg', 'text/plain', 'text/csv',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
]);

create policy evidence_files_read on storage.objects for select to authenticated
  using (bucket_id = 'evidence' and private.is_member(((storage.foldername(name))[1])::uuid));
create policy evidence_files_write on storage.objects for insert to authenticated
  with check (bucket_id = 'evidence' and private.can_write(((storage.foldername(name))[1])::uuid));
