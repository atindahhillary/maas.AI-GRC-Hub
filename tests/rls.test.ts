import { createHash } from 'node:crypto'
import { readFileSync, readdirSync } from 'node:fs'
import { PGlite, type Results } from '@electric-sql/pglite'
import { pgcrypto } from '@electric-sql/pglite/contrib/pgcrypto'
import { beforeAll, describe, expect, it } from 'vitest'
import { level, riskRef, score } from '../src/lib/risk'

// What a Supabase project already has before migrations run. Without the default
// privileges every denial below would come from a missing grant and prove nothing about RLS.
const SUPABASE_STUB = `
  create role anon nologin noinherit;
  create role authenticated nologin noinherit;
  create role service_role nologin noinherit bypassrls;

  create schema auth;
  create schema storage;
  create schema extensions;
  grant usage on schema public, auth, storage, extensions to anon, authenticated, service_role;
  alter default privileges in schema public grant all on tables to anon, authenticated, service_role;
  alter default privileges in schema public grant all on functions to anon, authenticated, service_role;
  alter default privileges in schema public grant all on sequences to anon, authenticated, service_role;

  create table auth.users (id uuid primary key, email text);
  create type auth.factor_status as enum ('unverified', 'verified');
  create table auth.mfa_factors (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references auth.users (id) on delete cascade,
    status auth.factor_status not null
  );
  create function auth.jwt() returns jsonb language sql stable as $$
    select nullif(current_setting('request.jwt.claims', true), '')::jsonb
  $$;
  create function auth.uid() returns uuid language sql stable as $$
    select (auth.jwt() ->> 'sub')::uuid
  $$;

  create table storage.buckets (
    id text primary key, name text not null, public boolean default false,
    file_size_limit bigint, allowed_mime_types text[]
  );
  create table storage.objects (
    id uuid primary key default gen_random_uuid(), bucket_id text references storage.buckets (id), name text
  );
  alter table storage.objects enable row level security;
  grant all on storage.objects, storage.buckets to anon, authenticated, service_role;
  create function storage.foldername(name text) returns text[] language sql immutable as $$
    select (string_to_array(name, '/'))[1:array_length(string_to_array(name, '/'), 1) - 1]
  $$;
`

const uid = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`
const A = uid(1001)
const B = uid(1002)
const USERS = {
  ownerA: uid(1), adminA: uid(2), analystA: uid(3), viewerA: uid(4), mfaA: uid(5), pendingMfaA: uid(6), ownerB: uid(7), outsider: uid(8),
}
type Name = keyof typeof USERS
type Who = { role: 'anon' | 'authenticated' | 'service_role' | 'none'; claims?: Record<string, unknown> }

const emailOf = (n: Name) => `${n.toLowerCase()}@test.local`
const user = (n: Name, aal = 'aal1'): Who => ({ role: 'authenticated', claims: { sub: USERS[n], email: emailOf(n), aal, role: 'authenticated' } })
const anon: Who = { role: 'anon' }
const service: Who = { role: 'service_role' }
const superuser: Who = { role: 'none' } // the migration owner, used to arrange and inspect
const [ownerA, adminA, analystA, viewerA, ownerB, outsider] = (['ownerA', 'adminA', 'analystA', 'viewerA', 'ownerB', 'outsider'] as const).map((n) => user(n))

const RLS = /row-level security|permission denied/

// A write refused by missing privileges is as blocked as one filtered to zero rows by RLS.
const refused = async <T extends { affectedRows?: number; rows?: unknown[] }>(q: Promise<T>) => {
  try {
    return await q
  } catch (e) {
    if (/permission denied/.test(String(e))) return { affectedRows: 0, rows: [] } as unknown as T
    throw e
  }
}
const NO_PERMISSION = /permission denied/

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex')

const seedOrg = (org: string, n: number, slug: string) => `
  insert into public.orgs (id, slug, name, profile) values ('${org}', '${slug}', 'Org ${slug}', '{}');
  insert into public.risks (id, org_id, description, likelihood, impact) values ('${uid(n + 1)}', '${org}', 'Seed risk', 2, 3);
  insert into public.answers (org_id, control_id, status) values ('${org}', 'GOV-01', 'yes');
  insert into public.evidence (org_id, control_id, name, storage_path, sha256, size_bytes)
    values ('${org}', 'GOV-01', 'e.pdf', '${org}/e.pdf', '${'a'.repeat(64)}', 1);
  insert into public.domains (id, org_id, domain) values ('${uid(n + 2)}', '${org}', '${slug}.example.com');
  insert into public.scans (id, org_id, domain_id, domain, score, results)
    values ('${uid(n + 3)}', '${org}', '${uid(n + 2)}', '${slug}.example.com', 50, '[]');
  insert into public.policies (id, org_id, template_id, title, body) values ('${uid(n + 4)}', '${org}', 'tpl', 'Draft', '{}');
  insert into public.policies (id, org_id, template_id, title, body, status, approved_at)
    values ('${uid(n + 5)}', '${org}', 'tpl2', 'Approved', '{}', 'approved', now());
  insert into public.attestations (id, org_id, slug, payload, canonical, signature, key_id, expires_at)
    values ('${uid(n + 6)}', '${org}', '${slug}', '{"score": 1}', '{}', 'sig', 'kid', now() + interval '90 days');
  insert into public.invites (id, org_id, email, role, token_hash)
    values ('${uid(n + 7)}', '${org}', 'new@test.local', 'viewer', '${sha256(`seed-${org}`)}');
  insert into storage.objects (bucket_id, name) values ('evidence', '${org}/e.pdf');
`

const RISK_A = uid(2001)
const DOMAIN_A = uid(2002)
const DRAFT_A = uid(2004)
const APPROVED_A = uid(2005)
const UNPUBLISHED_A = uid(2006)
const RISK_B = uid(3001)
const PUBLISHED_A = uid(2099)

const SEED = `
  insert into auth.users (id, email) values ${Object.entries(USERS).map(([n, id]) => `('${id}', '${emailOf(n as Name)}')`).join(',')};
  ${seedOrg(A, 2000, 'org-a')}
  ${seedOrg(B, 3000, 'org-b')}
  insert into public.attestations (id, org_id, slug, payload, canonical, signature, key_id, published, expires_at)
    values ('${PUBLISHED_A}', '${A}', 'org-a', '{"score": 2}', '{}', 'sig', 'kid', true, now() + interval '90 days');
  insert into public.members (org_id, user_id, email, role) values
    ('${A}', '${USERS.ownerA}', 'a', 'owner'), ('${A}', '${USERS.adminA}', 'a', 'admin'), ('${A}', '${USERS.analystA}', 'a', 'analyst'),
    ('${A}', '${USERS.viewerA}', 'a', 'viewer'), ('${A}', '${USERS.mfaA}', 'a', 'analyst'), ('${A}', '${USERS.pendingMfaA}', 'a', 'viewer'),
    ('${B}', '${USERS.ownerB}', 'b', 'owner');
  insert into auth.mfa_factors (user_id, status) values ('${USERS.mfaA}', 'verified'), ('${USERS.pendingMfaA}', 'unverified');
`

let db: PGlite

beforeAll(async () => {
  db = new PGlite({ extensions: { pgcrypto } })
  await db.exec(SUPABASE_STUB)
  const dir = new URL('../supabase/migrations/', import.meta.url)
  for (const file of readdirSync(dir).filter((f) => f.endsWith('.sql')).sort()) await db.exec(readFileSync(new URL(file, dir), 'utf8'))
  await db.exec(SEED)
}, 120_000)

type Row = Record<string, any>
type Step = (who: Who, sql: string, params?: unknown[]) => Promise<Results<Row>>

// Runs in one transaction that is always rolled back, so no test can see another test's writes.
async function scenario<T>(fn: (step: Step) => Promise<T>): Promise<T> {
  let out!: T
  await db.transaction(async (tx) => {
    const step: Step = async (who, sql, params = []) => {
      await tx.exec('savepoint step')
      try {
        await tx.query(`select set_config('request.jwt.claims', $1, true)`, [who.claims ? JSON.stringify(who.claims) : ''])
        await tx.exec(`set local role ${who.role}`)
        const result = await tx.query<Row>(sql, params)
        await tx.exec('release savepoint step')
        return result
      } catch (e) {
        await tx.exec('rollback to savepoint step')
        throw e
      }
    }
    out = await fn(step)
    await tx.exec('set local role none')
    await tx.rollback()
  })
  return out
}

const run = (who: Who, sql: string, params?: unknown[]) => scenario((s) => s(who, sql, params))
const count = async (who: Who, table: string, where = 'true') => (await run(who, `select count(*)::int as n from ${table} where ${where}`)).rows[0].n as number
const verify = (s: Step, who: Who = ownerA) => s(who, `select * from public.verify_ledger('${A}')`).then((r) => r.rows[0])

const riskInsert = (org: string) => `insert into public.risks (org_id, description, likelihood, impact) values ('${org}', 'Probe risk', 1, 1)`

const TABLES: Record<string, { insert: (org: string) => string; update: string }> = {
  risks: { insert: riskInsert, update: `description = 'changed'` },
  answers: { insert: (o) => `insert into public.answers (org_id, control_id, status) values ('${o}', 'IAM-01', 'yes')`, update: `note = 'changed'` },
  evidence: {
    insert: (o) => `insert into public.evidence (org_id, control_id, name, storage_path, sha256, size_bytes) values ('${o}', 'GOV-01', 'x', 'probe', '${'b'.repeat(64)}', 1)`,
    update: `name = 'changed'`,
  },
  domains: { insert: (o) => `insert into public.domains (org_id, domain) values ('${o}', 'probe.example.com')`, update: `domain = 'changed.example.com'` },
  scans: { insert: (o) => `insert into public.scans (org_id, domain_id, domain, score, results) values ('${o}', '${DOMAIN_A}', 'x', 100, '[]')`, update: 'score = 100' },
  policies: { insert: (o) => `insert into public.policies (org_id, template_id, title, body) values ('${o}', 'probe', 'x', '{}')`, update: `title = 'changed'` },
  attestations: {
    insert: (o) => `insert into public.attestations (org_id, slug, payload, canonical, signature, key_id, expires_at) values ('${o}', 'x', '{}', '{}', 's', 'k', now())`,
    update: 'published = true',
  },
  ledger: {
    insert: (o) => `insert into public.ledger (org_id, seq, event, subject, payload_hash, prev_hash, hash) values ('${o}', 999, 'e', 's', 'p', 'q', 'h')`,
    update: `subject = 'changed'`,
  },
  members: { insert: (o) => `insert into public.members (org_id, user_id, email, role) values ('${o}', '${USERS.ownerA}', 'x', 'owner')`, update: `role = 'viewer'` },
  invites: { insert: (o) => `insert into public.invites (org_id, email, role, token_hash) values ('${o}', 'x@test.local', 'admin', 'probe')`, update: `email = 'changed@test.local'` },
}

describe('fixture', () => {
  it('runs the probes as non-superusers, so RLS really applies', async () => {
    const { rows } = await run(ownerA, `select current_user as who, (select rolsuper from pg_roles where rolname = current_user) as sup, (select rolbypassrls from pg_roles where rolname = current_user) as bypass`)
    expect(rows[0]).toEqual({ who: 'authenticated', sup: false, bypass: false })
  })

  it('has row level security on every public table', async () => {
    const { rows } = await run(superuser, `select c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'public' and c.relkind = 'r' and not c.relrowsecurity`)
    expect(rows).toEqual([])
  })
})

describe('tenant isolation', () => {
  describe.each(Object.keys(TABLES))('%s', (table) => {
    const { insert, update } = TABLES[table]
    const t = `public.${table}`

    it('a member of org B can see a row of org B, so the denials below are not vacuous', async () => {
      expect(await count(ownerB, t, `org_id = '${B}'`)).toBeGreaterThan(0)
    })

    it('a member of org A reads nothing of org B', async () => {
      expect(await count(ownerA, t, `org_id = '${B}'`)).toBe(0)
    })

    it('a member of org A updates nothing of org B', async () => {
      expect((await refused(run(ownerA, `update ${t} set ${update} where org_id = '${B}'`))).affectedRows).toBe(0)
    })

    it('a member of org A deletes nothing of org B', async () => {
      expect((await refused(run(ownerA, `delete from ${t} where org_id = '${B}'`))).affectedRows).toBe(0)
    })

    it('a member of org A cannot insert into org B', async () => {
      await expect(run(ownerA, insert(B))).rejects.toThrow(RLS)
    })

    it('someone in no org reads nothing at all', async () => {
      expect(await count(outsider, t)).toBe(0)
    })
  })

  it('a member of org A cannot read or change org B itself', async () => {
    expect(await count(ownerA, 'public.orgs', `id = '${B}'`)).toBe(0)
    expect((await refused(run(ownerA, `update public.orgs set name = 'hacked' where id = '${B}'`))).affectedRows).toBe(0)
  })

  it('a member of org A cannot read or upload evidence files of org B', async () => {
    expect(await count(ownerA, 'storage.objects', `name like '${B}/%'`)).toBe(0)
    await expect(run(ownerA, `insert into storage.objects (bucket_id, name) values ('evidence', '${B}/x.pdf')`)).rejects.toThrow(RLS)
  })

  it('members read and analysts upload evidence files of their own org, viewers do not upload', async () => {
    expect(await count(viewerA, 'storage.objects', `name like '${A}/%'`)).toBe(1)
    expect((await run(analystA, `insert into storage.objects (bucket_id, name) values ('evidence', '${A}/y.pdf')`)).affectedRows).toBe(1)
    await expect(run(viewerA, `insert into storage.objects (bucket_id, name) values ('evidence', '${A}/y.pdf')`)).rejects.toThrow(RLS)
  })

  it('a risk cannot be moved into another org', async () => {
    await expect(run(ownerA, `update public.risks set org_id = '${B}' where id = '${RISK_A}'`)).rejects.toThrow(RLS)
  })
})

describe('member roles', () => {
  it.each(['risks', 'answers', 'evidence', 'domains', 'scans', 'policies', 'attestations', 'ledger', 'members'])('a viewer reads %s', async (table) => {
    expect(await count(viewerA, `public.${table}`, `org_id = '${A}'`)).toBeGreaterThan(0)
  })

  it('a viewer reads no invites', async () => {
    expect(await count(viewerA, 'public.invites')).toBe(0)
  })

  it.each(['risks', 'answers', 'domains', 'policies', 'invites'])('a viewer cannot insert into %s', async (table) => {
    await expect(run(viewerA, TABLES[table].insert(A))).rejects.toThrow(RLS)
  })

  it.each(['risks', 'answers', 'domains', 'policies', 'invites', 'members', 'attestations'])('a viewer cannot update %s', async (table) => {
    expect((await refused(run(viewerA, `update public.${table} set ${TABLES[table].update} where org_id = '${A}'`))).affectedRows).toBe(0)
  })

  it.each(['risks', 'answers', 'domains', 'policies', 'invites', 'members'])('a viewer cannot delete from %s', async (table) => {
    expect((await refused(run(viewerA, `delete from public.${table} where org_id = '${A}'`))).affectedRows).toBe(0)
  })

  it('a viewer cannot change the org', async () => {
    expect((await refused(run(viewerA, `update public.orgs set name = 'changed' where id = '${A}'`))).affectedRows).toBe(0)
  })

  it('an analyst can add and update a risk', async () => {
    expect((await run(analystA, riskInsert(A))).affectedRows).toBe(1)
    expect((await run(analystA, `update public.risks set description = 'updated' where id = '${RISK_A}'`)).affectedRows).toBe(1)
  })

  it('an analyst can answer but cannot write a policy row, the server does', async () => {
    expect((await run(analystA, TABLES.answers.insert(A))).affectedRows).toBe(1)
    await expect(run(analystA, TABLES.policies.insert(A))).rejects.toThrow(/permission denied/)
  })

  it('an analyst cannot delete a risk', async () => {
    expect((await refused(run(analystA, `delete from public.risks where id = '${RISK_A}'`))).affectedRows).toBe(0)
  })

  it('an analyst cannot add a domain, invite anyone, or change the org', async () => {
    await expect(run(analystA, TABLES.domains.insert(A))).rejects.toThrow(RLS)
    await expect(run(analystA, TABLES.invites.insert(A))).rejects.toThrow(RLS)
    expect((await refused(run(analystA, `update public.orgs set name = 'changed' where id = '${A}'`))).affectedRows).toBe(0)
  })

  it.each([['admin', adminA], ['owner', ownerA]])('an %s can delete a risk', async (_n, who) => {
    expect((await run(who, `delete from public.risks where id = '${RISK_A}'`)).affectedRows).toBe(1)
  })

  it('an admin can add a domain, invite, and rename the org', async () => {
    expect((await run(adminA, TABLES.domains.insert(A))).affectedRows).toBe(1)
    expect((await run(adminA, TABLES.invites.insert(A))).affectedRows).toBe(1)
    expect((await run(adminA, `update public.orgs set name = 'Renamed' where id = '${A}'`)).affectedRows).toBe(1)
  })

  it('nobody can rewrite an org slug or creator, not even the owner', async () => {
    await expect(run(ownerA, `update public.orgs set slug = 'taken' where id = '${A}'`)).rejects.toThrow(NO_PERMISSION)
    await expect(run(ownerA, `update public.orgs set created_by = null where id = '${A}'`)).rejects.toThrow(NO_PERMISSION)
  })

  it('nobody can create or delete an org row directly', async () => {
    await expect(run(ownerA, `insert into public.orgs (slug, name, profile) values ('sneaky', 'Sneaky', '{}')`)).rejects.toThrow(RLS)
    expect((await refused(run(ownerA, `delete from public.orgs where id = '${A}'`))).affectedRows).toBe(0)
  })
})

describe('facts only the server may write', () => {
  it.each(['scans', 'evidence', 'attestations'])('even an owner cannot insert into %s', async (table) => {
    await expect(run(ownerA, TABLES[table].insert(A))).rejects.toThrow(RLS)
  })

  it.each(['scans', 'evidence'])('even an owner cannot update or delete %s', async (table) => {
    expect((await refused(run(ownerA, `update public.${table} set ${TABLES[table].update} where org_id = '${A}'`))).affectedRows).toBe(0)
    expect((await refused(run(ownerA, `delete from public.${table} where org_id = '${A}'`))).affectedRows).toBe(0)
  })

  it('the service role can write them', async () => {
    expect((await run(service, TABLES.scans.insert(A))).affectedRows).toBe(1)
    expect((await run(service, TABLES.evidence.insert(A))).affectedRows).toBe(1)
    expect((await run(service, TABLES.attestations.insert(A))).affectedRows).toBe(1)
  })

  describe('domains.verified_at', () => {
    it('cannot be set on insert', async () => {
      await expect(run(ownerA, `insert into public.domains (org_id, domain, verified_at) values ('${A}', 'x.example.com', now())`)).rejects.toThrow(RLS)
    })

    it('stays empty on a normal insert', async () => {
      const { rows } = await run(adminA, `insert into public.domains (org_id, domain) values ('${A}', 'x.example.com') returning verified_at, token`)
      expect(rows[0].verified_at).toBeNull()
      expect(rows[0].token).toMatch(/^[0-9a-f]{32}$/)
    })

    it('cannot be set on update', async () => {
      await scenario(async (s) => {
        expect((await refused(s(ownerA, `update public.domains set verified_at = now() where id = '${DOMAIN_A}'`))).affectedRows).toBe(0)
        expect((await s(superuser, `select verified_at from public.domains where id = '${DOMAIN_A}'`)).rows[0].verified_at).toBeNull()
      })
    })
  })

  describe('policy approval', () => {
    it('cannot insert a policy as approved', async () => {
      await expect(run(ownerA, `insert into public.policies (org_id, template_id, title, body, status) values ('${A}', 'x', 'x', '{}', 'approved')`)).rejects.toThrow(RLS)
    })

    it('cannot insert a draft with an approval date', async () => {
      await expect(run(ownerA, `insert into public.policies (org_id, template_id, title, body, approved_at) values ('${A}', 'x', 'x', '{}', now())`)).rejects.toThrow(RLS)
    })

    it('cannot flip a draft to approved', async () => {
      await expect(run(ownerA, `update public.policies set status = 'approved' where id = '${DRAFT_A}'`)).rejects.toThrow(RLS)
    })

    it('cannot edit a draft in place, a change is a new version', async () => {
      expect((await refused(run(analystA, `update public.policies set title = 'Edited' where id = '${DRAFT_A}'`))).affectedRows).toBe(0)
    })

    it('cannot edit or retire an approved policy', async () => {
      expect((await refused(run(ownerA, `update public.policies set title = 'Edited' where id = '${APPROVED_A}'`))).affectedRows).toBe(0)
      expect((await refused(run(ownerA, `update public.policies set status = 'draft' where id = '${APPROVED_A}'`))).affectedRows).toBe(0)
    })

    it('cannot delete a policy', async () => {
      expect((await refused(run(ownerA, `delete from public.policies where org_id = '${A}'`))).affectedRows).toBe(0)
    })

    it.each(['approved_at = now()', `approved_by = '${USERS.ownerA}'`, `approved_by_email = 'ceo@test.local'`])('an analyst cannot forge %s on a draft', async (set) => {
      await expect(run(analystA, `update public.policies set ${set} where id = '${DRAFT_A}'`)).rejects.toThrow(RLS)
    })
  })

  describe('attestations', () => {
    it.each([`payload = '{"score": 100}'`, `canonical = 'x'`, `signature = 'x'`, `key_id = 'x'`, `slug = 'x'`, 'expires_at = now()', `org_id = '${B}'`])(
      'even an owner cannot change the signed column in: %s', async (set) => {
        await expect(run(ownerA, `update public.attestations set ${set} where id = '${UNPUBLISHED_A}'`)).rejects.toThrow(NO_PERMISSION)
      })

    it.each([['admin', adminA], ['owner', ownerA]])('an %s can flip published', async (_n, who) => {
      await scenario(async (s) => {
        expect((await s(who, `update public.attestations set published = true where id = '${UNPUBLISHED_A}'`)).affectedRows).toBe(1)
        const live = await s(anon, `select public.attestation_live(signature) as live from (select 'sig-unpublished'::text as signature) x`)
        expect(live.rows).toHaveLength(1)
        expect((await s(who, `update public.attestations set published = false where id = '${UNPUBLISHED_A}'`)).affectedRows).toBe(1)
      })
    })

    it.each([['analyst', analystA], ['viewer', viewerA], ['outsider', outsider], ['owner of another org', ownerB]])('an %s cannot flip published', async (_n, who) => {
      expect((await refused(run(who, `update public.attestations set published = true where id = '${UNPUBLISHED_A}'`))).affectedRows).toBe(0)
    })

    it('even an owner cannot delete one', async () => {
      expect((await refused(run(ownerA, `delete from public.attestations where org_id = '${A}'`))).affectedRows).toBe(0)
    })
  })
})

describe('anonymous visitors', () => {
  it('cannot list attestations, so the tenant directory stays private', async () => {
    await expect(run(anon, 'select id from public.attestations')).rejects.toThrow(/permission denied/)
  })

  it('reach a published attestation only through its slug', async () => {
    const hit = await run(superuser, `select slug from public.attestations where id = '${PUBLISHED_A}'`)
    const { rows } = await run(anon, `select * from public.trust_page('${(hit.rows[0] as { slug: string }).slug}')`)
    expect(rows).toHaveLength(1)
    expect(Object.keys(rows[0] as object).sort()).toEqual(['canonical', 'key_id', 'signature'])
    expect((await run(anon, `select * from public.trust_page('no-such-org')`)).rows).toHaveLength(0)
  })

  it('unpublishing withdraws an attestation', async () => {
    await scenario(async (s) => {
      const { signature } = (await s(superuser, `select signature from public.attestations where id = '${PUBLISHED_A}'`)).rows[0] as { signature: string }
      const live = async () => ((await s(anon, `select public.attestation_live('${signature}') as l`)).rows[0] as { l: boolean }).l
      expect(await live()).toBe(true)
      await s(superuser, `update public.attestations set published = false`)
      expect(await live()).toBe(false)
    })
  })

  it.each(['orgs', 'members', 'invites', 'risks', 'answers', 'evidence', 'domains', 'scans', 'policies', 'ledger'])('read nothing from %s', async (table) => {
    await expect(count(anon, `public.${table}`)).rejects.toThrow(/permission denied/)
  })

  it('read no evidence files', async () => {
    expect(await count(anon, 'storage.objects')).toBe(0)
  })

  it.each(Object.keys(TABLES))('cannot insert into %s', async (table) => {
    await expect(run(anon, TABLES[table].insert(A))).rejects.toThrow(RLS)
  })

  it('cannot flip published or delete an attestation', async () => {
    expect((await refused(run(anon, `update public.attestations set published = false where id = '${PUBLISHED_A}'`))).affectedRows).toBe(0)
    expect((await refused(run(anon, `delete from public.attestations where id = '${PUBLISHED_A}'`))).affectedRows).toBe(0)
  })

  it.each([
    `select public.create_org('Anon Org', '{}')`,
    `select public.accept_invite('token')`,
    `select * from public.verify_ledger('${A}')`,
  ])('cannot run %s', async (sql) => {
    await expect(run(anon, sql)).rejects.toThrow(NO_PERMISSION)
  })
})

describe('role escalation', () => {
  const setRole = (name: Name, role: string) => `update public.members set role = '${role}' where org_id = '${A}' and user_id = '${USERS[name]}'`

  it('an admin cannot make themselves owner', async () => {
    await expect(run(adminA, setRole('adminA', 'owner'))).rejects.toThrow(RLS)
  })

  it('an admin cannot make anyone else owner', async () => {
    await expect(run(adminA, setRole('analystA', 'owner'))).rejects.toThrow(RLS)
  })

  it('an admin cannot demote or remove the owner', async () => {
    expect((await refused(run(adminA, setRole('ownerA', 'viewer')))).affectedRows).toBe(0)
    expect((await refused(run(adminA, `delete from public.members where org_id = '${A}' and user_id = '${USERS.ownerA}'`))).affectedRows).toBe(0)
  })

  it('an admin can still change an ordinary role', async () => {
    expect((await run(adminA, setRole('viewerA', 'analyst'))).affectedRows).toBe(1)
  })

  it.each([['analyst', analystA, 'analystA'], ['viewer', viewerA, 'viewerA']] as const)('an %s cannot promote themselves', async (_n, who, name) => {
    expect((await refused(run(who, setRole(name, 'admin')))).affectedRows).toBe(0)
  })

  it('a user cannot insert themselves into members', async () => {
    await expect(run(outsider, `insert into public.members (org_id, user_id, email, role) values ('${A}', '${USERS.outsider}', 'x', 'viewer')`)).rejects.toThrow(RLS)
  })

  it('an admin cannot insert a member directly, only invite', async () => {
    await expect(run(adminA, `insert into public.members (org_id, user_id, email, role) values ('${A}', '${USERS.outsider}', 'x', 'viewer')`)).rejects.toThrow(RLS)
  })

  it('an admin cannot invite an owner', async () => {
    await expect(run(adminA, `insert into public.invites (org_id, email, role, token_hash) values ('${A}', 'x@test.local', 'owner', 'probe')`)).rejects.toThrow(/check constraint/)
  })

  it('an admin cannot re-arm or edit an invite, or read its token hash', async () => {
    await expect(run(adminA, `update public.invites set role = 'admin', accepted_at = null where org_id = '${A}'`)).rejects.toThrow(/permission denied/)
    await expect(run(adminA, `select token_hash from public.invites where org_id = '${A}'`)).rejects.toThrow(/permission denied/)
  })

  it('an admin cannot re-point a member row at a user who never accepted an invite', async () => {
    await expect(run(adminA, `update public.members set user_id = '${USERS.outsider}' where org_id = '${A}' and user_id = '${USERS.viewerA}'`)).rejects.toThrow(/row-level security|permission denied/)
  })

  it('a signed-in user cannot call the private ledger writer against another org', async () => {
    await expect(run(outsider, `select private.ledger_append('${B}', 'risks.delete', 'forged', null, '{}')`)).rejects.toThrow(NO_PERMISSION)
  })

  it('an anonymous visitor cannot call the private ledger writer', async () => {
    await expect(run(anon, `select private.ledger_append('${B}', 'risks.delete', 'forged', null, '{}')`)).rejects.toThrow(NO_PERMISSION)
  })
})

describe('MFA', () => {
  const mfa = (aal?: string) => {
    const who = user('mfaA', aal)
    if (!aal) delete who.claims!.aal
    return who
  }

  it.each([['aal1', 'aal1'], ['a missing aal claim', undefined]])('a user with a verified factor sees nothing at %s', async (_n, aal) => {
    for (const table of ['orgs', 'members', 'risks', 'answers', 'ledger']) expect(await count(mfa(aal), `public.${table}`)).toBe(0)
  })

  it('a user with a verified factor cannot write at aal1', async () => {
    await expect(run(mfa('aal1'), riskInsert(A))).rejects.toThrow(RLS)
    expect((await refused(run(mfa('aal1'), `update public.risks set description = 'x' where id = '${RISK_A}'`))).affectedRows).toBe(0)
  })

  it('verify_ledger treats an aal1 session as a non-member', async () => {
    await expect(run(mfa('aal1'), `select * from public.verify_ledger('${A}')`)).rejects.toThrow(/not a member/)
  })

  it('a user with a verified factor sees and writes their org at aal2', async () => {
    expect(await count(mfa('aal2'), 'public.orgs')).toBe(1)
    expect(await count(mfa('aal2'), 'public.risks', `org_id = '${A}'`)).toBe(1)
    expect((await run(mfa('aal2'), riskInsert(A))).affectedRows).toBe(1)
  })

  it('aal2 does not open any other org', async () => {
    expect(await count(mfa('aal2'), 'public.risks', `org_id = '${B}'`)).toBe(0)
  })

  it('an unverified factor does not gate a user', async () => {
    expect(await count(user('pendingMfaA'), 'public.orgs')).toBe(1)
  })

  it('a user with no factor is fine at aal1', async () => {
    expect(await count(ownerA, 'public.orgs')).toBe(1)
  })
})

describe('ledger', () => {
  const entries = (s: Step, org = A) => s(superuser, `select * from public.ledger where org_id = '${org}' order by seq`).then((r) => r.rows)
  const headSeq = async (s: Step) => Number((await entries(s)).at(-1)!.seq)

  it('verifies the chain written during seeding', async () => {
    await scenario(async (s) => {
      expect(await verify(s)).toMatchObject({ ok: true, broken_at: null })
    })
  })

  it('appends each change with a valid chain and records the actor', async () => {
    await scenario(async (s) => {
      const before = (await entries(s)).length
      await s(analystA, riskInsert(A))
      await s(analystA, TABLES.answers.insert(A))
      await s(adminA, `delete from public.risks where id = '${RISK_A}'`)
      const rows = await entries(s)
      expect(rows).toHaveLength(before + 3)
      rows.forEach((r, i) => {
        expect(Number(r.seq)).toBe(i + 1)
        expect(r.prev_hash).toBe(i ? rows[i - 1].hash : '0'.repeat(64))
        expect(r.hash).toMatch(/^[0-9a-f]{64}$/)
        expect(r.payload_hash).toMatch(/^[0-9a-f]{64}$/)
      })
      expect(rows.slice(-3).map((r) => [r.event, r.actor])).toEqual([
        ['risks.insert', USERS.analystA], ['answers.insert', USERS.analystA], ['risks.delete', USERS.adminA],
      ])
      expect(rows.at(-3)!.subject).toBe('RISK-002')
      expect(await verify(s)).toMatchObject({ ok: true, entries: before + 3, head: rows.at(-1)!.hash, broken_at: null })
    })
  })

  it('keeps each org on its own chain', async () => {
    await scenario(async (s) => {
      const before = (await entries(s, B)).length
      await s(analystA, riskInsert(A))
      expect(await entries(s, B)).toHaveLength(before)
      expect((await entries(s, B))[0].prev_hash).toBe('0'.repeat(64))
    })
  })

  it.each([['the migration owner', superuser], ['the service role', service]])('UPDATE raises for %s', async (_n, who) => {
    await expect(run(who, `update public.ledger set subject = 'forged' where org_id = '${A}' and seq = 1`)).rejects.toThrow(/append-only/)
  })

  it('DELETE raises for the migration owner', async () => {
    await expect(run(superuser, `delete from public.ledger where org_id = '${A}' and seq = 1`)).rejects.toThrow(/append-only/)
  })

  it('DELETE is not even granted to the service role', async () => {
    await expect(run(service, `delete from public.ledger where org_id = '${A}' and seq = 1`)).rejects.toThrow(/permission denied/)
  })

  it('TRUNCATE raises even for the migration owner', async () => {
    await expect(run(superuser, 'truncate public.ledger cascade')).rejects.toThrow(/append-only/)
  })

  it('claim_scan allows three tests per domain, then refuses, and clients cannot call it', async () => {
    await scenario(async (s) => {
      const claim = async () => ((await s(service, `select public.claim_scan('${A}', 'limit.example.com', null) as ok`)).rows[0] as { ok: boolean }).ok
      expect([await claim(), await claim(), await claim(), await claim()]).toEqual([true, true, true, false])
    })
    await expect(run(ownerA, `select public.claim_scan('${A}', 'x.example.com', null)`)).rejects.toThrow(/permission denied/)
  })

  it('answered_by and updated_at are stamped by the database, not the client', async () => {
    await scenario(async (s) => {
      await s(analystA, `insert into public.answers (org_id, control_id, status, answered_by, updated_at) values ('${A}', 'GOV-99', 'yes', '${USERS.ownerA}', '2000-01-01')`)
      const row = (await s(superuser, `select answered_by, updated_at from public.answers where control_id = 'GOV-99'`)).rows[0] as { answered_by: string; updated_at: Date }
      expect(row.answered_by).toBe(USERS.analystA)
      expect(new Date(row.updated_at).getFullYear()).toBeGreaterThan(2000)
    })
  })

  it('a risk id and creation time cannot be rewritten by a client', async () => {
    await expect(run(analystA, `update public.risks set seq = 999 where id = '${RISK_A}'`)).rejects.toThrow(/permission denied/)
  })

  it('UPDATE and DELETE reach no row for a member', async () => {
    expect((await refused(run(ownerA, `update public.ledger set subject = 'forged' where org_id = '${A}'`))).affectedRows).toBe(0)
    expect((await refused(run(ownerA, `delete from public.ledger where org_id = '${A}'`))).affectedRows).toBe(0)
  })

  it('a member cannot TRUNCATE the ledger', async () => {
    await expect(run(ownerA, 'truncate public.ledger')).rejects.toThrow(NO_PERMISSION)
  })

  it.each(['risks', 'scans', 'evidence', 'attestations', 'members'])('a member cannot TRUNCATE %s', async (table) => {
    await expect(run(ownerA, `truncate public.${table} cascade`)).rejects.toThrow(NO_PERMISSION)
  })

  const tamper = async (s: Step, change: string) => {
    await s(superuser, 'alter table public.ledger disable trigger ledger_no_update')
    await s(superuser, change)
    await s(superuser, 'alter table public.ledger enable trigger ledger_no_update')
  }

  it.each([
    [`subject = 'forged'`], [`event = 'forged'`], [`actor = '${USERS.ownerB}'`], [`payload_hash = '${'0'.repeat(64)}'`],
    [`prev_hash = '${'0'.repeat(64)}'`], [`hash = '${'0'.repeat(64)}'`], [`created_at = created_at + interval '1 second'`],
  ])('tampering with %s reports ok=false at that entry', async (set) => {
    await scenario(async (s) => {
      await tamper(s, `update public.ledger set ${set} where org_id = '${A}' and seq = 3`)
      expect(await verify(s)).toMatchObject({ ok: false, broken_at: 3, entries: 3 })
    })
  })

  it('deleting an entry from the middle reports the entry after the gap', async () => {
    await scenario(async (s) => {
      await tamper(s, `delete from public.ledger where org_id = '${A}' and seq = 3`)
      expect(await verify(s)).toMatchObject({ ok: false, broken_at: 4 })
    })
  })

  it('a forged entry added at the head is caught', async () => {
    await scenario(async (s) => {
      const seq = (await headSeq(s)) + 1
      await tamper(s, `insert into public.ledger (org_id, seq, event, subject, payload_hash, prev_hash, hash) values ('${A}', ${seq}, 'e', 's', 'p', 'q', 'h')`)
      expect(await verify(s)).toMatchObject({ ok: false, broken_at: seq })
    })
  })

  it('tampering with one org leaves the other org verifying', async () => {
    await scenario(async (s) => {
      await tamper(s, `update public.ledger set subject = 'forged' where org_id = '${A}' and seq = 3`)
      expect((await s(ownerB, `select * from public.verify_ledger('${B}')`)).rows[0]).toMatchObject({ ok: true })
    })
  })

  it('verify_ledger refuses a non-member', async () => {
    await expect(run(outsider, `select * from public.verify_ledger('${A}')`)).rejects.toThrow(/not a member/)
  })

  it('deleting a whole org removes its ledger, the one permitted path', async () => {
    await scenario(async (s) => {
      await s(superuser, `delete from public.orgs where id = '${B}'`)
      expect(await entries(s, B)).toEqual([])
    })
  })
})

describe('risk numbering and levels', () => {
  const seqs = (s: Step, org: string) => s(superuser, `select seq from public.risks where org_id = '${org}' order by seq`).then((r) => r.rows.map((x) => x.seq))

  it('numbers risks per org', async () => {
    await scenario(async (s) => {
      await s(ownerA, riskInsert(A))
      await s(ownerA, riskInsert(A))
      await s(ownerB, riskInsert(B))
      expect(await seqs(s, A)).toEqual([1, 2, 3])
      expect(await seqs(s, B)).toEqual([1, 2])
    })
  })

  it('ignores a seq the client tries to choose', async () => {
    const { rows } = await run(ownerA, `insert into public.risks (org_id, seq, description, likelihood, impact) values ('${A}', 999, 'Probe', 1, 1) returning seq`)
    expect(rows[0].seq).toBe(2)
  })

  it('never reissues a RISK id after a delete, the register is an audit record', async () => {
    await scenario(async (s) => {
      await s(ownerA, riskInsert(A))
      const { rows } = await s(ownerA, `delete from public.risks where org_id = '${A}' and seq = 2 returning seq`)
      expect(rows).toHaveLength(1)
      const next = await s(ownerA, `${riskInsert(A)} returning seq`)
      expect(next.rows[0].seq).toBe(3)
    })
  })

  it('stores the same score and band as src/lib/risk.ts for all 25 combinations', async () => {
    await scenario(async (s) => {
      for (let l = 1; l <= 5; l++) {
        for (let i = 1; i <= 5; i++) {
          const { rows } = await s(ownerA, `insert into public.risks (org_id, description, likelihood, impact, residual_likelihood, residual_impact)
            values ('${A}', 'Grid', ${l}, ${i}, ${i}, ${l}) returning inherent_score, inherent_level, residual_score, residual_level`)
          expect(rows[0]).toEqual({ inherent_score: score(l, i), inherent_level: level(score(l, i)), residual_score: score(l, i), residual_level: level(score(l, i)) })
        }
      }
    })
  })

  it('reproduces the video example, 4x5=20 High falling to 2x5=10 Medium', async () => {
    const { rows } = await run(ownerA, `insert into public.risks (org_id, seq, description, likelihood, impact, residual_likelihood, residual_impact)
      values ('${A}', 0, 'Video', 4, 5, 2, 5) returning *`)
    expect(rows[0]).toMatchObject({ inherent_score: 20, inherent_level: 'High', residual_score: 10, residual_level: 'Medium' })
    expect(riskRef(rows[0].seq)).toBe('RISK-002')
  })

  it('leaves residual fields empty until they are assessed', async () => {
    const { rows } = await run(ownerA, `${riskInsert(A)} returning residual_score, residual_level`)
    expect(rows[0]).toEqual({ residual_score: null, residual_level: null })
  })

  it.each(['0, 1', '6, 1', '1, 0', '1, 6'])('rejects likelihood and impact of %s', async (values) => {
    await expect(run(ownerA, `insert into public.risks (org_id, description, likelihood, impact) values ('${A}', 'Out of range', ${values})`)).rejects.toThrow(/check constraint/)
  })

  it('does not let a client write the generated score', async () => {
    await expect(run(ownerA, `update public.risks set inherent_score = 1 where id = '${RISK_A}'`)).rejects.toThrow(/can only be updated to DEFAULT/)
  })
})

describe('accept_invite', () => {
  const TOKEN = 'invite-token'
  const addInvite = (s: Step, email: string, opts: { expires?: string; role?: string } = {}) =>
    s(superuser, `insert into public.invites (org_id, email, role, token_hash, expires_at)
      values ('${A}', '${email}', '${opts.role ?? 'analyst'}', '${sha256(TOKEN)}', ${opts.expires ?? `now() + interval '7 days'`})`)
  const accept = (s: Step, who: Who, token = TOKEN) => s(who, `select public.accept_invite('${token}') as slug`)
  const memberRole = async (s: Step, name: Name) =>
    (await s(superuser, `select role from public.members where org_id = '${A}' and user_id = '${USERS[name]}'`)).rows[0]?.role

  it('adds the invited user with the invited role and spends the invite', async () => {
    await scenario(async (s) => {
      await addInvite(s, emailOf('outsider'))
      expect((await accept(s, outsider)).rows[0].slug).toBe('org-a')
      expect(await memberRole(s, 'outsider')).toBe('analyst')
      expect((await s(superuser, `select accepted_at from public.invites where token_hash = '${sha256(TOKEN)}'`)).rows[0].accepted_at).not.toBeNull()
      expect((await s(outsider, 'select id from public.orgs')).rows).toHaveLength(1)
    })
  })

  it('matches the email case-insensitively', async () => {
    await scenario(async (s) => {
      await addInvite(s, emailOf('outsider').toUpperCase())
      expect((await accept(s, outsider)).rows[0].slug).toBe('org-a')
    })
  })

  it('rejects the wrong email', async () => {
    await scenario(async (s) => {
      await addInvite(s, 'someone.else@test.local')
      await expect(accept(s, outsider)).rejects.toThrow(/invite not valid/)
      expect(await memberRole(s, 'outsider')).toBeUndefined()
    })
  })

  it('rejects a session with no email claim', async () => {
    await scenario(async (s) => {
      await addInvite(s, emailOf('outsider'))
      await expect(accept(s, { role: 'authenticated', claims: { sub: USERS.outsider, aal: 'aal1' } })).rejects.toThrow()
      expect(await memberRole(s, 'outsider')).toBeUndefined()
    })
  })

  it('rejects an expired invite', async () => {
    await scenario(async (s) => {
      await addInvite(s, emailOf('outsider'), { expires: `now() - interval '1 minute'` })
      await expect(accept(s, outsider)).rejects.toThrow(/invite not valid/)
      expect(await memberRole(s, 'outsider')).toBeUndefined()
    })
  })

  it('rejects a used invite', async () => {
    await scenario(async (s) => {
      await addInvite(s, emailOf('outsider'))
      await accept(s, outsider)
      await expect(accept(s, outsider)).rejects.toThrow(/invite not valid/)
    })
  })

  it('rejects an unknown token', async () => {
    await scenario(async (s) => {
      await addInvite(s, emailOf('outsider'))
      await expect(accept(s, outsider, 'wrong-token')).rejects.toThrow(/invite not valid/)
    })
  })

  it('rejects a session with no user', async () => {
    await scenario(async (s) => {
      await addInvite(s, emailOf('outsider'))
      await expect(accept(s, { role: 'authenticated' })).rejects.toThrow(/sign in first/)
    })
  })

  it('does not lower or raise an existing member', async () => {
    await scenario(async (s) => {
      await addInvite(s, emailOf('viewerA'), { role: 'admin' })
      await accept(s, viewerA)
      expect(await memberRole(s, 'viewerA')).toBe('viewer')
    })
  })
})

describe('create_org', () => {
  const create = (s: Step, who: Who, name: string) => s(who, `select public.create_org($1, '{}') as slug`, [name]).then((r) => r.rows[0].slug as string)
  const SLUG = /^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$/

  it('makes the caller the owner', async () => {
    await scenario(async (s) => {
      const slug = await create(s, outsider, 'Acme Holdings')
      expect(slug).toBe('acme-holdings')
      const { rows } = await s(outsider, `select m.role, m.email, o.created_by from public.members m join public.orgs o on o.id = m.org_id where o.slug = '${slug}'`)
      expect(rows).toEqual([{ role: 'owner', email: emailOf('outsider'), created_by: USERS.outsider }])
    })
  })

  it('records the owner in the new ledger, which verifies', async () => {
    await scenario(async (s) => {
      const slug = await create(s, outsider, 'Acme Holdings')
      const { id } = (await s(outsider, `select id from public.orgs where slug = '${slug}'`)).rows[0]
      expect((await s(outsider, `select * from public.verify_ledger('${id}')`)).rows[0]).toMatchObject({ ok: true, entries: 1 })
    })
  })

  it('resolves a slug collision instead of failing', async () => {
    await scenario(async (s) => {
      const first = await create(s, outsider, 'Acme Holdings')
      const second = await create(s, ownerB, 'Acme Holdings')
      const third = await create(s, ownerB, 'ACME  holdings!')
      expect(new Set([first, second, third]).size).toBe(3)
      for (const slug of [second, third]) expect(slug).toMatch(/^acme-holdings-[0-9a-f]{5}$/)
    })
  })

  it('collides against the seeded org too', async () => {
    await scenario(async (s) => {
      expect(await create(s, outsider, 'Org A')).toMatch(/^org-a-[0-9a-f]{5}$/)
    })
  })

  it.each(['ab', '!!!', 'Ñ!', '日本語の会社', '--x--', 'a'.repeat(120), `${'long name '.repeat(11)}x`])('derives a valid slug from the name %j, twice', async (name) => {
    await scenario(async (s) => {
      expect(await create(s, outsider, name)).toMatch(SLUG)
      expect(await create(s, ownerB, name)).toMatch(SLUG)
    })
  })

  it('rejects a session with no user', async () => {
    await expect(run({ role: 'authenticated' }, `select public.create_org('Nobody', '{}')`)).rejects.toThrow(/sign in first/)
  })
})
