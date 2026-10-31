// Proves the emulator itself, with the real supabase-js client, so a journey pass cannot be an emulator false positive.
//   node tests/e2e/fake-supabase.mjs        (in another terminal, fresh process)
//   node tests/e2e/emulator-check.mjs
import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const URL_ = 'http://127.0.0.1:54321'
const key = (role) => {
  const body = `${Buffer.from('{"alg":"HS256","typ":"JWT"}').toString('base64url')}.${Buffer.from(JSON.stringify({ iss: 'fake-supabase', role, iat: 1700000000, exp: 2000000000 })).toString('base64url')}`
  return `${body}.${createHmac('sha256', 'fake-supabase-local-only-not-a-real-secret').update(body).digest('base64url')}`
}
const ANON = key('anon')
const SERVICE = key('service_role')
const opts = { auth: { persistSession: false, autoRefreshToken: false } }
const client = (k) => createClient(URL_, k, opts)
const tag = Date.now().toString(36)

let passed = 0
const failures = []
async function check(name, fn) {
  try {
    await fn()
    passed++
    console.log(`PASS ${name}`)
  } catch (e) {
    failures.push(name)
    console.log(`FAIL ${name}: ${e.message}`)
  }
}

async function newUser(name) {
  const c = client(ANON)
  const { data, error } = await c.auth.signUp({ email: `${name}.${tag}@example.test`, password: 'correct-horse-battery' })
  assert.equal(error, null)
  assert.ok(data.session, 'signup auto-confirms and returns a session')
  return { c, user: data.user, session: data.session }
}

const service = client(SERVICE)
const a = await newUser('a')
const b = await newUser('b')
const { data: slug, error: orgError } = await a.c.rpc('create_org', { p_name: `Org ${tag}`, p_profile: { sector: 'ngo' } })
assert.equal(orgError, null)
const { data: org } = await a.c.from('orgs').select('id').eq('slug', slug).single()

await check('jwt carries the required claims', async () => {
  const claims = JSON.parse(Buffer.from(a.session.access_token.split('.')[1], 'base64url'))
  assert.equal(claims.sub, a.user.id)
  assert.equal(claims.role, 'authenticated')
  assert.equal(claims.aal, 'aal1')
  assert.ok(claims.session_id && claims.email && claims.exp)
})
await check('wrong password is rejected, right one signs in', async () => {
  const c = client(ANON)
  const bad = await c.auth.signInWithPassword({ email: a.user.email, password: 'nope-nope-nope' })
  assert.equal(bad.error?.code, 'invalid_credentials')
  assert.equal((await c.auth.signInWithPassword({ email: a.user.email, password: 'correct-horse-battery' })).error, null)
})
await check('refresh rotates, and logout kills the session', async () => {
  const c = client(ANON)
  const { data } = await c.auth.signInWithPassword({ email: a.user.email, password: 'correct-horse-battery' })
  const fresh = await c.auth.refreshSession({ refresh_token: data.session.refresh_token })
  assert.equal(fresh.error, null)
  assert.notEqual(fresh.data.session.refresh_token, data.session.refresh_token)
  assert.ok((await c.auth.refreshSession({ refresh_token: data.session.refresh_token })).error, 'old refresh token is spent')
  const token = fresh.data.session.access_token
  assert.equal((await c.auth.getUser(token)).error, null)
  await c.auth.signOut({ scope: 'local' })
  assert.ok((await c.auth.getUser(token)).error, 'token of a dead session is refused by /user')
})
await check('MFA factors on the user drive the assurance level', async () => {
  const c = client(ANON)
  const u = await newUser('mfa')
  await c.auth.setSession({ access_token: u.session.access_token, refresh_token: u.session.refresh_token })
  assert.equal((await c.auth.mfa.getAuthenticatorAssuranceLevel()).data.nextLevel, 'aal1')
  assert.equal((await c.auth.mfa.listFactors()).data.all.length, 0)
})
await check('a forged token is refused', async () => {
  const forged = `${a.session.access_token.slice(0, -4)}AAAA`
  const c = createClient(URL_, ANON, { ...opts, global: { headers: { Authorization: `Bearer ${forged}` } } })
  const { error, status } = await c.from('orgs').select('id')
  assert.equal(status, 401)
  assert.equal(error.code, 'PGRST301')
})
await check('a role claim outside the three API roles is refused', async () => {
  const body = `${Buffer.from('{"alg":"HS256"}').toString('base64url')}.${Buffer.from('{"role":"postgres"}').toString('base64url')}`
  const t = `${body}.${createHmac('sha256', 'fake-supabase-local-only-not-a-real-secret').update(body).digest('base64url')}`
  const c = createClient(URL_, ANON, { ...opts, global: { headers: { Authorization: `Bearer ${t}` } } })
  assert.equal((await c.from('orgs').select('id')).status, 401)
})
await check('a missing apikey is refused', async () => {
  assert.equal((await fetch(`${URL_}/rest/v1/orgs`, { headers: { authorization: `Bearer ${ANON}` } })).status, 401)
})
await check('RLS: another user sees nothing and the service role sees it', async () => {
  assert.deepEqual((await b.c.from('orgs').select('id').eq('id', org.id)).data, [])
  assert.equal((await service.from('orgs').select('id').eq('id', org.id)).data.length, 1)
})
await check('RLS: insert into another org is 403 42501', async () => {
  const { error, status } = await b.c.from('risks').insert({ org_id: org.id, description: 'Probe', likelihood: 1, impact: 1 })
  assert.equal(status, 403)
  assert.equal(error.code, '42501')
  assert.match(error.message, /row-level security/)
})
await check('anon on an RPC it has no grant for is 401 42501', async () => {
  const { error, status } = await client(ANON).rpc('create_org', { p_name: 'Nope', p_profile: {} })
  assert.equal(status, 401)
  assert.equal(error.code, '42501')
})
await check('column privilege: orgs.slug update is 403 42501, name update works', async () => {
  const { error, status } = await a.c.from('orgs').update({ slug: 'taken-slug' }).eq('id', org.id)
  assert.equal(status, 403)
  assert.equal(error.code, '42501')
  assert.equal((await a.c.from('orgs').update({ name: 'Renamed' }).eq('id', org.id)).error, null)
})
await check('23505 reaches the client as 409', async () => {
  const row = { org_id: org.id, source_ref: 'dup', description: 'Dup', likelihood: 1, impact: 1 }
  assert.equal((await a.c.from('risks').insert(row)).error, null)
  const { error, status } = await a.c.from('risks').insert(row)
  assert.equal(status, 409)
  assert.equal(error.code, '23505')
})
await check('bulk insert: a key missing from one row is NULL, not the default, as PostgREST', async () => {
  const { error, status } = await a.c.from('risks').insert([
    { org_id: org.id, description: 'One', likelihood: 1, impact: 1, status: 'Open' },
    { org_id: org.id, description: 'Two', likelihood: 1, impact: 1 },
  ])
  assert.equal(status, 400)
  assert.equal(error.code, '23502')
})
await check('bulk insert with defaultToNull false uses column defaults', async () => {
  const { error } = await a.c.from('risks').insert([
    { org_id: org.id, description: 'Three', likelihood: 1, impact: 1, status: 'Closed' },
    { org_id: org.id, description: 'Four', likelihood: 1, impact: 1 },
  ], { defaultToNull: false })
  assert.equal(error, null)
})
await check('upsert merges on the primary key', async () => {
  const row = { org_id: org.id, control_id: 'GOV-01', status: 'no', note: 'first' }
  assert.equal((await a.c.from('answers').upsert(row)).error, null)
  assert.equal((await a.c.from('answers').upsert({ ...row, status: 'yes' })).error, null)
  const { data } = await a.c.from('answers').select('status').eq('org_id', org.id).eq('control_id', 'GOV-01').single()
  assert.equal(data.status, 'yes')
})
await check('single: none is 406 PGRST116, maybeSingle: none is null', async () => {
  const { error, status } = await a.c.from('orgs').select('id').eq('slug', 'nope').single()
  assert.equal(status, 406)
  assert.equal(error.code, 'PGRST116')
  const maybe = await a.c.from('orgs').select('id').eq('slug', 'nope').maybeSingle()
  assert.equal(maybe.error, null)
  assert.equal(maybe.data, null)
})
await check('count exact on head, and limit does not change it', async () => {
  const { count, data } = await a.c.from('risks').select('id', { count: 'exact', head: true }).eq('org_id', org.id)
  assert.equal(data, null)
  assert.ok(count >= 3)
  const limited = await a.c.from('risks').select('id', { count: 'exact' }).eq('org_id', org.id).limit(1)
  assert.equal(limited.data.length, 1)
  assert.equal(limited.count, count)
})
await check('filters is, not.is, gte and order behave', async () => {
  const ids = await a.c.from('risks').select('seq').eq('org_id', org.id).order('seq', { ascending: false })
  assert.ok(ids.data[0].seq > ids.data.at(-1).seq)
  const refs = await a.c.from('risks').select('source_ref').eq('org_id', org.id).not('source_ref', 'is', null)
  assert.deepEqual(refs.data, [{ source_ref: 'dup' }])
  const nulls = await a.c.from('risks').select('id').eq('org_id', org.id).is('source_ref', null)
  assert.ok(nulls.data.length >= 2)
  assert.equal((await a.c.from('risks').select('id').eq('org_id', org.id).gte('created_at', '2999-01-01')).data.length, 0)
})
await check('a filter the emulator does not implement fails loudly', async () => {
  const { status, error } = await a.c.from('risks').select('id').like('description', 'x%')
  assert.equal(status, 400)
  assert.equal(error.code, 'PGRST100')
})
await check('embed orgs(slug, name) on members', async () => {
  const { data } = await a.c.from('members').select('role, orgs(slug, name)').eq('user_id', a.user.id)
  assert.deepEqual(data, [{ role: 'owner', orgs: { slug, name: 'Renamed' } }])
})
await check('delete with count', async () => {
  const { data } = await a.c.from('risks').insert({ org_id: org.id, description: 'Gone', likelihood: 1, impact: 1 }).select('id').single()
  const { count, error } = await a.c.from('risks').delete({ count: 'exact' }).eq('id', data.id)
  assert.equal(error, null)
  assert.equal(count, 1)
})
await check('rpc: set returning function, plain and single', async () => {
  const many = await a.c.rpc('verify_ledger', { p_org: org.id })
  assert.equal(many.data[0].ok, true)
  const one = await a.c.rpc('verify_ledger', { p_org: org.id }).single()
  assert.equal(one.data.ok, true)
  assert.equal(typeof one.data.entries, 'number')
  assert.match((await b.c.rpc('verify_ledger', { p_org: org.id })).error.message, /not a member/)
})
await check('storage: analyst uploads, member downloads, stranger is refused', async () => {
  const path = `${org.id}/GOV-01/x.pdf`
  const file = new File(['%PDF-1.4 hello'], 'x.pdf', { type: 'application/pdf' })
  assert.equal((await a.c.storage.from('evidence').upload(path, file)).error, null)
  assert.ok((await a.c.storage.from('evidence').upload(path, file)).error, 'second upload to the same path conflicts')
  const { data, error } = await a.c.storage.from('evidence').download(path)
  assert.equal(error, null)
  assert.equal(await data.text(), '%PDF-1.4 hello')
  assert.ok((await b.c.storage.from('evidence').download(path)).error)
  assert.ok((await b.c.storage.from('evidence').createSignedUrl(path, 60)).error)
  assert.ok((await b.c.storage.from('evidence').upload(`${org.id}/GOV-01/y.pdf`, file)).error)
  assert.ok((await client(ANON).storage.from('evidence').download(path)).error)
})
await check('storage: the bucket mime rule applies', async () => {
  const bad = new File(['<svg/>'], 'x.svg', { type: 'image/svg+xml' })
  assert.ok((await a.c.storage.from('evidence').upload(`${org.id}/GOV-01/x.svg`, bad)).error)
})
await check('storage: signed url works once made, is bound to its path, and tampering fails', async () => {
  const path = `${org.id}/GOV-01/x.pdf`
  const { data, error } = await a.c.storage.from('evidence').createSignedUrl(path, 60)
  assert.equal(error, null)
  assert.equal((await fetch(data.signedUrl)).status, 200)
  assert.equal((await fetch(data.signedUrl.replace('x.pdf', 'other.pdf'))).status, 400)
  assert.equal((await fetch(`${data.signedUrl}x`)).status, 400)
})

console.log(`\n${passed} passed, ${failures.length} failed`)
process.exit(failures.length ? 1 : 0)
