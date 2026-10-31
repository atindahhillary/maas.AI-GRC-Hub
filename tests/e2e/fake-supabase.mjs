// Local stand-in for the Supabase stack, for machines that cannot run Docker. It speaks just enough GoTrue,
// PostgREST and Storage for this app, over a real Postgres (PGlite) running the real migrations, so row level
// security and column privileges are enforced by Postgres and not reimplemented here.
//
//   node tests/e2e/fake-supabase.mjs              serve on 127.0.0.1:54321, in memory, a restart gives an empty DB
//   node tests/e2e/fake-supabase.mjs --write-env  also point .env.local at it, leaving other lines alone
//
// Anything the app does not use fails loudly (PGRST100) instead of returning a plausible wrong answer.
import { createHmac, randomBytes, randomUUID, scryptSync, timingSafeEqual } from 'node:crypto'
import { readFileSync, readdirSync, writeFileSync } from 'node:fs'
import http from 'node:http'
import { PGlite } from '@electric-sql/pglite'
import { pgcrypto } from '@electric-sql/pglite/contrib/pgcrypto'

const HOST = '127.0.0.1'
const PORT = 54321
const BASE = `http://${HOST}:${PORT}`
const SECRET = 'fake-supabase-local-only-not-a-real-secret'
const TOKEN_TTL = 3600
const ROOT = new URL('../../', import.meta.url)

// JWT ---------------------------------------------------------------------------------------------

const b64 = (v) => Buffer.from(v).toString('base64url')
const hmac = (data) => createHmac('sha256', SECRET).update(data).digest()

function signJwt(claims) {
  const body = `${b64('{"alg":"HS256","typ":"JWT"}')}.${b64(JSON.stringify(claims))}`
  return `${body}.${hmac(body).toString('base64url')}`
}

// Returns claims, or a string saying why the token is no good.
function readJwt(token) {
  const [head, payload, sig] = token.split('.')
  if (!head || !payload || !sig) return 'malformed'
  const given = Buffer.from(sig, 'base64url')
  const want = hmac(`${head}.${payload}`)
  if (JSON.parse(Buffer.from(head, 'base64url')).alg !== 'HS256' || given.length !== want.length || !timingSafeEqual(given, want)) return 'bad signature'
  const claims = JSON.parse(Buffer.from(payload, 'base64url'))
  return claims.exp && claims.exp < Date.now() / 1000 ? 'expired' : claims
}

// Fixed timestamps, so the keys are the same every run and a build keeps working across restarts.
const ANON = signJwt({ iss: 'fake-supabase', role: 'anon', iat: 1700000000, exp: 2000000000 })
const SERVICE = signJwt({ iss: 'fake-supabase', role: 'service_role', iat: 1700000000, exp: 2000000000 })

// Database ----------------------------------------------------------------------------------------

class HttpError extends Error {
  constructor(status, body) {
    super(body.message ?? body.msg ?? 'error')
    this.status = status
    this.body = body
  }
}

const db = new PGlite({ extensions: { pgcrypto } })

// PGlite has one connection, so every use goes through this queue and no two transactions interleave.
let tail = Promise.resolve()
const enqueue = (fn) => {
  const run = tail.then(fn)
  tail = run.catch(() => {})
  return run
}

const asOwner = (sql, params) => enqueue(() => db.query(sql, params))

// One request, one transaction, one role, exactly how PostgREST does it, so a throw rolls everything back.
const asRole = (claims, fn) => enqueue(() => db.transaction(async (tx) => {
  await tx.query(`select set_config('request.jwt.claims', $1, true)`, [JSON.stringify(claims)])
  await tx.exec(`set local role ${claims.role}`) // claims.role is checked against ROLES in identify()
  return fn(tx)
}))

const stub = readFileSync(new URL('tests/rls.test.ts', ROOT), 'utf8').match(/const SUPABASE_STUB = `([\s\S]*?)`/)?.[1]
if (!stub) throw new Error('SUPABASE_STUB not found in tests/rls.test.ts')
await db.exec(stub)
const migrations = new URL('supabase/migrations/', ROOT)
for (const file of readdirSync(migrations).filter((f) => f.endsWith('.sql')).sort()) await db.exec(readFileSync(new URL(file, migrations), 'utf8'))
await db.exec('create unique index bucketid_objname on storage.objects (bucket_id, name)') // real Supabase has this, the stub does not need it

const TABLES = new Set()
const PK = {}
const FK = {}
const FUNCS = {}
for (const { relname } of (await db.query(`select c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'public' and c.relkind = 'r'`)).rows) TABLES.add(relname)
for (const r of (await db.query(`
  select con.contype::text as type, t.relname as tbl, f.relname as ref,
    (select array_agg(a.attname::text order by k.ord) from unnest(con.conkey) with ordinality k(n, ord) join pg_attribute a on a.attrelid = con.conrelid and a.attnum = k.n) as cols,
    (select array_agg(a.attname::text order by k.ord) from unnest(con.confkey) with ordinality k(n, ord) join pg_attribute a on a.attrelid = con.confrelid and a.attnum = k.n) as refcols
  from pg_constraint con join pg_class t on t.oid = con.conrelid join pg_namespace n on n.oid = t.relnamespace left join pg_class f on f.oid = con.confrelid
  where n.nspname = 'public' and con.contype in ('p', 'f')`)).rows) {
  if (r.type === 'p') PK[r.tbl] = r.cols
  // shortcut: keeps the last foreign key when two point at one table, PostgREST would answer PGRST201. Fine while the app only embeds members -> orgs.
  else FK[`${r.tbl}->${r.ref}`] = { col: r.cols[0], ref: r.refcols[0] }
}
for (const r of (await db.query(`select p.proname, p.proretset from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public'`)).rows) FUNCS[r.proname] = { set: r.proretset }

// HTTP helpers ------------------------------------------------------------------------------------

const ROLES = ['anon', 'authenticated', 'service_role']

const readBody = async (req) => {
  const chunks = []
  for await (const c of req) chunks.push(c)
  return Buffer.concat(chunks)
}

const parseJson = (buf) => {
  try {
    return JSON.parse(buf.toString('utf8') || '{}')
  } catch {
    throw new HttpError(400, { code: 'PGRST102', message: 'Empty or invalid json', details: null, hint: null })
  }
}

function identify(req) {
  const token = (req.headers.authorization ?? '').replace(/^Bearer\s+/i, '')
  const claims = token ? readJwt(token) : 'missing'
  if (claims === 'expired') throw new HttpError(401, { code: 'PGRST303', message: 'JWT expired', details: null, hint: null })
  if (typeof claims === 'string' || !ROLES.includes(claims.role)) throw new HttpError(401, { code: 'PGRST301', message: `Invalid JWT: ${typeof claims === 'string' ? claims : 'unknown role'}`, details: null, hint: null })
  return claims
}

// Same status mapping as PostgREST's table: unknown function or table 404, permissions 401/403, conflicts 409.
function pgStatus(e, role) {
  if (e.code === '42501') return role === 'anon' ? 401 : 403
  if (e.code === '23505' || e.code === '23503') return 409
  if (e.code === '42883' || e.code === '42P01') return 404
  return /^(22|23|42|P0)/.test(e.code ?? '') ? 400 : 500
}

const pgError = (e, role) => new HttpError(pgStatus(e, role), { code: e.code, message: e.message, details: e.detail ?? null, hint: e.hint ?? null })

// PostgREST ---------------------------------------------------------------------------------------

const unsupported = (message) => new HttpError(400, { code: 'PGRST100', message, details: 'not implemented by fake-supabase', hint: null })

const ident = (s) => {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(s)) throw unsupported(`invalid identifier: ${s}`)
  return `"${s}"`
}
const lit = (v) => `'${String(v).replaceAll("'", "''")}'` // an unknown-typed literal, so Postgres casts it to the column type as PostgREST's params do

const RESERVED = new Set(['select', 'order', 'limit', 'offset', 'columns', 'on_conflict'])
const OPS = { eq: '=', gte: '>=' }

function whereClause(table, params) {
  const clauses = []
  for (const [col, raw] of params) {
    if (RESERVED.has(col)) continue
    const m = raw.match(/^(not\.)?(eq|gte|is)\.(.*)$/s)
    if (!m) throw unsupported(`unsupported filter ${col}=${raw}`)
    const [, not, op, value] = m
    const target = `${ident(table)}.${ident(col)}`
    if (op === 'is' && !['null', 'true', 'false'].includes(value)) throw unsupported(`unsupported is value: ${value}`)
    const sql = op === 'is' ? `${target} is ${value}` : `${target} ${OPS[op]} ${lit(value)}`
    clauses.push(not ? `not (${sql})` : sql)
  }
  return clauses.length ? ` where ${clauses.join(' and ')}` : ''
}

function selectList(table, select) {
  const items = (select || '*').match(/[^,()]+(?:\([^()]*\))?/g) ?? []
  return items.map((item) => {
    if (item === '*') return `${ident(table)}.*`
    const embed = item.match(/^(\w+)\((.*)\)$/)
    if (!embed) return `${ident(table)}.${ident(item)}`
    const [, child, cols] = embed
    const fk = FK[`${table}->${child}`]
    // shortcut: to-one embeds only, the app has no to-many embed. Add one when it does.
    if (!fk || !TABLES.has(child)) throw new HttpError(400, { code: 'PGRST200', message: `Could not find a relationship between '${table}' and '${child}'`, details: null, hint: null })
    return `(select row_to_json(pgrst_e) from (select ${selectList(child, cols)} from public.${ident(child)} where ${ident(child)}.${ident(fk.ref)} = ${ident(table)}.${ident(fk.col)}) pgrst_e) as ${ident(child)}`
  }).join(', ')
}

function orderClause(order) {
  if (!order) return ''
  return ` order by ${order.split(',').map((term) => {
    const [col, dir = 'asc', nulls] = term.split('.')
    if (!['asc', 'desc'].includes(dir) || (nulls && !['nullsfirst', 'nullslast'].includes(nulls))) throw unsupported(`unsupported order: ${term}`)
    return `${ident(col)} ${dir}${nulls ? ` nulls ${nulls.slice(5)}` : ''}`
  }).join(', ')}`
}

const limitClause = (url) => ['limit', 'offset'].map((k) => {
  const v = url.searchParams.get(k)
  if (v !== null && !/^\d+$/.test(v)) throw unsupported(`bad ${k}`)
  return v === null ? '' : ` ${k} ${v}`
}).join('')

const agg = (source) => `select coalesce(json_agg(pgrst_t), '[]')::text as body, count(*)::int as n from ${source}`

async function mutation(tx, sql, params, url, table, wantBody) {
  const returning = wantBody ? selectList(table, url.searchParams.get('select')) : '1 as pgrst_one'
  const { rows } = await tx.query(`with pgrst_t as (${sql} returning ${returning}) ${agg('pgrst_t')}`, params)
  return rows[0]
}

function insertStatement(t, cols, conflict) {
  const list = cols.map(ident).join(', ')
  return `insert into public.${ident(t)} (${list}) select ${list} from jsonb_populate_recordset(null::public.${ident(t)}, $1::text::jsonb)${conflict}`
}

async function insertRows(tx, t, url, prefer, body, wantBody) {
  const rows = Array.isArray(body) ? body : [body]
  const given = url.searchParams.get('columns')
  const cols = given ? given.split(',').map((c) => c.replace(/^"|"$/g, '')) : Object.keys(rows[0] ?? {})
  if (!given && rows.some((r) => Object.keys(r).length !== cols.length || cols.some((c) => !(c in r)))) throw new HttpError(400, { code: 'PGRST102', message: 'All object keys must match', details: null, hint: null })
  let conflict = ''
  if (prefer.has('resolution=merge-duplicates')) {
    const target = url.searchParams.get('on_conflict')?.split(',') ?? PK[t]
    conflict = ` on conflict (${target.map(ident).join(', ')}) do update set ${cols.map((c) => `${ident(c)} = excluded.${ident(c)}`).join(', ')}`
  }
  // Without missing=default a key absent from one row is NULL, not the column default. That is PostgREST's real behaviour.
  const batches = prefer.has('missing=default') ? rows.map((r) => [Object.keys(r), [r]]) : [[cols, rows]]
  let body2 = []
  for (const [names, batch] of batches) {
    const { body: json } = await mutation(tx, insertStatement(t, names, conflict), [JSON.stringify(batch)], url, t, wantBody)
    body2 = body2.concat(JSON.parse(json))
  }
  return { body: JSON.stringify(body2), n: body2.length }
}

function updateRows(tx, t, url, body, wantBody) {
  const cols = Object.keys(body)
  if (!cols.length) throw unsupported('empty update')
  const set = cols.map((c) => `${ident(c)} = pgrst_body.${ident(c)}`).join(', ')
  const sql = `update public.${ident(t)} set ${set} from (select * from jsonb_populate_record(null::public.${ident(t)}, $1::text::jsonb)) pgrst_body${whereClause(t, url.searchParams)}`
  return mutation(tx, sql, [JSON.stringify(body)], url, t, wantBody)
}

const deleteRows = (tx, t, url, wantBody) => mutation(tx, `delete from public.${ident(t)}${whereClause(t, url.searchParams)}`, [], url, t, wantBody)

async function selectRows(tx, t, url, wantCount) {
  const from = `from public.${ident(t)}${whereClause(t, url.searchParams)}`
  const page = `(select ${selectList(t, url.searchParams.get('select'))} ${from}${orderClause(url.searchParams.get('order'))}${limitClause(url)}) pgrst_t`
  const { rows } = await tx.query(agg(page))
  const total = wantCount ? (await tx.query(`select count(*)::int as n ${from}`)).rows[0].n : null
  return { ...rows[0], total }
}

async function callFunction(tx, name, args) {
  const fn = FUNCS[name]
  if (!fn) throw new HttpError(404, { code: 'PGRST202', message: `Could not find the function public.${name} in the schema cache`, details: null, hint: null })
  const list = Object.entries(args).map(([k, v]) => `${ident(k)} := ${v === null ? 'null' : lit(typeof v === 'string' ? v : JSON.stringify(v))}`).join(', ')
  const call = `public.${ident(name)}(${list})`
  const { rows } = await tx.query(fn.set ? agg(`${call} pgrst_t`) : `select to_json(${call})::text as body, 1 as n`)
  return rows[0]
}

async function rest(req, res, url) {
  const claims = identify(req)
  const raw = await readBody(req)
  const prefer = new Set((req.headers.prefer ?? '').split(/[,\s]+/).filter(Boolean))
  const single = (req.headers.accept ?? '').includes('application/vnd.pgrst.object+json')
  const wantCount = prefer.has('count=exact')
  const wantBody = prefer.has('return=representation')
  const route = url.pathname.slice('/rest/v1/'.length)
  const rpc = route.startsWith('rpc/') ? route.slice(4) : null
  if (!rpc && !TABLES.has(route)) throw new HttpError(404, { code: 'PGRST205', message: `Could not find the table 'public.${route}' in the schema cache`, details: null, hint: null })
  const method = req.method === 'HEAD' ? 'GET' : req.method
  if (rpc && !['POST', 'GET'].includes(method)) throw unsupported(`${method} on rpc`)
  if (!rpc && !['GET', 'POST', 'PATCH', 'DELETE'].includes(method)) throw unsupported(`method ${method}`)

  let result
  try {
    result = await asRole(claims, async (tx) => {
      const out = rpc ? await callFunction(tx, rpc, parseJson(raw))
        : method === 'GET' ? await selectRows(tx, route, url, wantCount)
        : method === 'POST' ? await insertRows(tx, route, url, prefer, parseJson(raw), wantBody)
        : method === 'PATCH' ? await updateRows(tx, route, url, parseJson(raw), wantBody)
        : await deleteRows(tx, route, url, wantBody)
      // Thrown inside the transaction, so a singular write that matched the wrong number of rows rolls back as well.
      if (single && (method === 'GET' || rpc || wantBody) && out.n !== 1) throw new HttpError(406, { code: 'PGRST116', message: 'Cannot coerce the result to a single JSON object', details: `The result contains ${out.n} rows`, hint: null })
      return out
    })
  } catch (e) {
    throw e instanceof HttpError ? e : pgError(e, claims.role)
  }

  const reads = method === 'GET' || rpc
  const payload = !reads && !wantBody ? '' : single && !(rpc && !FUNCS[rpc].set) ? JSON.stringify(JSON.parse(result.body)[0]) : result.body
  const range = `${result.n ? `0-${result.n - 1}` : '*'}/${wantCount ? (result.total ?? result.n) : '*'}`
  const status = method === 'POST' && !rpc ? 201 : payload || reads ? 200 : 204
  res.writeHead(status, { 'content-type': `${single ? 'application/vnd.pgrst.object+json' : 'application/json'}; charset=utf-8`, 'content-range': range })
  res.end(req.method === 'HEAD' ? undefined : payload)
}

// GoTrue ------------------------------------------------------------------------------------------

const users = new Map() // email -> { id, email, salt, hash, created_at }
const sessions = new Map() // session_id -> user id
const refreshTokens = new Map() // token -> { sessionId, user }

const hashPassword = (password, salt) => scryptSync(password, salt, 32)
const authError = (status, error_code, msg) => new HttpError(status, { code: status, error_code, msg })

async function publicUser(user) {
  const { rows } = await asOwner(`select id, status::text as status from auth.mfa_factors where user_id = $1`, [user.id])
  const factors = rows.map((f) => ({ id: f.id, status: f.status, factor_type: 'totp', friendly_name: null, created_at: user.created_at, updated_at: user.created_at }))
  return {
    id: user.id, aud: 'authenticated', role: 'authenticated', email: user.email,
    email_confirmed_at: user.created_at, confirmed_at: user.created_at, last_sign_in_at: new Date().toISOString(),
    app_metadata: { provider: 'email', providers: ['email'] }, user_metadata: {}, identities: [],
    created_at: user.created_at, updated_at: user.created_at, ...(factors.length ? { factors } : {}),
  }
}

async function issueSession(user, sessionId = randomUUID()) {
  const now = Math.floor(Date.now() / 1000)
  const refresh_token = randomBytes(16).toString('hex')
  sessions.set(sessionId, user.id)
  refreshTokens.set(refresh_token, { sessionId, user })
  const access_token = signJwt({
    iss: `${BASE}/auth/v1`, aud: 'authenticated', sub: user.id, email: user.email, role: 'authenticated', aal: 'aal1',
    amr: [{ method: 'password', timestamp: now }], session_id: sessionId, iat: now, exp: now + TOKEN_TTL,
  })
  return { access_token, token_type: 'bearer', expires_in: TOKEN_TTL, expires_at: now + TOKEN_TTL, refresh_token, user: await publicUser(user) }
}

function currentUser(req) {
  const claims = readJwt((req.headers.authorization ?? '').replace(/^Bearer\s+/i, ''))
  if (typeof claims === 'string' || !claims.sub) throw authError(401, 'bad_jwt', `invalid JWT: ${typeof claims === 'string' ? claims : 'missing sub claim'}`)
  if (!sessions.has(claims.session_id)) throw authError(403, 'session_not_found', 'Session from session_id claim in JWT does not exist')
  const user = [...users.values()].find((u) => u.id === claims.sub)
  if (!user) throw authError(403, 'user_not_found', 'User from sub claim in JWT does not exist')
  return { user, claims }
}

async function signup(body) {
  const email = String(body.email ?? '').trim().toLowerCase()
  const password = String(body.password ?? '')
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw authError(400, 'validation_failed', 'Unable to validate email address: invalid format')
  if (password.length < 6) throw new HttpError(422, { code: 422, error_code: 'weak_password', msg: 'Password should be at least 6 characters.', weak_password: { reasons: ['length'] } })
  if (users.has(email)) throw authError(422, 'user_already_exists', 'User already registered')
  const salt = randomBytes(16)
  const user = { id: randomUUID(), email, salt, hash: hashPassword(password, salt), created_at: new Date().toISOString() }
  await asOwner(`insert into auth.users (id, email) values ($1, $2)`, [user.id, email])
  users.set(email, user)
  return issueSession(user)
}

async function token(url, body) {
  const grant = url.searchParams.get('grant_type')
  if (grant === 'password') {
    const user = users.get(String(body.email ?? '').trim().toLowerCase())
    if (!user || !timingSafeEqual(hashPassword(String(body.password ?? ''), user.salt), user.hash)) throw authError(400, 'invalid_credentials', 'Invalid login credentials')
    return issueSession(user)
  }
  if (grant === 'refresh_token') {
    const entry = refreshTokens.get(body.refresh_token)
    if (!entry || !sessions.has(entry.sessionId)) throw authError(400, 'refresh_token_not_found', 'Invalid Refresh Token: Refresh Token Not Found')
    refreshTokens.delete(body.refresh_token)
    return issueSession(entry.user, entry.sessionId)
  }
  throw authError(400, 'unsupported_grant_type', `grant_type ${grant} is not implemented by fake-supabase`)
}

function logout(req, url) {
  const { user, claims } = currentUser(req)
  const scope = url.searchParams.get('scope') ?? 'global'
  for (const [id, owner] of sessions) {
    const mine = scope === 'local' ? id === claims.session_id : owner === user.id && (scope === 'global' || id !== claims.session_id)
    if (!mine) continue
    sessions.delete(id)
    for (const [t, e] of refreshTokens) if (e.sessionId === id) refreshTokens.delete(t)
  }
}

async function gotrue(req, res, url) {
  const route = `${req.method} ${url.pathname.slice('/auth/v1'.length)}`
  const body = req.method === 'POST' ? parseJson(await readBody(req)) : {}
  const json = (data) => {
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify(data))
  }
  if (route === 'POST /signup') return json(await signup(body))
  if (route === 'POST /token') return json(await token(url, body))
  if (route === 'GET /user') return json(await publicUser(currentUser(req).user))
  if (route === 'POST /logout') {
    logout(req, url)
    res.writeHead(204)
    return res.end()
  }
  throw authError(404, 'not_found', `${route} is not implemented by fake-supabase`)
}

// Storage -----------------------------------------------------------------------------------------

const files = new Map() // 'bucket/name' -> { bytes, type }
const storageError = (status, code, error, message) => new HttpError(status, { statusCode: String(code), error, message })

const denied = (e) => {
  if (e instanceof HttpError) return e
  if (e.code === '23505') return storageError(409, 409, 'Duplicate', 'The resource already exists')
  if (e.code === '42501') return storageError(403, 403, 'Unauthorized', e.message)
  if (e.code === '22P02') return storageError(400, 400, 'InvalidKey', e.message) // the folder is not an org uuid, the policy's cast rejects it
  return e
}

async function readUpload(req, raw) {
  const type = req.headers['content-type'] ?? 'application/octet-stream'
  if (!type.startsWith('multipart/form-data')) return { bytes: raw, type }
  const form = await new Response(raw, { headers: { 'content-type': type } }).formData()
  const file = [...form.values()].find((v) => v instanceof Blob)
  if (!file) throw storageError(400, 400, 'InvalidRequest', 'no file in the form')
  return { bytes: Buffer.from(await file.arrayBuffer()), type: file.type }
}

// The row in storage.objects is what the policies guard, and it is the only way to the bytes.
const readable = (tx, bucket, name) => tx.query('select 1 from storage.objects where bucket_id = $1 and name = $2', [bucket, name]).then((r) => r.rows.length > 0)

async function upload(req, res, claims, bucket, name) {
  if (req.headers['x-upsert'] === 'true') throw storageError(400, 400, 'NotImplemented', 'x-upsert is not implemented by fake-supabase')
  const file = await readUpload(req, await readBody(req))
  await asRole(claims, async (tx) => {
    const { rows } = await tx.query('select file_size_limit, allowed_mime_types from storage.buckets where id = $1', [bucket])
    if (!rows[0]) throw storageError(400, 404, 'Bucket not found', 'Bucket not found')
    if (rows[0].file_size_limit && file.bytes.length > Number(rows[0].file_size_limit)) throw storageError(413, 413, 'Payload too large', 'The object exceeded the maximum allowed size')
    if (rows[0].allowed_mime_types?.length && !rows[0].allowed_mime_types.includes(file.type)) throw storageError(415, 415, 'invalid_mime_type', `mime type ${file.type} is not supported`)
    await tx.query('insert into storage.objects (bucket_id, name) values ($1, $2)', [bucket, name])
  }).catch((e) => { throw denied(e) })
  files.set(`${bucket}/${name}`, file)
  res.writeHead(200, { 'content-type': 'application/json' })
  res.end(JSON.stringify({ Id: randomUUID(), Key: `${bucket}/${name}` }))
}

const sendFile = (res, file) => {
  res.writeHead(200, { 'content-type': file.type, 'content-length': file.bytes.length })
  res.end(file.bytes)
}

const notFound = () => storageError(400, 404, 'not_found', 'Object not found')

async function download(res, claims, bucket, name) {
  const allowed = await asRole(claims, (tx) => readable(tx, bucket, name)).catch((e) => { throw denied(e) })
  const file = files.get(`${bucket}/${name}`)
  if (!allowed || !file) throw notFound()
  sendFile(res, file)
}

async function signUrl(req, res, claims, bucket, name) {
  const { expiresIn } = parseJson(await readBody(req))
  const allowed = await asRole(claims, (tx) => readable(tx, bucket, name)).catch((e) => { throw denied(e) })
  if (!allowed) throw notFound()
  const now = Math.floor(Date.now() / 1000)
  // No role claim, so a signed-url token is useless as an API token.
  const token = signJwt({ url: `${bucket}/${name}`, iat: now, exp: now + Number(expiresIn) })
  res.writeHead(200, { 'content-type': 'application/json' })
  res.end(JSON.stringify({ signedURL: `/object/sign/${bucket}/${name}?token=${token}` }))
}

function signedDownload(res, url, bucket, name) {
  const claims = readJwt(url.searchParams.get('token') ?? '')
  if (typeof claims === 'string' || claims.url !== `${bucket}/${name}`) throw storageError(400, 400, 'InvalidSignature', 'The signature is invalid or has expired')
  const file = files.get(claims.url)
  if (!file) throw notFound()
  sendFile(res, file)
}

async function storage(req, res, url) {
  const m = url.pathname.match(/^\/storage\/v1\/object\/(sign\/)?([^/]+)\/(.+)$/)
  if (!m) throw storageError(404, 404, 'not_found', `${url.pathname} is not implemented by fake-supabase`)
  const [, sign, bucket, path] = m
  const name = decodeURIComponent(path)
  if (sign && req.method === 'GET') return signedDownload(res, url, bucket, name)
  const claims = identify(req)
  if (sign && req.method === 'POST') return signUrl(req, res, claims, bucket, name)
  if (req.method === 'POST') return upload(req, res, claims, bucket, name)
  if (req.method === 'GET') return download(res, claims, bucket, name)
  throw storageError(405, 405, 'MethodNotAllowed', req.method)
}

// Server ------------------------------------------------------------------------------------------

async function route(req, res, url) {
  const path = url.pathname
  if (path === '/health') return res.end('ok')
  const signedGet = req.method === 'GET' && path.startsWith('/storage/v1/object/sign/') // public route, the token in the URL is the credential
  if (!signedGet && ![ANON, SERVICE].includes(req.headers.apikey)) throw new HttpError(401, { message: 'Invalid API key', hint: 'apikey header must be the anon or service key' })
  if (path.startsWith('/auth/v1/')) return gotrue(req, res, url)
  if (path.startsWith('/rest/v1/')) return rest(req, res, url)
  if (path.startsWith('/storage/v1/')) return storage(req, res, url)
  throw new HttpError(404, { message: `no route for ${path}` })
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, BASE)
  res.setHeader('access-control-allow-origin', '*')
  res.setHeader('access-control-expose-headers', 'content-range')
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'access-control-allow-methods': 'GET,HEAD,POST,PATCH,PUT,DELETE,OPTIONS',
      'access-control-allow-headers': req.headers['access-control-request-headers'] ?? '*', // a bare * would not cover Authorization
    })
    return res.end()
  }
  try {
    await route(req, res, url)
  } catch (e) {
    const known = e instanceof HttpError
    const status = known ? e.status : 500
    const body = known ? e.body : { code: 'FAKE500', message: String(e?.stack ?? e) }
    console.log(`[fake-supabase] ${req.method} ${url.pathname}${url.search} -> ${status} ${JSON.stringify(body)}`)
    if (!res.headersSent) res.writeHead(status, { 'content-type': 'application/json' })
    res.end(JSON.stringify(body))
  }
})

function writeEnv() {
  const file = new URL('.env.local', ROOT)
  let text = readFileSync(file, 'utf8')
  const wanted = { NEXT_PUBLIC_SUPABASE_URL: BASE, NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY: ANON, SUPABASE_SERVICE_ROLE_KEY: SERVICE }
  for (const [key, value] of Object.entries(wanted)) {
    const line = new RegExp(`^${key}=.*$`, 'm')
    text = line.test(text) ? text.replace(line, `${key}=${value}`) : `${text.trimEnd()}\n${key}=${value}\n`
  }
  writeFileSync(file, text)
}

if (process.argv.includes('--write-env')) writeEnv()

const stop = () => server.close(() => db.close().finally(() => process.exit(0)))
process.on('SIGTERM', stop)
process.on('SIGINT', stop)

server.listen(PORT, HOST, () => {
  console.log(`fake-supabase on ${BASE}
NEXT_PUBLIC_SUPABASE_URL=${BASE}
NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=${ANON}
SUPABASE_SERVICE_ROLE_KEY=${SERVICE}`)
})
