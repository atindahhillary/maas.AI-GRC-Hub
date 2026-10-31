// End to end journey: the real production build of the app, in real Edge, against tests/e2e/fake-supabase.mjs.
//   node tests/e2e/journey.cjs             build, start everything, run, always stop everything
//   node tests/e2e/journey.cjs --no-build  reuse .next, only safe if .env.local and src/ have not changed
// Exit code 1 if any step failed. SHOTS_DIR overrides where screenshots go.
const { execFileSync, spawn, spawnSync } = require('node:child_process')
const { createHash } = require('node:crypto')
const fs = require('node:fs')
const path = require('node:path')
const { chromium } = require(path.join(process.env.APPDATA, 'npm/node_modules/@playwright/cli/node_modules/playwright-core'))

const ROOT = path.resolve(__dirname, '../..')
const SCRATCH = 'C:\\Users\\ATINDLET\\AppData\\Local\\Temp\\claude\\C--Users-ATINDLET--claude-spares-spare-7btdH3\\c0aa3a31-e2f2-4e16-9fed-79ee97f43eb5\\scratchpad'
const SHOTS = process.env.SHOTS_DIR ?? path.join(SCRATCH, 'shots')
const APP = 'http://127.0.0.1:3100'
const SB = 'http://127.0.0.1:54321'
const NEXT_BIN = path.join(ROOT, 'node_modules/next/dist/bin/next')
const WAIT = 20000

const ORG_NAME = 'Amani Relief Trust'
const PASSWORD = 'correct-horse-battery-staple'
const tag = Date.now().toString(36)
const A = { email: `owner.${tag}@example.test` }
const B = { email: `viewer.${tag}@example.test` }
const PDF = Buffer.from('%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n')
const ANSWERS = ['Yes', 'Yes', 'Partly', 'Yes', 'No', 'Yes', 'Partly', 'Yes', 'Yes', 'No', 'Yes', 'N/A']

// Processes ---------------------------------------------------------------------------------------

const children = []
function start(label, args) {
  const log = fs.createWriteStream(path.join(SCRATCH, `${label}.log`))
  const child = spawn(process.execPath, args, { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] })
  child.stdout.pipe(log)
  child.stderr.pipe(log)
  children.push(child)
  return child
}

function stopAll() {
  for (const c of children.splice(0)) {
    try {
      execFileSync('taskkill', ['/pid', String(c.pid), '/T', '/F'], { stdio: 'ignore' }) // the whole tree, next start has workers
    } catch {} // already gone
  }
}
process.on('exit', stopAll)
process.on('SIGINT', () => process.exit(130))
process.on('SIGTERM', () => process.exit(143))

async function waitFor(url, label) {
  for (let i = 0; i < 120; i++) {
    if (await fetch(url).then(() => true, () => false)) return
    await new Promise((r) => setTimeout(r, 500))
  }
  throw new Error(`${label} did not come up at ${url}`)
}

const portFree = async (url) => fetch(url).then(() => false, () => true)

// Harness -----------------------------------------------------------------------------------------

const results = []
const consoleErrors = []
let allowConsole = null

async function step(name, fn, { critical } = {}) {
  try {
    const note = await fn()
    results.push({ name, ok: true, note })
    console.log(`PASS ${name}${note ? `  [${note}]` : ''}`)
  } catch (e) {
    const error = String(e.message).split('\n')[0].slice(0, 400)
    results.push({ name, ok: false, error })
    console.log(`FAIL ${name}: ${error}`)
    if (critical) throw new Error(`stopping, nothing after "${name}" can run`)
  }
}

function assert(ok, message) {
  if (!ok) throw new Error(message)
}

function watch(page, who) {
  const record = (kind, text, url) => {
    if (allowConsole?.test(text)) return
    consoleErrors.push({ who, kind, text: text.slice(0, 300), url })
    console.log(`  ${kind} (${who}) ${url}: ${text.slice(0, 200)}`)
  }
  page.on('console', (m) => m.type() === 'error' && record('console', m.text(), page.url()))
  page.on('pageerror', (e) => record('pageerror', e.message, page.url()))
  page.on('response', (r) => r.status() >= 500 && record('http5xx', `${r.status()} ${r.request().method()}`, r.url()))
  page.on('dialog', (d) => d.accept())
  page.setDefaultTimeout(WAIT)
}

async function newUserPage(browser, who) {
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, acceptDownloads: true })
  context.on('page', (p) => watch(p, who))
  return context.newPage()
}

const goto = (page, url) => page.goto(url.startsWith('http') ? url : `${APP}${url}`, { waitUntil: 'networkidle' })
const seen = (page, text, timeout = WAIT) => page.getByText(text).first().waitFor({ timeout })
const absent = async (page, text) => assert(await page.getByText(text, { exact: true }).count() === 0, `"${text}" should not be shown`)

async function shot(page, name) {
  await page.waitForLoadState('networkidle')
  const sizes = [[1440, 900, 'desktop'], [390, 844, 'mobile']]
  const overflow = []
  for (const [width, height, label] of sizes) {
    await page.setViewportSize({ width, height })
    await page.waitForTimeout(150)
    await page.screenshot({ path: path.join(SHOTS, `${name}-${label}.png`), fullPage: true })
    const over = await page.evaluate(() => {
      const by = document.documentElement.scrollWidth - window.innerWidth
      const out = [...document.querySelectorAll('body *')].find((e) => getComputedStyle(e).position === 'absolute' && e.getBoundingClientRect().right > window.innerWidth)
      return by > 0 ? `by ${by}px, absolute element past the edge: <${out?.tagName.toLowerCase()} class="${out?.className}">${out?.textContent}` : ''
    })
    if (over) overflow.push(`${name} ${label} ${over}`)
  }
  await page.setViewportSize({ width: 1440, height: 900 })
  return overflow
}

// Service role and user REST calls, which is how a hostile client would reach the API --------------

let ANON
let SERVICE

const rest = async (route, { token = SERVICE, method = 'GET', body, prefer } = {}) => {
  const res = await fetch(`${SB}/rest/v1/${route}`, {
    method,
    headers: { apikey: token === SERVICE ? SERVICE : ANON, authorization: `Bearer ${token}`, 'content-type': 'application/json', ...(prefer ? { prefer } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const text = await res.text()
  return { status: res.status, json: text ? JSON.parse(text) : null }
}

async function tokenFor(user) {
  const res = await fetch(`${SB}/auth/v1/token?grant_type=password`, {
    method: 'POST', headers: { apikey: ANON, 'content-type': 'application/json' }, body: JSON.stringify({ email: user.email, password: PASSWORD }),
  })
  const json = await res.json()
  assert(json.access_token, `sign in failed for ${user.email}: ${JSON.stringify(json)}`)
  return json.access_token
}

const storageCall = (route, token, init = {}) => fetch(`${SB}/storage/v1/object/${route}`, { ...init, headers: { apikey: ANON, authorization: `Bearer ${token}`, ...init.headers } })

// App actions -------------------------------------------------------------------------------------

async function signUp(page, user) {
  await goto(page, '/signup')
  await page.fill('input[name=email]', user.email)
  await page.fill('input[name=password]', PASSWORD)
  await page.getByText('Create account', { exact: true }).click()
  await page.waitForURL(/\/onboarding/)
}

const postureLine = async (page) => {
  const text = await page.getByText(/^You claim/).first().innerText()
  const m = text.match(/You claim (\d+)% and can prove (\d+)%/)
  assert(m, `no posture line in: ${text}`)
  return { claimed: Number(m[1]), proven: Number(m[2]) }
}

const progress = async (page) => {
  const m = (await page.getByText(/^\d+ of \d+ answered$/).first().innerText()).match(/(\d+) of (\d+)/)
  return { done: Number(m[1]), total: Number(m[2]) }
}

// Domain buttons show "Governance 2/6". Matched on that text alone, not on any role.
const domainButtons = (page) => page.locator('button').filter({ hasText: /\d+\/\d+/ })
const answerRows = (page) => page.locator('li').filter({ has: page.getByText('Partly', { exact: true }) })

// Answers through the real buttons, one at a time, waiting for the server to confirm each.
// "Unanswered only" is a snapshot taken when ticked, so answered rows stay listed and the walk goes by index.
async function answerControls(page, slug, howMany, cursor = { i: 0 }) {
  await goto(page, `/o/${slug}/assess`)
  await page.getByText('Unanswered only').click()
  let left = howMany
  const domains = await domainButtons(page).count()
  for (let d = 0; d < domains && left > 0; d++) {
    await domainButtons(page).nth(d).click()
    const rows = await answerRows(page).count()
    for (let r = 0; r < rows && left > 0; r++) {
      const { done, total } = await progress(page)
      await answerRows(page).nth(r).getByText(ANSWERS[cursor.i++ % ANSWERS.length], { exact: true }).click()
      await seen(page, `${done + 1} of ${total} answered`)
      left--
    }
  }
  assert(left === 0, `${left} controls could not be answered`)
}

// Journey -----------------------------------------------------------------------------------------

async function journey(browser) {
  const a = await newUserPage(browser, 'A')
  const stranger = await newUserPage(browser, 'signed-out')
  const b = await newUserPage(browser, 'B')
  const cursor = { i: 0 }
  let slug
  let orgId
  let policyId
  let bundle
  let evidencePath
  let overflow = []

  await step('A signs up and lands on onboarding', () => signUp(a, A), { critical: true })

  await step('A completes onboarding', async () => {
    const pick = (name, value) => a.locator(`label:has(input[name="${name}"][value="${value}"])`).click()
    await a.fill('input[name=name]', ORG_NAME)
    await pick('sector', 'ngo')
    await pick('size', '11-50')
    await pick('countries', 'KE')
    await pick('countries', 'UG')
    await pick('dataTypes', 'personal')
    await pick('dataTypes', 'children')
    await pick('platforms', 'm365')
    await pick('usesAI', 'on')
    await pick('budget', 'moderate')
    await a.getByText('Create workspace', { exact: true }).click()
    await a.waitForURL(/\/o\/[a-z0-9-]+$/)
    slug = new URL(a.url()).pathname.split('/')[2]
    orgId = (await rest(`orgs?select=id&slug=eq.${slug}`)).json[0].id
    return `slug ${slug}`
  }, { critical: true })

  await step('dashboard renders with empty states', async () => {
    await goto(a, `/o/${slug}`)
    for (const t of [`Welcome to ${ORG_NAME}`, 'Start the assessment', 'Add risks to see where they sit.', 'No open findings yet.', 'Run your first', 'No live test yet']) await seen(a, t)
    const p = await postureLine(a)
    assert(p.claimed === 0 && p.proven === 0, `expected 0 and 0, got ${JSON.stringify(p)}`)
    overflow.push(...await shot(a, 'dashboard-empty'))
  })

  await step('A answers 15 controls', async () => {
    await answerControls(a, slug, 15, cursor)
    await goto(a, `/o/${slug}/assess`)
    const { done, total } = await progress(a)
    assert(done === 15, `${done} answered after reload`)
    return `${done} of ${total}`
  })

  let before
  await step('claimed is above proven before any evidence', async () => {
    await goto(a, `/o/${slug}`)
    before = await postureLine(a)
    assert(before.claimed > 0 && before.proven === 0, JSON.stringify(before))
    return JSON.stringify(before)
  })

  await step('A attaches a PDF and the row moves from claimed to evidenced', async () => {
    await goto(a, `/o/${slug}/assess`)
    const row = a.locator('li').filter({ hasText: 'Claimed only' }).first()
    await row.waitFor()
    const id = (await row.innerText()).match(/[A-Z]{2,3}-\d{2}/)[0]
    await row.locator('button[aria-expanded]').click()
    await row.locator('input[type=file]').setInputFiles({ name: 'access-review.pdf', mimeType: 'application/pdf', buffer: PDF })
    const done = a.locator('li').filter({ hasText: id }).first()
    await done.getByText('Evidenced', { exact: true }).waitFor()
    await done.getByText('access-review.pdf').waitFor()
    const { json } = await rest(`evidence?select=storage_path,sha256,size_bytes&org_id=eq.${orgId}`)
    assert(json.length === 1, `${json.length} evidence rows`)
    const sha = createHash('sha256').update(PDF).digest('hex')
    assert(json[0].sha256 === sha, `stored ${json[0].sha256}, file is ${sha}`)
    evidencePath = json[0].storage_path
    return `${id}, sha256 ${sha.slice(0, 12)} matches the file bytes`
  })

  await step('proven rises on the dashboard, claimed does not change', async () => {
    await goto(a, `/o/${slug}`)
    const after = await postureLine(a)
    assert(after.proven > before.proven && after.claimed === before.claimed, `${JSON.stringify(before)} then ${JSON.stringify(after)}`)
    return `${JSON.stringify(before)} then ${JSON.stringify(after)}`
  })

  await step('load worked examples into the risk register', async () => {
    await goto(a, `/o/${slug}/risks`)
    await a.getByText('Load worked examples', { exact: true }).click()
    await a.locator('tbody tr, main [role=alert]').first().waitFor({ timeout: 8000 }) // main, because Next's route announcer is also an empty role=alert
    const alert = a.locator('main [role=alert]')
    assert(await alert.count() === 0, `the app reported: ${await alert.first().innerText().catch(() => '')}`)
    const rows = await a.locator('tbody tr').count()
    assert(rows === 3, `${rows} rows`)
    return '3 rows'
  })

  await step('add a risk by hand, 4x5=20 High, residual 2x5=10 Medium', async () => {
    await goto(a, `/o/${slug}/risks`)
    await a.getByText('Add risk', { exact: true }).click()
    const dialog = a.getByRole('dialog')
    await dialog.locator('textarea[name=description]').fill('Field laptop holding donor records is stolen from a vehicle')
    await dialog.locator('textarea[name=consequence]').fill('Personal data exposed, regulator notified')
    await dialog.locator('input[name=owner]').fill('Operations Lead')
    await dialog.locator('select[name=likelihood]').selectOption('4')
    await dialog.locator('select[name=impact]').selectOption('5')
    await dialog.getByText('20', { exact: true }).waitFor()
    await dialog.getByText('High', { exact: true }).waitFor()
    await dialog.locator('select[name=residual_likelihood]').selectOption('2')
    await dialog.locator('select[name=residual_impact]').selectOption('5')
    await dialog.getByText('10', { exact: true }).waitFor()
    await dialog.getByText('Medium', { exact: true }).waitFor()
    await dialog.getByText('Save risk', { exact: true }).click()
    await dialog.waitFor({ state: 'hidden' })
    const row = a.locator('tbody tr').filter({ hasText: 'Field laptop' })
    await row.waitFor()
    const text = (await row.innerText()).replace(/\s+/g, ' ')
    assert(/\b20 High\b/.test(text) && /\b10 Medium\b/.test(text), text)
    return text.slice(0, 110)
  })

  await step('export CSV carries the scored risk', async () => {
    const [download] = await Promise.all([a.waitForEvent('download'), a.getByText('Export CSV', { exact: true }).click()])
    const csv = fs.readFileSync(await download.path(), 'utf8')
    fs.writeFileSync(path.join(SCRATCH, download.suggestedFilename()), csv)
    const line = csv.split('\r\n').find((l) => l.includes('Field laptop'))
    assert(csv.startsWith('Risk ID,Date Identified,'), csv.slice(0, 80))
    assert(line && /,4,5,20,High,/.test(line) && /,2,5,10,Medium,/.test(line), `line: ${line}`)
    return download.suggestedFilename()
  })

  await step('edit that risk, within the column grants on risks', async () => {
    const row = a.locator('tbody tr').filter({ hasText: 'Field laptop' })
    await row.getByText(/^RISK-\d+$/).click()
    const dialog = a.getByRole('dialog')
    await dialog.locator('input[name=owner]').fill('Country Director')
    await dialog.getByText('Save risk', { exact: true }).click()
    await dialog.waitFor({ state: 'hidden' })
    await row.getByText('Country Director').waitFor()
  })

  await step('raise a recommendation into the register', async () => {
    await goto(a, `/o/${slug}/recommendations`)
    const add = a.getByText('Add to register', { exact: true })
    const offered = await add.count()
    assert(offered > 0, 'nothing to raise')
    for (let i = 0; i < Math.min(3, offered); i++) {
      await add.first().click()
      await a.getByText('In register').nth(i).waitFor()
    }
    const { json } = await rest(`risks?select=source_ref&org_id=eq.${orgId}&source_ref=not.is.null`)
    const raised = json.filter((r) => r.source_ref.startsWith('control:'))
    assert(raised.length === Math.min(3, offered), JSON.stringify(json))
    return raised.map((r) => r.source_ref).join(', ')
  })

  await step('delete a risk as owner', async () => {
    await goto(a, `/o/${slug}/risks`)
    const rows = await a.locator('tbody tr').count()
    await a.getByLabel(/^Delete RISK/).first().click()
    await a.waitForFunction((n) => document.querySelectorAll('tbody tr').length === n, rows - 1)
    const { json } = await rest(`ledger?select=event&org_id=eq.${orgId}&event=eq.risks.delete`)
    assert(json.length === 1, `${json.length} delete entries in the ledger`)
    return `${rows} rows then ${rows - 1}, ledger recorded it`
  })

  // Which early answers hit a trigger control depends on the control library, so Needed is asserted after the scan.
  await step('guardrails open', async () => {
    await goto(a, `/o/${slug}/guardrails`)
    await seen(a, /\d+ of \d+ are needed now/)
    return (await a.getByText(/\d+ of \d+ are needed now/).first().innerText()).slice(0, 40)
  })

  await step('generate and approve the AI policy', async () => {
    await goto(a, `/o/${slug}/policies`)
    const card = a.locator('li').filter({ hasText: 'AI Acceptable Use Policy' })
    await card.getByText('Generate', { exact: true }).click()
    await card.getByText('Open v1', { exact: true }).click()
    await a.waitForURL(/\/policies\/[0-9a-f-]{36}$/)
    policyId = a.url().split('/').pop()
    await a.getByText('Approve', { exact: true }).click()
    await seen(a, `Approved by ${A.email}`)
    const { json } = await rest(`policies?select=status,content_sha256&id=eq.${policyId}`)
    assert(json[0].status === 'approved' && json[0].content_sha256, JSON.stringify(json))
  })

  await step('custom system opens', async () => {
    await goto(a, `/o/${slug}/blueprint`)
    await seen(a, 'Your Custom Security System')
    await seen(a, /First \d+ days/)
  })

  await step('A answers every remaining control through the UI', async () => {
    await goto(a, `/o/${slug}/assess`)
    const { done, total } = await progress(a)
    await answerControls(a, slug, total - done, cursor)
    await goto(a, `/o/${slug}/assess`)
    const after = await progress(a)
    assert(after.done === total, `${after.done} of ${total}`)
    return `${after.done} of ${total}`
  })

  await step('one live scan of example.com, verified by service role in this emulator only', async () => {
    const seeded = await rest('domains', { method: 'POST', prefer: 'return=representation', body: { org_id: orgId, domain: 'example.com', verified_at: new Date().toISOString() } })
    assert(seeded.status === 201, JSON.stringify(seeded))
    await goto(a, `/o/${slug}/tests`)
    await seen(a, 'Verified')
    await a.getByText('Run live test', { exact: true }).click()
    await seen(a, 'Results for example.com', 120000)
    const { json } = await rest(`scans?select=score,results&org_id=eq.${orgId}`)
    assert(json.length === 1, `${json.length} scans`)
    const tally = {}
    for (const r of json[0].results) tally[r.outcome] = (tally[r.outcome] ?? 0) + 1
    return `score ${json[0].score}, ${JSON.stringify(tally)}`
  })

  await step('guardrails react to the scan findings', async () => {
    await goto(a, `/o/${slug}/guardrails`)
    const shown = await a.getByText('Needed', { exact: true }).count()
    assert(shown > 0, 'no guardrail marked Needed after a scan with failures')
    return (await a.getByText(/\d+ of \d+ are needed now/).first().innerText()).slice(0, 40)
  })

  await step('sign an attestation and publish it', async () => {
    await goto(a, `/o/${slug}/proof`)
    await seen(a, 'Chain intact')
    await a.getByText('Sign attestation', { exact: true }).click()
    await a.getByText('Publish', { exact: true }).waitFor()
    await a.getByText('Publish', { exact: true }).click()
    await a.getByText('Trust page').waitFor()
    await goto(a, `/o/${slug}/proof`)
    await seen(a, 'Unpublish')
    const { json } = await rest(`attestations?select=published&org_id=eq.${orgId}`)
    assert(json.length === 1 && json[0].published === true, JSON.stringify(json))
  })

  await step('trust page, signed out, says Signature valid', async () => {
    await goto(stranger, `/trust/${slug}`)
    await seen(stranger, 'Signature valid')
    await seen(stranger, ORG_NAME)
    await seen(stranger, 'example.com')
    bundle = await stranger.getByLabel('Signed bundle').inputValue()
    assert(bundle.includes('canonical'), bundle.slice(0, 80))
  })

  await step('the workspace itself stays closed to a signed-out visitor', async () => {
    await goto(stranger, `/o/${slug}`)
    assert(new URL(stranger.url()).pathname === '/signin', stranger.url())
  })

  const verify = async (raw) => {
    await goto(stranger, '/verify')
    await stranger.getByLabel('Signed bundle').fill(raw)
    await stranger.getByText('Verify', { exact: true }).click()
    await stranger.getByRole('status').waitFor()
    return stranger.getByRole('status').innerText()
  }

  await step('verifier accepts the pasted bundle', async () => {
    const text = await verify(bundle)
    assert(text.startsWith('Valid.'), text)
    return text.slice(0, 80)
  })

  await step('verifier rejects the bundle with one character changed', async () => {
    const signed = JSON.parse(bundle)
    const at = signed.canonical.indexOf(ORG_NAME)
    assert(at >= 0, 'org name not in canonical')
    signed.canonical = `${signed.canonical.slice(0, at)}B${signed.canonical.slice(at + 1)}`
    const text = await verify(JSON.stringify(signed))
    assert(text.startsWith('Not valid.') && text.includes('content was changed'), text)
    return text
  })

  await step('unpublishing withdraws the trust page and the bundle, publishing restores them', async () => {
    await goto(a, `/o/${slug}/proof`)
    await a.getByText('Unpublish', { exact: true }).click()
    await a.getByText('Publish', { exact: true }).waitFor()
    allowConsole = /status of 404/
    const gone = await goto(stranger, `/trust/${slug}`)
    allowConsole = null
    assert(gone.status() === 404, `trust page gave ${gone.status()}`)
    const text = await verify(bundle)
    assert(text.startsWith('Not valid.') && text.includes('withdrawn'), text)
    await a.getByText('Publish', { exact: true }).click()
    await a.getByText('Unpublish', { exact: true }).waitFor()
    assert((await verify(bundle)).startsWith('Valid.'), 'not valid again after republishing')
  })

  let bToken
  await step('B signs up', async () => {
    await signUp(b, B)
    bToken = await tokenFor(B)
  }, { critical: true })

  await step('B gets a 404 on every page of A', async () => {
    allowConsole = /status of 404/
    for (const p of ['', '/risks', '/proof', '/settings']) {
      const res = await goto(b, `/o/${slug}${p}`)
      assert(res.status() === 404, `/o/${slug}${p} gave ${res.status()}`)
    }
    allowConsole = null
    await absent(b, ORG_NAME)
  })

  await step('A\'s rows are unreachable with B\'s own token', async () => {
    const counts = []
    for (const table of ['risks', 'answers', 'evidence', 'scans', 'domains', 'policies', 'ledger', 'members', 'invites']) {
      const { status, json } = await rest(`${table}?select=org_id&org_id=eq.${orgId}`, { token: bToken })
      assert(status === 200 && json.length === 0, `${table}: ${status} ${JSON.stringify(json).slice(0, 80)}`)
      counts.push(table)
    }
    assert((await rest(`orgs?select=id&id=eq.${orgId}`, { token: bToken })).json.length === 0, 'orgs row visible')
    const ledger = await rest('rpc/verify_ledger', { token: bToken, method: 'POST', body: { p_org: orgId } })
    assert(ledger.status === 400 && /not a member/.test(ledger.json.message), JSON.stringify(ledger))
    const forged = await rest('risks', { token: bToken, method: 'POST', body: { org_id: orgId, description: 'Injected', likelihood: 1, impact: 1 } })
    assert(forged.status === 403 && forged.json.code === '42501', JSON.stringify(forged))
    return `${counts.length} tables empty, verify_ledger refused, insert ${forged.status} ${forged.json.code}`
  })

  await step('A\'s evidence file is unreachable with B\'s own token', async () => {
    const encoded = evidencePath.split('/').map(encodeURIComponent).join('/')
    const download = await storageCall(`evidence/${encoded}`, bToken)
    const sign = await storageCall(`sign/evidence/${encoded}`, bToken, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"expiresIn":60}' })
    assert(!download.ok && !sign.ok, `download ${download.status}, sign ${sign.status}`)
    return `download ${download.status}, sign ${sign.status}`
  })

  let inviteLink
  await step('A invites B as viewer', async () => {
    await goto(a, `/o/${slug}/settings`)
    await a.getByPlaceholder('colleague@example.org').fill(B.email)
    await a.locator('select[name=role]').selectOption('viewer')
    await a.getByText('Invite', { exact: true }).click()
    await seen(a, 'Send this link')
    inviteLink = await a.getByText(/\/invite\//).first().innerText()
    assert(inviteLink.startsWith(`${APP}/invite/`), inviteLink)
  })

  await step('B accepts and joins as viewer', async () => {
    await goto(b, inviteLink)
    await b.getByText('Accept invite', { exact: true }).click()
    await b.waitForURL(new RegExp(`/o/${slug}$`))
    await seen(b, ORG_NAME)
    const { json } = await rest(`members?select=role&org_id=eq.${orgId}&email=eq.${encodeURIComponent(B.email)}`)
    assert(json[0]?.role === 'viewer', JSON.stringify(json))
  })

  await step('B sees a read-only UI', async () => {
    const checks = []
    await goto(b, `/o/${slug}/risks`)
    await seen(b, 'Risk Register')
    await absent(b, 'Add risk')
    assert(await b.getByLabel(/^Delete RISK/).count() === 0, 'delete buttons shown')
    checks.push('risks')
    await goto(b, `/o/${slug}/assess`)
    await seen(b, /^\d+ of \d+ answered$/)
    const answerButtons = b.locator('button').filter({ hasText: /^(Yes|Partly|No|N\/A)$/ })
    const all = await answerButtons.count()
    assert(all > 0, 'no answer buttons found')
    for (let i = 0; i < all; i++) assert(await answerButtons.nth(i).isDisabled(), `${await answerButtons.nth(i).innerText()} is enabled`)
    await answerRows(b).first().locator('button[aria-expanded]').click()
    await absent(b, 'Attach evidence')
    checks.push('assess')
    await goto(b, `/o/${slug}/policies`)
    await absent(b, 'Generate')
    await absent(b, 'New version')
    await goto(b, `/o/${slug}/policies/${policyId}`)
    await absent(b, 'Approve')
    checks.push('policies')
    await goto(b, `/o/${slug}/proof`)
    await absent(b, 'Sign attestation')
    await absent(b, 'Unpublish')
    checks.push('proof')
    await goto(b, `/o/${slug}/settings`)
    assert(await b.locator('input[name=name]').isDisabled(), 'org name editable')
    assert(await b.getByText('Save profile', { exact: true }).isDisabled(), 'save enabled')
    assert(await b.getByPlaceholder('colleague@example.org').count() === 0, 'invite form shown')
    checks.push('settings')
    await goto(b, `/o/${slug}/recommendations`)
    await absent(b, 'Add to register')
    checks.push('recommendations')
    await goto(b, `/o/${slug}/tests`)
    await seen(b, 'Results for example.com')
    await absent(b, 'Run live test')
    checks.push('tests')
    return checks.join(', ')
  })

  await step('B\'s write attempts fail in the database', async () => {
    const before2 = (await rest(`orgs?select=name&id=eq.${orgId}`)).json[0].name
    const risk = await rest('risks', { token: bToken, method: 'POST', body: { org_id: orgId, description: 'Viewer write', likelihood: 1, impact: 1 } })
    assert(risk.status === 403 && risk.json.code === '42501', `risk: ${JSON.stringify(risk)}`)
    const answer = await rest('answers', { token: bToken, method: 'POST', prefer: 'resolution=merge-duplicates', body: { org_id: orgId, control_id: 'GOV-01', status: 'yes' } })
    assert(answer.status === 403 && answer.json.code === '42501', `answer: ${JSON.stringify(answer)}`)
    await rest(`orgs?id=eq.${orgId}`, { token: bToken, method: 'PATCH', body: { name: 'Hijacked' } })
    assert((await rest(`orgs?select=name&id=eq.${orgId}`)).json[0].name === before2, 'viewer renamed the org')
    const upload = await storageCall(`evidence/${orgId}/GOV-01/viewer.pdf`, bToken, { method: 'POST', headers: { 'content-type': 'application/pdf' }, body: PDF })
    assert(!upload.ok, `upload ${upload.status}`)
    return `risk ${risk.status}, answer ${answer.status}, rename changed nothing, upload ${upload.status}`
  })

  await step('A saves the organization profile', async () => {
    await goto(a, `/o/${slug}/settings`)
    await a.getByText('Save profile', { exact: true }).click()
    await seen(a, 'Profile saved')
  })

  await step('A removes B, and B is back to a 404', async () => {
    await goto(a, `/o/${slug}/settings`)
    await a.locator('li').filter({ hasText: B.email }).getByText('Remove', { exact: true }).click()
    await a.locator('li').filter({ hasText: B.email }).waitFor({ state: 'detached' })
    allowConsole = /status of 404/
    const res = await goto(b, `/o/${slug}`)
    allowConsole = null
    assert(res.status() === 404, `got ${res.status()}`)
  })

  await step('ledger chain still verifies after the whole journey', async () => {
    await goto(a, `/o/${slug}/proof`)
    await seen(a, 'Chain intact')
    const { json } = await rest(`ledger?select=event,actor&org_id=eq.${orgId}&order=seq.asc`)
    const noActor = {}
    for (const e of json) if (!e.actor) noActor[e.event] = (noActor[e.event] ?? 0) + 1
    return `${json.length} entries, without actor: ${JSON.stringify(noActor)}`
  })

  await step('screenshots of every workspace page at both sizes', async () => {
    const pages = [['risks', '/risks'], ['assess', '/assess'], ['tests', '/tests'], ['recommendations', '/recommendations'], ['guardrails', '/guardrails'],
      ['policies', '/policies'], ['policy-detail', `/policies/${policyId}`], ['blueprint', '/blueprint'], ['proof', '/proof'], ['settings', '/settings']]
    for (const [name, route] of pages) {
      await goto(a, `/o/${slug}${route}`)
      overflow.push(...await shot(a, name))
    }
    await goto(stranger, `/trust/${slug}`)
    overflow.push(...await shot(stranger, 'trust'))
    await goto(stranger, '/verify')
    overflow.push(...await shot(stranger, 'verify'))
    await goto(a, `/o/${slug}`)
    overflow.push(...await shot(a, 'dashboard-final'))
    return `${pages.length + 3} pages, 2 sizes each`
  })

  await step('no horizontal overflow on any screenshot', async () => {
    assert(overflow.length === 0, overflow.join('; '))
  })

  await step('A signs out from the sidebar', async () => {
    await goto(a, `/o/${slug}`)
    await a.getByText('Sign out', { exact: true }).click()
    await a.waitForURL(`${APP}/`)
    await goto(a, `/o/${slug}`)
    assert(new URL(a.url()).pathname === '/signin', a.url())
  })

  // The build lists these as static, and a prerendered page cannot carry the per-request CSP nonce.
  await step('prerendered pages run their scripts under the CSP', async () => {
    const blocked = []
    allowConsole = /status of 404/ // /no-such-page is meant to 404, only its CSP errors count
    for (const route of ['/', '/signin/mfa', '/no-such-page']) {
      const before3 = consoleErrors.length
      await goto(stranger, route)
      const hydrated = await stranger.evaluate(() => [...document.querySelectorAll('body, body *')].some((e) => Object.keys(e).some((k) => k.startsWith('__react'))))
      const csp = consoleErrors.slice(before3).filter((e) => /Content Security Policy/i.test(e.text)).length
      if (!hydrated || csp) blocked.push(`${route} hydrated=${hydrated} cspErrors=${csp}`)
    }
    allowConsole = null
    assert(blocked.length === 0, blocked.join('; '))
  })

  await step('the MFA code form is handled by the page, not submitted natively', async () => {
    await goto(stranger, '/signin/mfa')
    await stranger.getByLabel('6-digit code').fill('123456')
    await stranger.getByText('Verify', { exact: true }).click()
    await stranger.waitForTimeout(1500)
    assert(!stranger.url().includes('code=123456'), `native GET, the code landed in the URL: ${stranger.url()}`)
  })

  await step('no console errors, page errors, 5xx or CSP violations', async () => {
    const distinct = [...new Set(consoleErrors.map((e) => `${e.kind} ${new URL(e.url).pathname}: ${e.text}`))]
    assert(distinct.length === 0, `${consoleErrors.length} events, ${distinct.length} distinct. First: ${distinct.slice(0, 3).join(' | ')}`)
  })
}

async function main() {
  fs.mkdirSync(SHOTS, { recursive: true })
  assert(await portFree(`${SB}/health`), `${SB} is already in use`)
  assert(await portFree(APP), `${APP} is already in use`)

  start('emulator', ['tests/e2e/fake-supabase.mjs', '--write-env'])
  await waitFor(`${SB}/health`, 'fake-supabase')
  const env = fs.readFileSync(path.join(ROOT, '.env.local'), 'utf8')
  ANON = env.match(/^NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=(.*)$/m)[1].trim()
  SERVICE = env.match(/^SUPABASE_SERVICE_ROLE_KEY=(.*)$/m)[1].trim()

  if (!process.argv.includes('--no-build')) {
    console.log('next build')
    const built = spawnSync(process.execPath, [NEXT_BIN, 'build'], { cwd: ROOT, stdio: 'inherit' })
    assert(built.status === 0, `next build exited ${built.status}`)
  }
  start('next', ['--require', path.join(__dirname, 'scan-dns-stub.cjs'), NEXT_BIN, 'start', '-p', '3100'])
  await waitFor(APP, 'next start')

  const browser = await chromium.launch({ channel: 'msedge', headless: true })
  try {
    await journey(browser)
  } finally {
    await browser.close()
  }
}

main()
  .catch((e) => {
    results.push({ name: 'run', ok: false, error: e.message })
    console.log(`ABORTED ${e.message}`)
  })
  .finally(() => {
    stopAll()
    fs.writeFileSync(path.join(SCRATCH, 'journey-results.json'), JSON.stringify({ results, consoleErrors }, null, 2))
    const failed = results.filter((r) => !r.ok)
    console.log(`\n${results.length - failed.length} passed, ${failed.length} failed`)
    for (const f of failed) console.log(`  FAILED ${f.name}: ${f.error}`)
    process.exit(failed.length ? 1 : 0)
  })
