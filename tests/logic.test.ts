import { generateKeyPairSync } from 'node:crypto'
import { readFileSync, readdirSync } from 'node:fs'
import ts from 'typescript'
import { afterEach, beforeAll, describe, expect, it } from 'vitest'
import { canonicalize, publicKeyInfo, signPayload, verifySignature, type AttestationPayload } from '../src/lib/attest'
import { AI_CONTROLS } from '../src/lib/content/ai-controls'
import { BLUEPRINT } from '../src/lib/content/blueprints'
import { CONTROLS } from '../src/lib/content/controls'
import { GUARDRAILS } from '../src/lib/content/guardrails'
import { POLICIES } from '../src/lib/content/policies'
import type { OrgProfile } from '../src/lib/content/types'
import { regulators, renderPolicy, tokens } from '../src/lib/policy'
import {
  ALL_CONTROLS, TESTED_BY, controlById, controlStates, guardrails, posture, recommendations,
  type Answer, type ControlState, type EvidenceRow, type ScanRow,
} from '../src/lib/posture'
import { parseProfile } from '../src/lib/profile'
import { BANDS, csvCell, currentScore, level, riskRef, risksToCsv, score, type Risk } from '../src/lib/risk'
import { CHECK_RISK, scanScore, type CheckResult, type Outcome } from '../src/lib/scan/checks'
import { isPublicIp, safeLookup } from '../src/lib/scan/fetch'

const source = (path: string) => readFileSync(new URL(`../src/lib/${path}`, import.meta.url), 'utf8')

const profile = (over: Partial<OrgProfile> = {}): OrgProfile => ({
  sector: 'tech', size: '11-50', countries: ['KE'], dataTypes: ['personal'], platforms: ['m365'],
  usesAI: false, buildsAI: false, hasSecurityLead: true, budget: 'moderate', ...over,
})

it('every file in src/lib parses', () => {
  const dir = new URL('../src/lib/', import.meta.url)
  const files = readdirSync(dir, { recursive: true, encoding: 'utf8' }).filter((f) => f.endsWith('.ts'))
  const errors = files.flatMap((f) => {
    const { diagnostics = [] } = ts.transpileModule(readFileSync(new URL(f.replaceAll('\\', '/'), dir), 'utf8'), { reportDiagnostics: true, fileName: f })
    return diagnostics.map((d) => `${f}: ${ts.flattenDiagnosticMessageText(d.messageText, '\n')}`)
  })
  expect(files.length).toBeGreaterThan(10)
  expect(errors).toEqual([])
})

describe('risk.ts', () => {
  it('scores as likelihood times impact', () => {
    expect(score(1, 1)).toBe(1)
    expect(score(5, 5)).toBe(25)
  })

  it.each([[1, 'Low'], [7, 'Low'], [8, 'Medium'], [14, 'Medium'], [15, 'High'], [25, 'High']])(
    'puts a score of %i in the %s band', (s, expected) => expect(level(s)).toBe(expected))

  it('keeps BANDS in step with level()', () => {
    for (const [name, [lo, hi]] of Object.entries(BANDS)) {
      expect(level(lo)).toBe(name)
      expect(level(hi)).toBe(name)
    }
  })

  it('reproduces the video example, 4x5=20 High falling to 2x5=10 Medium', () => {
    expect(score(4, 5)).toBe(20)
    expect(level(score(4, 5))).toBe('High')
    expect(score(2, 5)).toBe(10)
    expect(level(score(2, 5))).toBe('Medium')
  })

  it('pads risk references and prefers the residual score once assessed', () => {
    expect(riskRef(7)).toBe('RISK-007')
    expect(riskRef(1234)).toBe('RISK-1234')
    expect(currentScore({ inherent_score: 20, residual_score: 10 })).toBe(10)
    expect(currentScore({ inherent_score: 20, residual_score: null })).toBe(20)
  })

  it.each(['=1+1', '+1', '-1', '@SUM(A1)', '\tcmd', '\rcmd'])('neutralises the formula cell %j', (v) => {
    expect(csvCell(v).replace(/^"/, '').startsWith(`'${v[0]}`)).toBe(true)
  })

  it('leaves ordinary text and numbers alone, and writes null as empty', () => {
    expect(csvCell('plain')).toBe('plain')
    expect(csvCell(5)).toBe('5')
    expect(csvCell(-5)).toBe('-5')
    expect(csvCell(null)).toBe('')
  })

  it('quotes commas, quotes and newlines', () => {
    expect(csvCell('a,b')).toBe('"a,b"')
    expect(csvCell('say "hi"')).toBe('"say ""hi"""')
    expect(csvCell('a\nb')).toBe('"a\nb"')
    expect(csvCell('a\rb')).toBe('"a\rb"')
  })

  it('escapes the formula first and quotes the result', () => {
    expect(csvCell('=HYPERLINK("http://x","y")')).toBe(`"'=HYPERLINK(""http://x"",""y"")"`)
  })

  const row: Risk = {
    id: 'r1', org_id: 'o1', seq: 3, source_ref: null, date_identified: '2026-01-02', description: '=cmd()', consequence: 'a, b',
    category: 'Security', likelihood: 4, impact: 5, inherent_score: 20, inherent_level: 'High', existing_controls: '',
    strategy: 'Mitigate', mitigation: '', owner: 'Ann', target_date: null, status: 'Open', residual_likelihood: 2,
    residual_impact: 5, residual_score: 10, residual_level: 'Medium', last_reviewed: null,
  }

  it('writes the header row first with every column, joined by CRLF', () => {
    const [header, ...rest] = risksToCsv([row]).split('\r\n')
    expect(header.split(',')).toHaveLength(20)
    expect(header.startsWith('Risk ID,Date Identified,Risk Description,Consequence,Category,')).toBe(true)
    expect(header.endsWith('Residual Risk Level,Last Reviewed')).toBe(true)
    expect(rest).toHaveLength(1)
    expect(rest[0].startsWith(`RISK-003,2026-01-02,'=cmd(),"a, b",Security,4,5,20,High`)).toBe(true)
  })

  it('writes only the header for an empty register', () => {
    expect(risksToCsv([]).split('\r\n')).toHaveLength(1)
  })
})

describe('scan/fetch.ts isPublicIp', () => {
  it.each([
    '127.0.0.1', '127.255.255.254', '10.0.0.1', '10.255.255.255', '172.16.0.1', '172.20.1.1', '172.31.255.255',
    '192.168.0.1', '192.168.255.255', '169.254.169.254', '100.64.0.1', '100.127.255.255', '0.0.0.0', '224.0.0.1',
    '255.255.255.255', '198.18.0.1', '::1', '::', 'fc00::', 'fd12:3456::1', 'fe80::', 'febf::1', 'ff02::1',
    '::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:10.0.0.1', '::ffff:a9fe:a9fe', '2001:db8::1', '64:ff9b::7f00:1',
  ])('rejects %s', (ip) => expect(isPublicIp(ip)).toBe(false))

  it.each(['', 'not-an-ip', 'localhost', '256.0.0.1', '1.2.3', '1.2.3.4.5', '1.2.3.4/24', 'http://1.1.1.1', ' 8.8.8.8', '::g'])(
    'rejects the garbage string %j', (ip) => expect(isPublicIp(ip)).toBe(false))

  it.each(['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111', '172.15.255.255', '172.32.0.1', '100.63.255.255', '100.128.0.1', '192.169.0.1', '169.253.0.1'])(
    'accepts %s', (ip) => expect(isPublicIp(ip)).toBe(true))

  // Beyond the requested list: these are the same addresses in spellings the prefix match does not see.
  it.each(['0:0:0:0:0:0:0:1', '0:0:0:0:0:ffff:7f00:1', '0:0:0:0:0:FFFF:127.0.0.1', '::127.0.0.1', 'fec0::1', '2002:7f00:1::'])(
    'rejects the non-public address %s written in an uncommon form', (ip) => expect(isPublicIp(ip)).toBe(false))

  it('accepts addresses in 192.0.0.0/16 outside the reserved /24s', () => {
    expect(isPublicIp('192.0.78.24')).toBe(true) // WordPress.com hosting
  })

  it('safeLookup refuses a name that resolves to loopback', async () => {
    const err = await new Promise<NodeJS.ErrnoException | null>((resolve) => safeLookup('localhost', {}, (e) => resolve(e)))
    expect(err?.code).toBe('EBLOCKED')
  })
})

describe('scan/checks.ts scanScore', () => {
  const r = (outcome: Outcome, weight: 1 | 2 | 3 = 1): CheckResult => ({ id: 'x', group: 'Web', title: 't', detail: 'd', outcome, weight })

  it('gives 100 for all pass and 0 for all fail', () => {
    expect(scanScore([r('pass'), r('pass', 3)])).toBe(100)
    expect(scanScore([r('fail'), r('fail', 3)])).toBe(0)
  })

  it('ignores info results', () => {
    expect(scanScore([r('pass'), r('info', 3)])).toBe(100)
    expect(scanScore([r('fail'), r('info', 3)])).toBe(0)
  })

  it('counts a warn as half', () => {
    expect(scanScore([r('warn')])).toBe(50)
    expect(scanScore([r('pass'), r('warn'), r('fail')])).toBe(50)
  })

  it('applies weights', () => {
    expect(scanScore([r('pass', 3), r('fail', 1)])).toBe(75)
    expect(scanScore([r('pass', 1), r('warn', 2), r('fail', 3)])).toBe(33)
  })

  it('gives 0 for all-info and for no results', () => {
    expect(scanScore([r('info'), r('info', 3)])).toBe(0)
    expect(scanScore([])).toBe(0)
  })
})

describe('attest.ts', () => {
  const payload: AttestationPayload = {
    version: 1, org: 'Acme', slug: 'acme', issuedAt: '2026-01-01T00:00:00.000Z', expiresAt: '2026-04-01T00:00:00.000Z',
    claimedScore: 80, provenScore: 60, controlsApplicable: 10, controlsProven: 6, frameworks: ['NIST CSF 2.0'],
    scan: { domain: 'acme.co.ke', at: '2026-01-01', score: 90, passed: 18, total: 20 }, policiesApproved: ['Info Sec'],
    ledger: { entries: 5, head: 'abc' },
  }

  beforeAll(() => {
    process.env.ATTESTATION_PRIVATE_KEY = generateKeyPairSync('ed25519').privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64')
  })

  it('canonicalizes independently of key order, at every depth', () => {
    expect(canonicalize({ a: 1, b: { c: 2, d: [{ e: 3, f: 4 }] } })).toBe(canonicalize({ b: { d: [{ f: 4, e: 3 }], c: 2 }, a: 1 }))
  })

  it('keeps array order, since arrays are ordered data', () => {
    expect(canonicalize([1, 2])).not.toBe(canonicalize([2, 1]))
  })

  it('survives a database style JSON round trip byte for byte', () => {
    const shuffled = JSON.parse(JSON.stringify(Object.fromEntries(Object.entries(payload).reverse())))
    expect(canonicalize(shuffled)).toBe(canonicalize(payload))
  })

  it('verifies what it signed', () => {
    const { canonical, signature, keyId } = signPayload(payload)
    expect(verifySignature(canonical, signature)).toBe(true)
    expect(keyId).toMatch(/^[0-9a-f]{16}$/)
    expect(keyId).toBe(publicKeyInfo().keyId)
  })

  it('verifies with the published public key', () => {
    const { canonical, signature } = signPayload(payload)
    expect(verifySignature(canonical, signature, publicKeyInfo().publicKey)).toBe(true)
  })

  it('fails when one character of the canonical text changes', () => {
    const { canonical, signature } = signPayload(payload)
    expect(verifySignature(canonical.replace('"provenScore":60', '"provenScore":90'), signature)).toBe(false)
    expect(verifySignature(`${canonical.slice(0, -1)} `, signature)).toBe(false)
  })

  it.each(['', 'not base64 !!', 'AAAA', 'A'.repeat(88)])('returns false, not a throw, for the bad signature %j', (bad) => {
    expect(verifySignature(signPayload(payload).canonical, bad)).toBe(false)
  })

  it.each(['', 'garbage', 'AAAA'])('returns false, not a throw, for the bad public key %j', (bad) => {
    const { canonical, signature } = signPayload(payload)
    expect(verifySignature(canonical, signature, bad)).toBe(false)
  })

  it('returns false for a valid key that did not sign', () => {
    const { canonical, signature } = signPayload(payload)
    const other = generateKeyPairSync('ed25519').publicKey.export({ format: 'der', type: 'spki' }).toString('base64')
    expect(verifySignature(canonical, signature, other)).toBe(false)
  })
})

describe('posture.ts', () => {
  const NOW = Date.parse('2026-06-01T00:00:00Z')
  const DAY = 86400000
  const ago = (days: number) => new Date(NOW - days * DAY).toISOString()
  const base = profile()
  const [c1, c2, c3] = ALL_CONTROLS.filter((c) => !c.appliesIf)

  const answer = (control_id: string, status: Answer['status']): Answer => ({ control_id, status, note: '', updated_at: ago(0) })
  const doc = (control_id: string, days: number): EvidenceRow => ({ id: 'e', control_id, name: 'n', sha256: 'x', size_bytes: 1, storage_path: 'p', created_at: ago(days) })
  const scan = (days: number, results: [string, Outcome][]): ScanRow => ({
    id: 's', domain: 'acme.co.ke', score: 0, created_at: ago(days),
    results: results.map(([id, outcome]) => ({ id, outcome, group: 'Web', title: `title of ${id}`, detail: `detail of ${id}`, weight: 1 })),
  })
  const stateOf = (id: string, answers: Answer[], evidence: EvidenceRow[] = [], s: ScanRow | null = null) =>
    controlStates(base, answers, evidence, s, NOW).find((x) => x.control.id === id)!

  afterEach(() => { for (const k of Object.keys(TESTED_BY)) delete TESTED_BY[k] })

  describe('controlStates', () => {
    it('treats yes without evidence as claimed', () => {
      expect(stateOf(c1.id, [answer(c1.id, 'yes')]).assurance).toBe('claimed')
    })

    it('treats yes with fresh evidence as evidenced', () => {
      expect(stateOf(c1.id, [answer(c1.id, 'yes')], [doc(c1.id, 10)]).assurance).toBe('evidenced')
    })

    it('counts evidence up to exactly 365 days old, and not a day older', () => {
      expect(stateOf(c1.id, [answer(c1.id, 'yes')], [doc(c1.id, 365)]).assurance).toBe('evidenced')
      expect(stateOf(c1.id, [answer(c1.id, 'yes')], [doc(c1.id, 366)]).assurance).toBe('claimed')
    })

    it('still lists stale evidence on the state, it just proves nothing', () => {
      expect(stateOf(c1.id, [answer(c1.id, 'yes')], [doc(c1.id, 400)]).evidence).toHaveLength(1)
    })

    it('ignores evidence filed against a different control', () => {
      expect(stateOf(c1.id, [answer(c1.id, 'yes')], [doc(c2.id, 1)]).assurance).toBe('claimed')
    })

    it.each(['no', 'na'] as const)('gives no assurance for %s even with evidence', (status) => {
      expect(stateOf(c1.id, [answer(c1.id, status)], [doc(c1.id, 1)]).assurance).toBe('none')
    })

    it('gives no assurance for an unanswered control', () => {
      expect(stateOf(c1.id, [], [doc(c1.id, 1)]).assurance).toBe('none')
    })

    it('treats partial with fresh evidence as evidenced', () => {
      expect(stateOf(c1.id, [answer(c1.id, 'partial')], [doc(c1.id, 1)]).assurance).toBe('evidenced')
    })

    it('marks a control tested only when all of its tests pass in a fresh scan', () => {
      TESTED_BY[c1.id] = ['dns.spf', 'dns.dmarc']
      const yes = [answer(c1.id, 'yes')]
      expect(stateOf(c1.id, yes, [], scan(1, [['dns.spf', 'pass'], ['dns.dmarc', 'pass']])).assurance).toBe('tested')
      expect(stateOf(c1.id, yes, [], scan(1, [['dns.spf', 'pass'], ['dns.dmarc', 'warn']])).assurance).toBe('claimed')
      expect(stateOf(c1.id, yes, [], scan(1, [['dns.spf', 'pass']])).assurance).toBe('claimed')
    })

    it('stops trusting a scan after 90 days', () => {
      TESTED_BY[c1.id] = ['dns.spf']
      const yes = [answer(c1.id, 'yes')]
      expect(stateOf(c1.id, yes, [], scan(90, [['dns.spf', 'pass']])).assurance).toBe('tested')
      expect(stateOf(c1.id, yes, [], scan(91, [['dns.spf', 'pass']])).assurance).toBe('claimed')
    })

    it('leaves out controls that do not apply to the profile', () => {
      const ai = ALL_CONTROLS.filter((c) => c.appliesIf && !c.appliesIf(base))
      expect(ai.length).toBeGreaterThan(0)
      const ids = controlStates(base, [], [], null, NOW).map((s) => s.control.id)
      for (const c of ai) expect(ids).not.toContain(c.id)
    })
  })

  describe('posture', () => {
    const st = (weight: 1 | 2 | 3, status: Answer['status'] | null, assurance: ControlState['assurance'], domain = c1.domain): ControlState => ({
      control: { ...c1, weight, domain }, answer: status ? answer('X', status) : undefined, assurance, evidence: [],
    })

    it('separates claimed from proven', () => {
      const p = posture([st(3, 'yes', 'evidenced'), st(1, 'yes', 'claimed')])
      expect(p).toMatchObject({ claimed: 100, proven: 75, provenCount: 1 })
    })

    it('gives partial half credit, on both scales', () => {
      expect(posture([st(2, 'partial', 'evidenced')])).toMatchObject({ claimed: 50, proven: 50 })
      expect(posture([st(3, 'yes', 'evidenced'), st(1, 'partial', 'claimed')])).toMatchObject({ claimed: 88, proven: 75 })
    })

    it('excludes na from the denominator but still counts it as answered', () => {
      expect(posture([st(1, 'yes', 'claimed'), st(3, 'na', 'none')])).toMatchObject({ claimed: 100, answered: 2, total: 2 })
    })

    it('keeps unanswered controls in the denominator', () => {
      expect(posture([st(1, 'yes', 'claimed'), st(1, null, 'none')])).toMatchObject({ claimed: 50, answered: 1, total: 2 })
    })

    it('returns 0, not NaN, when everything is na or empty', () => {
      expect(posture([st(2, 'na', 'none')])).toMatchObject({ claimed: 0, proven: 0 })
      expect(posture([])).toMatchObject({ claimed: 0, proven: 0, total: 0 })
    })

    it('breaks the scores down by domain', () => {
      const p = posture([st(1, 'yes', 'evidenced', 'identity'), st(1, 'no', 'none', 'cloud')])
      expect(p.byDomain.find((d) => d.domain === 'identity')).toMatchObject({ claimed: 100, proven: 100, total: 1 })
      expect(p.byDomain.find((d) => d.domain === 'cloud')).toMatchObject({ claimed: 0, proven: 0, total: 1 })
    })

    it('flows through from controlStates: stale evidence leaves a claim unproven', () => {
      const answers = [c1, c2, c3].map((c) => answer(c.id, 'yes'))
      const states = controlStates(base, answers, [doc(c1.id, 400), doc(c2.id, 1)], null, NOW).filter((s) => s.answer)
      const total = c1.weight + c2.weight + c3.weight
      expect(posture(states)).toMatchObject({ claimed: 100, proven: Math.round((c2.weight / total) * 100), provenCount: 1 })
    })
  })

  describe('recommendations', () => {
    const rank: Record<string, number> = { hours: 4, days: 3, weeks: 2, months: 1 }

    it('sorts by severity, then the quicker fix', () => {
      const states = controlStates(base, ALL_CONTROLS.map((c) => answer(c.id, 'no')), [], null, NOW)
      const recs = recommendations(states, scan(1, [['exposure.env', 'fail'], ['dns.spf', 'warn']]))
      expect(recs.length).toBeGreaterThan(5)
      for (let i = 1; i < recs.length; i++) {
        expect(recs[i - 1].severity).toBeGreaterThanOrEqual(recs[i].severity)
        if (recs[i - 1].severity === recs[i].severity) expect(rank[recs[i - 1].effort]).toBeGreaterThanOrEqual(rank[recs[i].effort])
      }
      expect(recs[0]).toMatchObject({ key: 'check:exposure.env', severity: 25, source: 'Live test' })
    })

    it('recommends for no and partial only', () => {
      const states = controlStates(base, [answer(c1.id, 'no'), answer(c2.id, 'partial'), answer(c3.id, 'yes')], [], null, NOW)
      expect(recommendations(states, null).map((r) => r.key).sort()).toEqual([`control:${c1.id}`, `control:${c2.id}`].sort())
    })

    it('rates a warn one likelihood step below a fail', () => {
      const t = CHECK_RISK['dns.spf']
      expect(recommendations([], scan(1, [['dns.spf', 'fail']]))[0].severity).toBe(t.likelihood * t.impact)
      expect(recommendations([], scan(1, [['dns.spf', 'warn']]))[0].severity).toBe((t.likelihood - 1) * t.impact)
    })

    it('skips passes, info and checks with no risk template', () => {
      expect(recommendations([], scan(1, [['dns.spf', 'pass'], ['dns.dmarc', 'info'], ['web.nosniff', 'fail']]))).toEqual([])
    })
  })

  describe('guardrails', () => {
    const named = GUARDRAILS.find((g) => g.id === 'email-dmarc-phased')!
    const byId = (list: ReturnType<typeof guardrails>, id: string) => list.find((g) => g.guardrail.id === id)!

    it('marks a guardrail needed from a failing or warning scan check, and gives the reason', () => {
      for (const outcome of ['fail', 'warn'] as const) {
        const g = byId(guardrails(base, [], scan(1, [['dns.dmarc', outcome]])), named.id)
        expect(g).toMatchObject({ needed: true, reasons: ['title of dns.dmarc'] })
      }
    })

    it('marks a guardrail needed from a no or partial control answer', () => {
      const id = GUARDRAILS.flatMap((g) => g.triggers).find((t) => controlById.has(t))!
      const owner = GUARDRAILS.find((g) => g.triggers.includes(id) && !g.appliesIf)!
      for (const status of ['no', 'partial'] as const) {
        const state: ControlState = { control: controlById.get(id)!, answer: answer(id, status), assurance: 'none', evidence: [] }
        expect(byId(guardrails(base, [state], null), owner.id).needed).toBe(true)
      }
    })

    it('does not mark it needed when the trigger passes', () => {
      expect(byId(guardrails(base, [], scan(1, [['dns.dmarc', 'pass']])), named.id)).toMatchObject({ needed: false, reasons: [] })
    })

    it('lists needed guardrails first', () => {
      const list = guardrails(base, [], scan(1, [['dns.dmarc', 'fail']]))
      expect(list.findIndex((g) => !g.needed)).toBeGreaterThan(list.findLastIndex((g) => g.needed))
    })

    it('leaves out guardrails that do not apply to the profile', () => {
      const hidden = GUARDRAILS.filter((g) => g.appliesIf && !g.appliesIf(base))
      expect(hidden.length).toBeGreaterThan(0)
      const shown = guardrails(base, [], null).map((g) => g.guardrail.id)
      for (const g of hidden) expect(shown).not.toContain(g.id)
    })
  })
})

describe('policy.ts', () => {
  const PROFILES: [string, OrgProfile][] = [
    ['Kenyan tech firm', profile()],
    ['small Kenyan bank with no security lead', profile({ sector: 'finance', size: '1-10', hasSecurityLead: false })],
    ['large health org with empty lists', profile({ sector: 'health', size: '1000+', countries: [], dataTypes: [], platforms: [], hasSecurityLead: false })],
    ['AI builder selecting everything', profile({ sector: 'education', countries: ['KE', 'UG', 'TZ', 'RW', 'NG', 'ZA', 'GH', 'GB', 'US', 'EU'], dataTypes: ['personal', 'health', 'financial', 'children', 'ip'], platforms: ['aws', 'azure', 'gcp', 'm365', 'google_workspace', 'on_prem'], usesAI: true, buildsAI: true })],
    ['non-profit in Germany and Uganda',profile({ sector: 'ngo', countries: ['DE', 'UG'], usesAI: true })],
    ['unknown sector and country', profile({ sector: 'other', size: '251-1000', countries: ['ZZ'], budget: 'minimal' })],
  ]
  const strings = (v: unknown): string[] =>
    typeof v === 'string' ? [v] : Array.isArray(v) ? v.flatMap(strings) : v && typeof v === 'object' ? Object.values(v).flatMap(strings) : []

  describe.each(PROFILES)('renderPolicy for a %s', (_name, p) => {
    it.each(POLICIES.map((t) => [t.id, t] as const))('%s has no leftover braces', (_id, tpl) => {
      const bad = strings(renderPolicy(tpl, 'Acme Ltd', p)).filter((s) => /[{}]/.test(s))
      expect(bad).toEqual([])
    })

    it('keeps exactly the sections whose appliesIf passes', () => {
      for (const tpl of POLICIES) {
        const expected = tpl.sections.filter((s) => !s.appliesIf || s.appliesIf(p)).length
        expect(renderPolicy(tpl, 'Acme Ltd', p).sections).toHaveLength(expected)
      }
    })

    it('produces no doubled words such as "personal data data"', () => {
      const bad = POLICIES.flatMap((t) => strings(renderPolicy(t, 'Acme Ltd', p)).flatMap((s) => [...s.matchAll(/\b(\w+) \1\b/gi)].map((m) => `${t.id}: ...${s.slice(Math.max(0, m.index - 30), m.index + 30)}...`)))
      expect(bad).toEqual([])
    })
  })

  const privacyEU = POLICIES.flatMap((t) => t.sections.filter((s) => s.heading === 'EU and EEA data').map(() => t))[0]
  const headings = (p: OrgProfile) => renderPolicy(privacyEU, 'Acme Ltd', p).sections.map((s) => s.heading)

  it('filters the EU section out for an org that does not touch the EU', () => {
    expect(headings(profile())).not.toContain('EU and EEA data')
  })

  it('keeps the EU section for an org in Germany', () => {
    expect(headings(profile({ countries: ['DE'] }))).toContain('EU and EEA data')
  })

  it('keeps the EU section for the "EU" choice, the only EU option on the onboarding form', () => {
    expect(headings(profile({ countries: ['EU'] }))).toContain('EU and EEA data')
  })

  it('names the Kenya ODPC for KE', () => {
    expect(regulators(profile({ countries: ['KE'] }))).toContain('Office of the Data Protection Commissioner (Kenya)')
  })

  it('adds the CBK only for finance in Kenya', () => {
    expect(regulators(profile({ countries: ['KE'], sector: 'finance' }))).toContain('Central Bank of Kenya')
    expect(regulators(profile({ countries: ['KE'], sector: 'tech' }))).not.toContain('Central Bank of Kenya')
    expect(regulators(profile({ countries: ['UG'], sector: 'finance' }))).not.toContain('Central Bank of Kenya')
  })

  it('falls back to a generic regulator rather than an empty list', () => {
    expect(regulators(profile({ countries: [] }))).toEqual(['your national data protection authority'])
  })

  it('chooses the security owner from lead, then size', () => {
    expect(tokens('A', profile({ hasSecurityLead: true }))['{securityOwner}']).toBe('Security Lead')
    expect(tokens('A', profile({ hasSecurityLead: false, size: '1-10' }))['{securityOwner}']).toBe('Managing Director')
    expect(tokens('A', profile({ hasSecurityLead: false, size: '1000+' }))['{securityOwner}']).toBe('IT Lead')
  })
})

describe('profile.ts parseProfile', () => {
  const form = (over: Record<string, string | string[] | null> = {}) => {
    const values: Record<string, string | string[] | null> = { sector: 'finance', size: '1-10', budget: 'minimal', ...over }
    const f = new FormData()
    for (const [k, v] of Object.entries(values)) for (const item of [v].flat()) if (item !== null) f.append(k, item)
    return f
  }

  it('accepts a known profile', () => {
    expect(parseProfile(form({ countries: ['KE', 'UG'], dataTypes: ['personal'], platforms: ['aws'], usesAI: 'on' }))).toEqual({
      sector: 'finance', size: '1-10', budget: 'minimal', countries: ['KE', 'UG'], dataTypes: ['personal'], platforms: ['aws'],
      usesAI: true, buildsAI: false, hasSecurityLead: false,
    })
  })

  it.each([['sector', 'banking'], ['size', '5'], ['budget', 'unlimited'], ['sector', ''], ['sector', null], ['size', null], ['budget', null]])(
    'rejects %s=%j', (key, value) => expect(parseProfile(form({ [key]: value }))).toBeNull())

  it('drops unknown list values rather than storing them', () => {
    const p = parseProfile(form({ dataTypes: ['personal', 'dna'], platforms: ['aws', 'oracle'], countries: ['KE', 'kenya', 'ke', '<script>'] }))
    expect(p).toMatchObject({ dataTypes: ['personal'], platforms: ['aws'], countries: ['KE'] })
  })

  it('caps countries at 20', () => {
    const p = parseProfile(form({ countries: Array.from({ length: 30 }, (_, i) => `A${String.fromCharCode(65 + (i % 26))}`) }))
    expect(p?.countries).toHaveLength(20)
  })

  it('treats a flag as on only for the exact value "on"', () => {
    expect(parseProfile(form({ usesAI: 'true', buildsAI: 'on' }))).toMatchObject({ usesAI: false, buildsAI: true })
  })
})

describe('content integrity', () => {
  const FILES = ['content/controls.ts', 'content/ai-controls.ts', 'content/policies.ts', 'content/guardrails.ts', 'content/blueprints.ts']
  const dupes = (ids: string[]) => ids.filter((id, i) => ids.indexOf(id) !== i)
  const CONTROL_IDS = new Set(ALL_CONTROLS.map((c) => c.id))
  // runChecks needs the network, so its ids are read from the source that defines them.
  const CHECK_IDS = new Set([...source('scan/checks.ts').matchAll(/\bid: '([a-z]+\.[a-z]+)'/g)].map((m) => m[1]))

  it('finds the check ids it is about to compare against', () => {
    expect(CHECK_IDS.size).toBeGreaterThanOrEqual(20)
    expect(CHECK_IDS).toContain('dns.spf')
    expect(CHECK_IDS).toContain('exposure.securitytxt')
  })

  it.each([
    ['controls', [...CONTROLS, ...AI_CONTROLS]],
    ['policies', POLICIES],
    ['guardrails', GUARDRAILS],
    ['blueprint layers', BLUEPRINT],
  ] as [string, { id: string }[]][])('%s have unique ids', (_name, items) => {
    expect(items.length).toBeGreaterThan(0)
    expect(dupes(items.map((i) => i.id))).toEqual([])
  })

  it('control ids fit the database check on answers and evidence', () => {
    expect(ALL_CONTROLS.map((c) => c.id).filter((id) => !/^[A-Z]{2,3}-[0-9]{2}$/.test(id))).toEqual([])
  })

  it('every policy clause references controls that exist', () => {
    const dangling = POLICIES.flatMap((t) => t.sections.flatMap((s) => s.clauses.flatMap((c) => c.controls.filter((id) => !CONTROL_IDS.has(id)).map((id) => `${t.id}: ${id}`))))
    expect(dangling).toEqual([])
  })

  it('every blueprint layer references controls that exist', () => {
    const dangling = BLUEPRINT.flatMap((l) => l.controls.filter((id) => !CONTROL_IDS.has(id)).map((id) => `${l.id}: ${id}`))
    expect(dangling).toEqual([])
  })

  it('every guardrail trigger is a control or a scan check', () => {
    const dangling = GUARDRAILS.flatMap((g) => g.triggers.filter((t) => !CONTROL_IDS.has(t) && !CHECK_IDS.has(t)).map((t) => `${g.id}: ${t}`))
    expect(dangling).toEqual([])
  })

  it('every guardrail has at least one trigger, so it can surface', () => {
    expect(GUARDRAILS.filter((g) => g.triggers.length === 0).map((g) => g.id)).toEqual([])
  })

  it('every CHECK_RISK key is a real scan check', () => {
    expect(Object.keys(CHECK_RISK).filter((k) => !CHECK_IDS.has(k))).toEqual([])
  })

  it('every likelihood and impact is an integer from 1 to 5', () => {
    const risks = [...ALL_CONTROLS.map((c) => [c.id, c.risk] as const), ...Object.entries(CHECK_RISK)]
    const bad = risks.filter(([, r]) => ![r.likelihood, r.impact].every((n) => Number.isInteger(n) && n >= 1 && n <= 5)).map(([id]) => id)
    expect(bad).toEqual([])
  })

  it.each(FILES)('%s has no em dash', (file) => {
    const lines = source(file).split('\n').flatMap((l, i) => (l.includes('—') ? [`line ${i + 1}: ${l.trim().slice(0, 80)}`] : []))
    expect(lines).toEqual([])
  })
})
