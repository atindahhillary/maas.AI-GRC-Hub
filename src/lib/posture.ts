import { AI_CONTROLS } from './content/ai-controls'
import { BLUEPRINT } from './content/blueprints'
import { CONTROLS } from './content/controls'
import { GUARDRAILS } from './content/guardrails'
import type { Control, Domain, Guardrail, OrgProfile, RiskTemplate } from './content/types'
import { CHECK_RISK, type CheckResult } from './scan/checks'

export const ALL_CONTROLS: Control[] = [...CONTROLS, ...AI_CONTROLS]
export const controlById = new Map(ALL_CONTROLS.map((c) => [c.id, c]))
export const applicableControls = (p: OrgProfile) => ALL_CONTROLS.filter((c) => !c.appliesIf || c.appliesIf(p))

export const DOMAIN_LABEL: Record<Domain, string> = {
  governance: 'Governance', identity: 'Identity and access', data: 'Data protection', endpoint: 'Devices',
  network: 'Network', cloud: 'Cloud', appsec: 'Application security', vendor: 'Third parties',
  people: 'People', incident: 'Incident response', resilience: 'Backup and resilience', ai: 'AI governance',
}

// Which live tests stand behind a control. A control is machine-proven only if all of its tests pass.
export const TESTED_BY: Record<string, string[]> = {
  'NET-01': ['dns.spf', 'dns.dmarc'],
  'DAT-04': ['tls.https', 'tls.redirect', 'web.hsts'],
}

export interface Answer { control_id: string; status: 'yes' | 'partial' | 'no' | 'na'; note: string; updated_at: string }
export interface EvidenceRow { id: string; control_id: string; name: string; sha256: string; size_bytes: number; created_at: string; storage_path: string }
export interface ScanRow { id: string; domain: string; score: number; results: CheckResult[]; created_at: string }

export type Assurance = 'tested' | 'evidenced' | 'claimed' | 'none'

const DAY = 86400000
const SCAN_FRESH_DAYS = 90
const EVIDENCE_FRESH_DAYS = 365

export interface ControlState { control: Control; answer?: Answer; assurance: Assurance; evidence: EvidenceRow[] }

export function controlStates(profile: OrgProfile, answers: Answer[], evidence: EvidenceRow[], scan: ScanRow | null, now = Date.now()): ControlState[] {
  const byId = new Map(answers.map((a) => [a.control_id, a]))
  const freshScan = scan && now - Date.parse(scan.created_at) <= SCAN_FRESH_DAYS * DAY ? scan : null
  const passed = new Set(freshScan?.results.filter((r) => r.outcome === 'pass').map((r) => r.id))
  return applicableControls(profile).map((control) => {
    const answer = byId.get(control.id)
    const docs = evidence.filter((e) => e.control_id === control.id)
    const freshDoc = docs.some((e) => now - Date.parse(e.created_at) <= EVIDENCE_FRESH_DAYS * DAY)
    const tests = TESTED_BY[control.id]
    const positive = answer?.status === 'yes' || answer?.status === 'partial'
    const assurance: Assurance = !positive ? 'none'
      : tests?.length && tests.every((t) => passed.has(t)) ? 'tested'
      : freshDoc ? 'evidenced' : 'claimed'
    return { control, answer, assurance, evidence: docs }
  })
}

export interface Posture {
  claimed: number
  proven: number
  answered: number
  total: number
  provenCount: number
  byDomain: { domain: Domain; label: string; claimed: number; proven: number; total: number }[]
}

export function posture(states: ControlState[]): Posture {
  const inScope = states.filter((s) => s.answer?.status !== 'na')
  const credit = (s: ControlState) => (s.answer?.status === 'yes' ? 1 : s.answer?.status === 'partial' ? 0.5 : 0)
  const isProven = (s: ControlState) => s.assurance === 'tested' || s.assurance === 'evidenced'
  const pct = (list: ControlState[], f: (s: ControlState) => number) => {
    const total = list.reduce((n, s) => n + s.control.weight, 0)
    return total ? Math.round((list.reduce((n, s) => n + s.control.weight * f(s), 0) / total) * 100) : 0
  }
  const domains = [...new Set(inScope.map((s) => s.control.domain))]
  return {
    claimed: pct(inScope, credit),
    proven: pct(inScope, (s) => (isProven(s) ? credit(s) : 0)),
    answered: states.filter((s) => s.answer).length,
    total: states.length,
    provenCount: inScope.filter((s) => isProven(s) && credit(s) > 0).length,
    byDomain: domains.map((domain) => {
      const list = inScope.filter((s) => s.control.domain === domain)
      return { domain, label: DOMAIN_LABEL[domain], claimed: pct(list, credit), proven: pct(list, (s) => (isProven(s) ? credit(s) : 0)), total: list.length }
    }),
  }
}

export interface Recommendation {
  key: string // 'control:IAM-02' or 'check:dns.dmarc', also the register's source_ref
  title: string
  why: string
  fix: string
  source: 'Assessment' | 'Live test'
  severity: number // likelihood x impact
  effort: string
  risk: Omit<RiskTemplate, 'strategy' | 'category'> & { strategy: RiskTemplate['strategy']; category: string }
}

const EFFORT_RANK: Record<string, number> = { hours: 4, days: 3, weeks: 2, months: 1 }

// Biggest risk first, and the quicker fix wins a tie.
export function recommendations(states: ControlState[], scan: ScanRow | null): Recommendation[] {
  const out: Recommendation[] = []
  for (const s of states) {
    if (s.answer?.status !== 'no' && s.answer?.status !== 'partial') continue
    const { risk, id, title, why, howToFix, effort } = s.control
    out.push({ key: `control:${id}`, title, why, fix: howToFix, source: 'Assessment', severity: risk.likelihood * risk.impact, effort, risk })
  }
  for (const r of scan?.results ?? []) {
    const t = CHECK_RISK[r.id]
    if (!t || (r.outcome !== 'fail' && r.outcome !== 'warn')) continue
    const severity = r.outcome === 'fail' ? t.likelihood * t.impact : Math.max(1, t.likelihood - 1) * t.impact
    out.push({ key: `check:${r.id}`, title: r.title, why: r.detail, fix: t.mitigation, source: 'Live test', severity, effort: 'hours', risk: { ...t, strategy: 'Mitigate' } })
  }
  return out.sort((a, b) => b.severity - a.severity || EFFORT_RANK[b.effort] - EFFORT_RANK[a.effort])
}

export interface GuardrailState { guardrail: Guardrail; needed: boolean; reasons: string[] }

export function guardrails(profile: OrgProfile, states: ControlState[], scan: ScanRow | null): GuardrailState[] {
  const failing = new Map<string, string>()
  for (const s of states) if (s.answer?.status === 'no' || s.answer?.status === 'partial') failing.set(s.control.id, s.control.title)
  for (const r of scan?.results ?? []) if (r.outcome === 'fail' || r.outcome === 'warn') failing.set(r.id, r.title)
  return GUARDRAILS.filter((g) => !g.appliesIf || g.appliesIf(profile))
    .map((guardrail) => {
      const reasons = guardrail.triggers.filter((t) => failing.has(t)).map((t) => failing.get(t)!)
      return { guardrail, needed: reasons.length > 0, reasons }
    })
    .sort((a, b) => Number(b.needed) - Number(a.needed))
}

export const blueprintFor = (p: OrgProfile) =>
  BLUEPRINT.filter((l) => !l.appliesIf || l.appliesIf(p))
    .map((l) => ({ ...l, chosen: l.options[p.budget] }))
    .sort((a, b) => a.phase - b.phase)
