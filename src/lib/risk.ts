// Scoring method from the risk register: score = likelihood x impact.
export type Level = 'Low' | 'Medium' | 'High'

export const BANDS: Record<Level, [number, number]> = { Low: [1, 7], Medium: [8, 14], High: [15, 25] }

export const score = (likelihood: number, impact: number) => likelihood * impact

export const level = (s: number): Level => (s >= 15 ? 'High' : s >= 8 ? 'Medium' : 'Low')

export const LEVEL_STYLE: Record<Level, string> = {
  Low: 'bg-low-soft text-low',
  Medium: 'bg-med-soft text-med',
  High: 'bg-high-soft text-high',
}

export const LIKELIHOOD = ['Rare', 'Unlikely', 'Possible', 'Likely', 'Almost certain']
export const IMPACT = ['Negligible', 'Minor', 'Moderate', 'Major', 'Severe']

export interface Risk {
  id: string
  org_id: string
  seq: number
  source_ref: string | null
  date_identified: string
  description: string
  consequence: string
  category: string
  likelihood: number
  impact: number
  inherent_score: number
  inherent_level: Level
  existing_controls: string
  strategy: string
  mitigation: string
  owner: string
  target_date: string | null
  status: string
  residual_likelihood: number | null
  residual_impact: number | null
  residual_score: number | null
  residual_level: Level | null
  last_reviewed: string | null
}

export const riskRef = (seq: number) => `RISK-${String(seq).padStart(3, '0')}`

// The risk you actually carry today: residual once assessed, otherwise inherent.
export const currentScore = (r: Pick<Risk, 'inherent_score' | 'residual_score'>) => r.residual_score ?? r.inherent_score

const CSV_COLUMNS: [string, (r: Risk) => string | number | null][] = [
  ['Risk ID', (r) => riskRef(r.seq)],
  ['Date Identified', (r) => r.date_identified],
  ['Risk Description', (r) => r.description],
  ['Consequence', (r) => r.consequence],
  ['Category', (r) => r.category],
  ['Likelihood (1-5)', (r) => r.likelihood],
  ['Impact (1-5)', (r) => r.impact],
  ['Inherent Risk Score', (r) => r.inherent_score],
  ['Inherent Risk Level', (r) => r.inherent_level],
  ['Existing Controls', (r) => r.existing_controls],
  ['Response Strategy', (r) => r.strategy],
  ['Mitigation Actions', (r) => r.mitigation],
  ['Risk Owner', (r) => r.owner],
  ['Target Date', (r) => r.target_date],
  ['Status', (r) => r.status],
  ['Residual Likelihood', (r) => r.residual_likelihood],
  ['Residual Impact', (r) => r.residual_impact],
  ['Residual Risk Score', (r) => r.residual_score],
  ['Residual Risk Level', (r) => r.residual_level],
  ['Last Reviewed', (r) => r.last_reviewed],
]

// Prefixing a quote stops spreadsheets running a cell that starts with a formula character.
export function csvCell(value: string | number | null): string {
  const s = value === null ? '' : String(value)
  const safe = typeof value === 'string' && /^[=+\-@\t\r]/.test(s) ? `'${s}` : s
  return /[",\n\r]/.test(safe) ? `"${safe.replaceAll('"', '""')}"` : safe
}

export const risksToCsv = (rows: Risk[]) =>
  [CSV_COLUMNS.map(([h]) => csvCell(h)).join(','), ...rows.map((r) => CSV_COLUMNS.map(([, f]) => csvCell(f(r))).join(','))].join('\r\n')
