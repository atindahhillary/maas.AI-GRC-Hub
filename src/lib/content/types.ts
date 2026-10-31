// Shared contract between the expert-authored content and the app.

export type Sector = 'finance' | 'health' | 'education' | 'ngo' | 'government' | 'retail' | 'tech' | 'logistics' | 'other'
export type OrgSize = '1-10' | '11-50' | '51-250' | '251-1000' | '1000+'
export type Budget = 'minimal' | 'moderate' | 'substantial'
export type DataType = 'personal' | 'health' | 'financial' | 'children' | 'ip'
export type Platform = 'aws' | 'azure' | 'gcp' | 'm365' | 'google_workspace' | 'on_prem'

export interface OrgProfile {
  sector: Sector
  size: OrgSize
  countries: string[] // ISO 3166-1 alpha-2, e.g. ['KE', 'UG']
  dataTypes: DataType[]
  platforms: Platform[]
  usesAI: boolean // staff use AI tools such as ChatGPT or Copilot
  buildsAI: boolean // the org builds or ships AI features or agents
  hasSecurityLead: boolean
  budget: Budget
}

export type Applies = (p: OrgProfile) => boolean

export type Domain =
  | 'governance' | 'identity' | 'data' | 'endpoint' | 'network' | 'cloud'
  | 'appsec' | 'vendor' | 'people' | 'incident' | 'resilience' | 'ai'

export type RiskCategory =
  | 'Security' | 'Third-Party' | 'Operational' | 'Compliance' | 'Privacy' | 'AI' | 'Strategic'

export type Strategy = 'Mitigate' | 'Accept' | 'Transfer' | 'Avoid'

// Same shape as a row of the risk register: scores are 1 to 5, score = likelihood x impact.
export interface RiskTemplate {
  description: string
  consequence: string
  category: RiskCategory
  likelihood: 1 | 2 | 3 | 4 | 5
  impact: 1 | 2 | 3 | 4 | 5
  strategy: Strategy
  mitigation: string
}

export interface FrameworkRefs {
  iso27001?: string[] // Annex A 2022 ids, e.g. 'A.5.15'
  nistCsf?: string[] // CSF 2.0 ids, e.g. 'PR.AA-05'
  cisV8?: string[] // safeguard ids, e.g. '6.3'
  kenyaDpa?: string[] // Data Protection Act 2019 sections, e.g. 's.41'
  gdpr?: string[] // e.g. 'Art. 32'
  nistAiRmf?: string[] // e.g. 'GOVERN 1.1'
  iso42001?: string[] // e.g. 'A.6.2.4'
  euAiAct?: string[] // e.g. 'Art. 14'
}

export interface Control {
  id: string // e.g. 'IAM-02'
  domain: Domain
  title: string
  question: string // plain English, answerable by a non-specialist manager
  why: string // business reason in one or two sentences
  howToFix: string // concrete first steps
  weight: 1 | 2 | 3 // 3 means a failure commonly leads to a serious incident
  evidenceExamples: string[] // what an auditor would accept
  effort: 'hours' | 'days' | 'weeks' | 'months'
  frameworks: FrameworkRefs
  risk: RiskTemplate
  appliesIf?: Applies // omitted means every organization
}

// One SMART commitment inside a policy.
export interface PolicyClause {
  statement: string // Specific: what must happen
  metric: string // Measurable: how it is checked
  target: string // Achievable: the number to hit, may use {tokens}
  ownerRole: string // who is accountable
  relevance: string // Relevant: the risk or duty this addresses
  dueDays: number // Time-bound: days from approval to first compliance
  controls: string[] // Control ids this clause supports
}

export interface PolicySection {
  heading: string
  body?: string // may use {tokens}
  clauses: PolicyClause[]
  appliesIf?: Applies
}

export interface PolicyTemplate {
  id: string // e.g. 'ai-acceptable-use'
  title: string
  summary: string
  kind: 'security' | 'ai' | 'privacy'
  reviewMonths: number
  purpose: string // may use {tokens}
  scope: string // may use {tokens}
  sections: PolicySection[]
  appliesIf?: Applies
}

export interface Guardrail {
  id: string
  title: string
  kind: 'email' | 'web' | 'identity' | 'cloud' | 'endpoint' | 'data' | 'ai'
  problem: string
  action: string
  // Paste-ready snippet. {domain} is replaced with the org's verified domain.
  snippet?: { language: string; code: string }
  verify: string // how the org proves it is working
  triggers: string[] // Control ids or scan check ids that surface this guardrail
  appliesIf?: Applies
}

export interface BlueprintLayer {
  id: string
  title: string
  outcome: string
  // Vendor-neutral capability with example products per budget tier.
  options: Record<Budget, { approach: string; examples: string[]; monthlyCostUsd: string }>
  phase: 30 | 60 | 90 | 180
  controls: string[]
  appliesIf?: Applies
}

// Tokens available in policy text.
export const POLICY_TOKENS = ['{org}', '{sector}', '{regulators}', '{countries}', '{dataTypes}', '{securityOwner}'] as const
