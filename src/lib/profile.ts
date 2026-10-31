import type { Budget, DataType, OrgProfile, OrgSize, Platform, Sector } from './content/types'

export const SECTORS: [Sector, string][] = [['finance', 'Finance and insurance'], ['health', 'Healthcare'], ['education', 'Education'], ['ngo', 'NGO or foundation'], ['government', 'Government'], ['retail', 'Retail and e-commerce'], ['tech', 'Technology'], ['logistics', 'Logistics'], ['other', 'Something else']]
export const SIZES: OrgSize[] = ['1-10', '11-50', '51-250', '251-1000', '1000+']
export const DATA_TYPES: [DataType, string][] = [['personal', 'Personal data'], ['health', 'Health records'], ['financial', 'Financial records'], ['children', "Children's data"], ['ip', 'Intellectual property']]
export const PLATFORMS: [Platform, string][] = [['m365', 'Microsoft 365'], ['google_workspace', 'Google Workspace'], ['aws', 'AWS'], ['azure', 'Azure'], ['gcp', 'Google Cloud'], ['on_prem', 'Own servers']]
export const BUDGETS: [Budget, string, string][] = [['minimal', 'Minimal', 'Free and open source first'], ['moderate', 'Moderate', 'Some paid tools'], ['substantial', 'Substantial', 'Managed services']]

const oneOf = <T extends string>(v: FormDataEntryValue | null, allowed: readonly T[]) => (allowed.includes(v as T) ? (v as T) : null)
const someOf = <T extends string>(form: FormData, name: string, allowed: readonly T[]) => form.getAll(name).filter((v) => allowed.includes(v as T)) as T[]

// Untrusted form input becomes a profile only if every value is one we know.
export function parseProfile(form: FormData): OrgProfile | null {
  const sector = oneOf(form.get('sector'), SECTORS.map(([k]) => k))
  const size = oneOf(form.get('size'), SIZES)
  const budget = oneOf(form.get('budget'), BUDGETS.map(([k]) => k))
  if (!sector || !size || !budget) return null
  return {
    sector, size, budget,
    countries: form.getAll('countries').map(String).filter((c) => /^[A-Z]{2}$/.test(c)).slice(0, 20),
    dataTypes: someOf(form, 'dataTypes', DATA_TYPES.map(([k]) => k)),
    platforms: someOf(form, 'platforms', PLATFORMS.map(([k]) => k)),
    usesAI: form.get('usesAI') === 'on',
    buildsAI: form.get('buildsAI') === 'on',
    hasSecurityLead: form.get('hasSecurityLead') === 'on',
  }
}
