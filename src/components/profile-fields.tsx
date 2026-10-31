import type { OrgProfile } from '@/lib/content/types'
import { COUNTRY_OPTIONS } from '@/lib/policy'
import { BUDGETS, DATA_TYPES, PLATFORMS, SECTORS, SIZES } from '@/lib/profile'

const pill = 'cursor-pointer rounded-lg border border-line bg-card px-3 py-2 text-sm font-medium transition has-checked:border-brand has-checked:bg-brand-soft has-checked:text-brand has-focus-visible:outline-2 has-focus-visible:outline-brand'

function Group({ legend, hint, children }: { legend: string; hint?: string; children: React.ReactNode }) {
  return (
    <fieldset>
      <legend className="text-sm font-semibold">{legend}</legend>
      {hint && <p className="text-xs text-faint">{hint}</p>}
      <div className="mt-2 flex flex-wrap gap-2">{children}</div>
    </fieldset>
  )
}

const Pick = ({ type, name, value, label, checked, required }: { type: 'radio' | 'checkbox'; name: string; value: string; label: string; checked?: boolean; required?: boolean }) => (
  <label className={pill}><input type={type} name={name} value={value} defaultChecked={checked} required={required} className="sr-only" />{label}</label>
)

export function ProfileFields({ profile }: { profile?: OrgProfile }) {
  return (
    <div className="space-y-6">
      <p className="text-xs text-soft">Fields marked * are required.</p>
      <Group legend="What sector are you in? *">
        {SECTORS.map(([v, l]) => <Pick key={v} type="radio" name="sector" value={v} label={l} checked={profile?.sector === v} required />)}
      </Group>
      <Group legend="How many people work there? *">
        {SIZES.map((v) => <Pick key={v} type="radio" name="size" value={v} label={v} checked={profile?.size === v} required />)}
      </Group>
      <Group legend="Where do you operate?" hint="This decides which regulators your policies name.">
        {COUNTRY_OPTIONS.map(([v, l]) => <Pick key={v} type="checkbox" name="countries" value={v} label={l} checked={profile?.countries.includes(v)} />)}
      </Group>
      <Group legend="What data do you hold?">
        {DATA_TYPES.map(([v, l]) => <Pick key={v} type="checkbox" name="dataTypes" value={v} label={l} checked={profile?.dataTypes.includes(v)} />)}
      </Group>
      <Group legend="What do you run on?">
        {PLATFORMS.map(([v, l]) => <Pick key={v} type="checkbox" name="platforms" value={v} label={l} checked={profile?.platforms.includes(v)} />)}
      </Group>
      <Group legend="Tell us about AI and security">
        <Pick type="checkbox" name="usesAI" value="on" label="Staff use AI tools" checked={profile?.usesAI} />
        <Pick type="checkbox" name="buildsAI" value="on" label="We build AI features or agents" checked={profile?.buildsAI} />
        <Pick type="checkbox" name="hasSecurityLead" value="on" label="We have a named security lead" checked={profile?.hasSecurityLead} />
      </Group>
      <Group legend="What is your security budget like? *" hint="Your customised system is priced to match.">
        {BUDGETS.map(([v, l, d]) => <Pick key={v} type="radio" name="budget" value={v} label={`${l}: ${d}`} checked={profile?.budget === v} required />)}
      </Group>
    </div>
  )
}
