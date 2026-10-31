import { CheckCircle2, CircleAlert, CircleHelp, TriangleAlert, type LucideIcon } from 'lucide-react'
import { Empty, PageHead, Panel, day } from '@/components/ui'
import { atLeast } from '@/lib/access'
import { loadState } from '@/lib/load'
import type { CheckResult, Outcome } from '@/lib/scan/checks'
import { AddDomain, DomainRow } from './domain'

export const metadata = { title: 'Live Tests' }
// A full test makes about 20 outbound requests.
export const maxDuration = 60

const OUTCOME: Record<Outcome, [string, string, LucideIcon]> = {
  pass: ['Pass', 'text-low', CheckCircle2], warn: ['Warning', 'text-med', TriangleAlert],
  fail: ['Fail', 'text-high', CircleAlert], info: ['Check by hand', 'text-soft', CircleHelp],
}

export default async function Tests({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params
  const { supabase, org, role, scan } = await loadState(slug)
  const { data: domains } = await supabase.from('domains').select('id, domain, token, verified_at').eq('org_id', org.id).order('created_at')
  const groups = ['Email', 'Encryption', 'Web', 'Exposure'] as const
  const results: CheckResult[] = scan?.results ?? []
  return (
    <div>
      <PageHead title="Live Tests" sub="Real checks against your public domain. We only test domains you prove you own, and your team cannot edit the results." />
      <div className="grid gap-3 lg:grid-cols-[1fr_1.6fr]">
        <Panel title="Your domains">
          <div className="space-y-3">
            {(domains ?? []).map((d) => <DomainRow key={d.id} slug={slug} domain={d} canAdmin={atLeast(role, 'admin')} canTest={atLeast(role, 'analyst')} />)}
            {atLeast(role, 'admin') && <AddDomain slug={slug} />}
          </div>
        </Panel>
        {scan ? (
          <Panel title={`Results for ${scan.domain}, ${day(scan.created_at)}`} action={<span className="text-sm font-bold tabular-nums">{scan.score} / 100</span>}>
            <div className="space-y-4">
              {groups.map((g) => (
                <section key={g}>
                  <h3 className="eyebrow mb-1.5">{g}</h3>
                  <ul className="divide-y divide-line rounded-lg border border-line">
                    {results.filter((r) => r.group === g).map((r) => {
                      const [label, tone, Icon] = OUTCOME[r.outcome]
                      return (
                        <li key={r.id} className="flex items-start gap-3 px-3 py-2.5 text-sm">
                          <Icon className={`mt-0.5 size-4 shrink-0 ${tone}`} aria-hidden />
                          <span className="min-w-0 flex-1"><span className="font-medium">{r.title}</span><span className="block text-xs text-soft">{r.detail}</span></span>
                          <span className={`shrink-0 text-xs font-semibold ${tone}`}>{label}</span>
                        </li>
                      )
                    })}
                  </ul>
                </section>
              ))}
            </div>
            <p className="mt-3 text-xs text-faint">These are external checks of what is publicly visible. They do not replace a penetration test.</p>
          </Panel>
        ) : <Empty title="No test yet"><p>Add your domain, prove you own it with one DNS record, then run your first test. It takes under a minute.</p></Empty>}
      </div>
    </div>
  )
}
