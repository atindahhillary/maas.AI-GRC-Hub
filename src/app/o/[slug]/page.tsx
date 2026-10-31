import { ArrowDownRight, ArrowUpRight, CheckCircle2, ClipboardCheck, FileCheck2, Fingerprint, Radar, ShieldAlert, Siren, Target, type LucideIcon } from 'lucide-react'
import Link from 'next/link'
import { Donut, Ring, TrendChart } from '@/components/charts'
import { Heatmap } from '@/components/heatmap'
import { LevelBadge, PageHead, Panel } from '@/components/ui'
import { WorldMap } from '@/components/world-map'
import { loadState } from '@/lib/load'
import { regulators } from '@/lib/policy'
import { posture, recommendations } from '@/lib/posture'
import { currentScore, level, type Risk } from '@/lib/risk'

const EVENT: Record<string, [string, LucideIcon]> = {
  'risks.insert': ['Risk added', ShieldAlert], 'risks.update': ['Risk updated', ShieldAlert], 'risks.delete': ['Risk removed', ShieldAlert],
  'answers.insert': ['Control answered', ClipboardCheck], 'answers.update': ['Answer changed', ClipboardCheck],
  'evidence.insert': ['Evidence hashed', FileCheck2], 'scans.insert': ['Live test run', Radar],
  'policies.insert': ['Policy drafted', FileCheck2], 'policies.update': ['Policy approved', FileCheck2],
  'attestations.insert': ['Attestation signed', Fingerprint], 'attestations.update': ['Trust page changed', Fingerprint],
  'domains.insert': ['Domain added', Radar], 'domains.update': ['Domain verified', Radar], 'domains.delete': ['Domain removed', Radar],
  'members.insert': ['Member joined', CheckCircle2], 'members.update': ['Role changed', CheckCircle2], 'members.delete': ['Member removed', CheckCircle2],
  'invites.insert': ['Invite sent', CheckCircle2], 'invites.update': ['Invite accepted', CheckCircle2], 'invites.delete': ['Invite cancelled', CheckCircle2],
  'orgs.update': ['Profile updated', CheckCircle2],
}

export const metadata = { title: 'Overview' }

function Kpi({ label, value, sub, icon: Icon, tone, href, delta }: { label: string; value: string | number; sub: string; icon: LucideIcon; tone: string; href: string; delta?: { n: number; goodWhenUp: boolean } }) {
  const good = delta && (delta.n > 0) === delta.goodWhenUp
  return (
    <Link href={href} className="card flex items-start justify-between gap-3 p-4 transition hover:border-brand/50">
      <div className="min-w-0">
        <div className="text-xs font-medium text-soft">{label}</div>
        <div className="mt-1 text-3xl font-bold tabular-nums tracking-tight">{value}</div>
        <div className="mt-1 flex items-center gap-1 truncate text-xs text-faint">
          {delta && delta.n !== 0 && (
            <span className={`inline-flex items-center font-semibold ${good ? 'text-low' : 'text-high'}`}>
              <span className="sr-only">{delta.n > 0 ? 'Up ' : 'Down '}</span>{delta.n > 0 ? <ArrowUpRight className="size-3.5" /> : <ArrowDownRight className="size-3.5" />}{Math.abs(delta.n)}
            </span>
          )}
          {sub}
        </div>
      </div>
      <span className={`grid size-10 shrink-0 place-items-center rounded-lg ${tone}`}><Icon className="size-5" aria-hidden /></span>
    </Link>
  )
}

export default async function Overview({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params
  const { supabase, org, states, scan } = await loadState(slug)
  const [{ data: riskRows }, { data: scanRows }, { data: events }] = await Promise.all([
    supabase.from('risks').select('*').eq('org_id', org.id),
    supabase.from('scans').select('score, created_at').eq('org_id', org.id).order('created_at', { ascending: false }).limit(12),
    supabase.from('ledger').select('seq, event, subject, created_at').eq('org_id', org.id).order('seq', { ascending: false }).limit(6),
  ])
  const risks = (riskRows ?? []) as Risk[]
  const live = risks.filter((r) => r.status !== 'Closed')
  const p = posture(states)
  const recs = recommendations(states, scan)
  const high = live.filter((r) => level(currentScore(r)) === 'High')
  const weekAgo = Date.now() - 7 * 86400000
  const newRisks = risks.filter((r) => Date.parse(r.date_identified) >= weekAgo).length
  const scans = (scanRows ?? []).slice().reverse()
  const scanDelta = scans.length > 1 ? scans.at(-1)!.score - scans.at(-2)!.score : 0

  const byCategory = Object.entries(live.reduce<Record<string, number>>((m, r) => ({ ...m, [r.category]: (m[r.category] ?? 0) + 1 }), {}))
    .map(([label, value]) => ({ label, value })).sort((a, b) => b.value - a.value)
  const cells = live.reduce<Record<string, number>>((m, r) => {
    const k = `${r.residual_likelihood ?? r.likelihood}-${r.residual_impact ?? r.impact}`
    return { ...m, [k]: (m[k] ?? 0) + 1 }
  }, {})
  const weakest = p.byDomain.map((d) => ({ ...d, gap: 100 - d.proven })).sort((a, b) => b.gap - a.gap).slice(0, 5)
  const trail = (events ?? []).slice().reverse()

  return (
    <div className="space-y-4">
      <PageHead title="Overview" sub="Real-time security overview of your organization, built only from your own tests, answers and register." />
      {p.answered === 0 && (
        <section className="card flex flex-wrap items-center justify-between gap-3 border-brand/40 p-4">
          <div>
            <h2 className="text-lg">Welcome to {org.name}</h2>
            <p className="text-sm text-soft">Start with the assessment. It takes about an hour and fills this dashboard with your real numbers.</p>
          </div>
          <Link href={`/o/${slug}/assess`} className="btn btn-primary">Start the assessment</Link>
        </section>
      )}

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <Kpi label="Open risks" value={live.length} sub="in the register" icon={ShieldAlert} tone="bg-brand-soft text-brand" href={`/o/${slug}/risks`} delta={newRisks ? { n: newRisks, goodWhenUp: false } : undefined} />
        <Kpi label="High risks" value={high.length} sub={high.length ? 'scored 15 or above' : 'none open'} icon={Siren} tone="bg-high-soft text-high" href={`/o/${slug}/risks`} />
        <Kpi label="Recommendations" value={recs.length} sub="waiting for action" icon={Target} tone="bg-med-soft text-med" href={`/o/${slug}/recommendations`} />
        <Kpi label="Live test score" value={scan?.score ?? '-'} sub={scan ? 'of 100' : 'not run yet'} icon={Radar} tone="bg-violet-soft text-violet" href={`/o/${slug}/tests`} delta={scanDelta ? { n: scanDelta, goodWhenUp: true } : undefined} />
        <Kpi label="Controls proven" value={`${p.provenCount}/${p.total}`} sub="evidence or test" icon={CheckCircle2} tone="bg-low-soft text-low" href={`/o/${slug}/proof`} />
      </div>

      <div className="grid gap-3 xl:grid-cols-[1.2fr_1fr_1.2fr]">
        <Panel title="Live test score over time">
          {scans.length ? <TrendChart unit="score" points={scans.map((s) => ({ value: s.score, label: new Date(s.created_at).toLocaleDateString('en-GB', { day: 'numeric', month: 'short' }) }))} />
            : <p className="grid flex-1 place-items-center py-10 text-center text-sm text-soft">Run your first <Link href={`/o/${slug}/tests`} className="px-1 font-semibold text-brand">live test</Link> to start this line.</p>}
        </Panel>
        <Panel title="Risk distribution">
          {live.length ? <Donut slices={byCategory} total={live.length} centerLabel="Open" />
            : <p className="grid flex-1 place-items-center py-10 text-center text-sm text-soft">Add risks to see where they sit.</p>}
        </Panel>
        <Panel title="Regulatory footprint">
          <WorldMap countries={org.profile.countries} />
          <p className="mt-2 text-xs text-soft">{regulators(org.profile).join(', ')}</p>
        </Panel>
      </div>

      <div className="grid gap-3 xl:grid-cols-[1.2fr_1fr_1.2fr]">
        <Panel title="Priority findings" action={<Link href={`/o/${slug}/recommendations`} className="text-xs font-semibold text-brand">View all</Link>}>
          {recs.length ? (
            <ul className="space-y-2.5">
              {recs.slice(0, 4).map((r) => (
                <li key={r.key} className="flex items-center gap-3">
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium">{r.title}</span>
                    <span className="block truncate text-xs text-faint">{r.source}, {r.fix}</span>
                  </span>
                  <LevelBadge value={level(r.severity)} />
                </li>
              ))}
            </ul>
          ) : <p className="py-8 text-center text-sm text-soft">No open findings yet.</p>}
        </Panel>
        <Panel title="Least proven areas">
          {weakest.length ? (
            <ul className="space-y-3">
              {weakest.map((d) => (
                <li key={d.domain} className="text-xs">
                  <div className="mb-1 flex justify-between"><span className="text-soft">{d.label}</span><span className="font-semibold tabular-nums">{d.proven}%</span></div>
                  <div className="h-2 overflow-hidden rounded-full bg-sunk"><div className="h-full rounded-full bg-[#3987e5]" style={{ width: `${d.proven}%` }} /></div>
                </li>
              ))}
            </ul>
          ) : <p className="py-8 text-center text-sm text-soft">Nothing assessed yet.</p>}
        </Panel>
        <Panel title="Security posture">
          <div className="flex flex-1 flex-wrap items-center gap-5">
            <Ring value={p.proven} label="Proven" />
            <div className="min-w-44 flex-1 text-sm text-soft">
              <p>You claim <strong className="text-ink">{p.claimed}%</strong> and can prove <strong className="text-ink">{p.proven}%</strong>.{p.claimed > p.proven && ' Attach evidence or run a test to close the gap.'}</p>
              <Link href={`/o/${slug}/recommendations`} className="btn btn-primary mt-3">View recommendations</Link>
            </div>
          </div>
        </Panel>
      </div>

      <div className="grid gap-3 xl:grid-cols-[1fr_2.4fr]">
        <Panel title="Risk matrix"><Heatmap counts={cells} /></Panel>
        <Panel title="Security events timeline" action={<Link href={`/o/${slug}/proof`} className="text-xs font-semibold text-brand">Full ledger</Link>}>
          {trail.length ? (
            <ol className="relative grid flex-1 grid-cols-2 gap-4 sm:grid-cols-3 2xl:grid-cols-6">
              {trail.map((e) => {
                const [label, Icon] = EVENT[e.event] ?? [e.event, Fingerprint]
                return (
                  <li key={e.seq} className="min-w-0 text-center text-xs">
                    <span className="mx-auto grid size-8 place-items-center rounded-full bg-brand-soft text-brand"><Icon className="size-4" aria-hidden /></span>
                    <div className="mt-2 text-faint">{new Date(e.created_at).toLocaleString('en-GB', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })}</div>
                    <div className="truncate font-medium">{label}</div>
                    {e.subject.length <= 20 && <div className="truncate text-faint">{e.subject}</div>}
                  </li>
                )
              })}
            </ol>
          ) : <p className="py-8 text-center text-sm text-soft">Every change you make is recorded here.</p>}
        </Panel>
      </div>
    </div>
  )
}
