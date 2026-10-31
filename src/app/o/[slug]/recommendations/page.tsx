import { CheckCircle2 } from 'lucide-react'
import Link from 'next/link'
import { Empty, LevelBadge, PageHead, ScoreChip } from '@/components/ui'
import { atLeast } from '@/lib/access'
import { loadState } from '@/lib/load'
import { recommendations } from '@/lib/posture'
import { level } from '@/lib/risk'
import { RaiseButton } from './raise'

export const metadata = { title: 'Recommendations' }

export default async function Recommendations({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params
  const { supabase, org, role, states, scan } = await loadState(slug)
  const recs = recommendations(states, scan)
  const { data } = await supabase.from('risks').select('source_ref').eq('org_id', org.id).not('source_ref', 'is', null)
  const raised = new Set((data ?? []).map((r) => r.source_ref))
  return (
    <div>
      <PageHead title="Recommendations" sub="Everything your assessment and live tests found, biggest risk first. When two are equal, the quicker fix comes first." />
      {recs.length === 0 ? (
        <Empty title="Nothing to fix yet"><p>Complete the <Link href={`/o/${slug}/assess`} className="font-semibold text-brand">assessment</Link> or run a <Link href={`/o/${slug}/tests`} className="font-semibold text-brand">live test</Link> to get recommendations.</p></Empty>
      ) : (
        <ol className="space-y-2">
          {recs.map((r) => (
            <li key={r.key} tabIndex={-1} className="card flex flex-wrap items-start gap-4 p-4">
              <ScoreChip score={r.severity} />
              <div className="min-w-60 flex-1">
                <div className="flex flex-wrap items-center gap-2"><h2 className="text-sm font-semibold tracking-normal">{r.title}</h2><LevelBadge value={level(r.severity)} /></div>
                <p className="mt-1 text-sm text-soft">{r.fix}</p>
                <p className="mt-1 text-xs text-faint">{r.source}. Effort: {r.effort}. {r.why}</p>
              </div>
              {raised.has(r.key)
                ? <span className="inline-flex items-center gap-1.5 text-sm font-medium text-low"><CheckCircle2 className="size-4" /> In register</span>
                : atLeast(role, 'analyst') && <RaiseButton slug={slug} recKey={r.key} />}
            </li>
          ))}
        </ol>
      )}
    </div>
  )
}
