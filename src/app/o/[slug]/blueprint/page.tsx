import { PageHead } from '@/components/ui'
import { loadState } from '@/lib/load'
import { blueprintFor } from '@/lib/posture'

export const metadata = { title: 'Custom System' }

export default async function Blueprint({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params
  const { org } = await loadState(slug)
  const layers = blueprintFor(org.profile)
  const phases = [...new Set(layers.map((l) => l.phase))]
  return (
    <div>
      <PageHead title="Your Custom Security System" sub={`A phased design for ${org.name}, built from your size, sector, platforms and ${org.profile.budget} budget. Change your profile in Settings and this updates. Costs are rough estimates.`} />
      <div className="space-y-5">
        {phases.map((phase) => (
          <section key={phase}>
            <h2 className="mb-2 text-base">First {phase} days</h2>
            <ul className="grid gap-3 lg:grid-cols-2 xl:grid-cols-3">
              {layers.filter((l) => l.phase === phase).map((l) => (
                <li key={l.id} className="card flex flex-col p-4">
                  <h3 className="text-sm font-semibold tracking-normal">{l.title}</h3>
                  <p className="mt-1 text-sm text-soft">{l.outcome}</p>
                  <p className="mt-3 text-sm">{l.chosen.approach}</p>
                  <div className="mt-auto flex flex-wrap items-end justify-between gap-2 pt-3 text-xs">
                    <span className="text-faint">{l.chosen.examples.join(', ')}</span>
                    <span className="font-semibold tabular-nums text-soft">{l.chosen.monthlyCostUsd}</span>
                  </div>
                </li>
              ))}
            </ul>
          </section>
        ))}
      </div>
      <p className="mt-5 text-xs text-faint">Product names are examples, not endorsements. Check current pricing before buying.</p>
    </div>
  )
}
