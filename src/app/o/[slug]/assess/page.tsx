import { atLeast } from '@/lib/access'
import { loadState } from '@/lib/load'
import { DOMAIN_LABEL, posture } from '@/lib/posture'
import { Assessment } from './assessment'

export const metadata = { title: 'Assessment' }

export default async function Assess({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params
  const { org, role, states } = await loadState(slug)
  const p = posture(states)
  // Functions in the control library cannot cross to a client component.
  const items = states.map((s) => {
    const { appliesIf: _, ...control } = s.control
    return { ...s, control }
  })
  return <Assessment slug={slug} orgId={org.id} items={items} labels={DOMAIN_LABEL} answered={p.answered} total={p.total} canWrite={atLeast(role, 'analyst')} />
}
