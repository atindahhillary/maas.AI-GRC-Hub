import { atLeast } from '@/lib/access'
import { loadState } from '@/lib/load'
import type { Risk } from '@/lib/risk'
import { RiskRegister } from './register'

export const metadata = { title: 'Risk Register' }

export default async function Risks({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params
  const { supabase, org, role } = await loadState(slug)
  const { data } = await supabase.from('risks').select('*').eq('org_id', org.id).order('seq')
  return <RiskRegister slug={slug} risks={(data ?? []) as Risk[]} canWrite={atLeast(role, 'analyst')} canDelete={atLeast(role, 'admin')} />
}
