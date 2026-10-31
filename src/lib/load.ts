import { cache } from 'react'
import { requireRole, type Role } from './access'
import { controlStates, type Answer, type EvidenceRow, type ScanRow } from './posture'

// Everything the computed views need, read through RLS.
export const loadState = cache(async (slug: string, min: Role = 'viewer') => {
  const ctx = await requireRole(slug, min)
  const { supabase, org } = ctx
  const [a, e, s] = await Promise.all([
    supabase.from('answers').select('control_id, status, note, updated_at').eq('org_id', org.id),
    supabase.from('evidence').select('id, control_id, name, sha256, size_bytes, created_at, storage_path').eq('org_id', org.id).order('created_at', { ascending: false }),
    supabase.from('scans').select('id, domain, score, results, created_at').eq('org_id', org.id).order('created_at', { ascending: false }).limit(1).maybeSingle(),
  ])
  const scan = s.data as ScanRow | null
  const evidence = (e.data ?? []) as EvidenceRow[]
  return { ...ctx, scan, evidence, states: controlStates(org.profile, (a.data ?? []) as Answer[], evidence, scan) }
})
