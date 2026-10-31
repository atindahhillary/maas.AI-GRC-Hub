import { notFound, redirect } from 'next/navigation'
import { cache } from 'react'
import type { OrgProfile } from './content/types'
import { supabaseServer } from './supabase/server'

export type Role = 'owner' | 'admin' | 'analyst' | 'viewer'
export interface Org { id: string; slug: string; name: string; profile: OrgProfile }

const RANK: Record<Role, number> = { viewer: 0, analyst: 1, admin: 2, owner: 3 }
export const atLeast = (role: Role, min: Role) => RANK[role] >= RANK[min]

// Loads the org through RLS, so a non-member simply gets a 404.
export const orgContext = cache(async (slug: string) => {
  const supabase = await supabaseServer()
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) redirect('/signin')
  const { data: aal } = await supabase.auth.mfa.getAuthenticatorAssuranceLevel()
  if (aal?.nextLevel === 'aal2' && aal.currentLevel !== 'aal2') redirect(`/signin/mfa?next=/o/${slug}`)
  const { data: org } = await supabase.from('orgs').select('id, slug, name, profile').eq('slug', slug).maybeSingle()
  if (!org) notFound()
  const { data: member } = await supabase.from('members').select('role').eq('org_id', org.id).eq('user_id', user.id).single()
  return { supabase, user, org: org as Org, role: member!.role as Role }
})

export class RoleError extends Error {}

export async function requireRole(slug: string, min: Role) {
  const ctx = await orgContext(slug)
  if (!atLeast(ctx.role, min)) throw new RoleError('Your role does not allow this action.')
  return ctx
}
