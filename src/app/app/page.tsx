import Link from 'next/link'
import { redirect } from 'next/navigation'
import { supabaseServer } from '@/lib/supabase/server'
import { Logo } from '@/components/ui'

export const metadata = { title: 'Choose a workspace' }

// Landing point after sign-in: one org goes straight in, several get a chooser.
export default async function AppHome() {
  const supabase = await supabaseServer()
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) redirect('/signin')
  const { data: aal } = await supabase.auth.mfa.getAuthenticatorAssuranceLevel()
  if (aal?.nextLevel === 'aal2' && aal.currentLevel !== 'aal2') redirect('/signin/mfa')
  const { data } = await supabase.from('members').select('role, orgs(slug, name)').eq('user_id', user.id)
  const orgs = (data ?? []).map((m) => ({ role: m.role, ...(m.orgs as unknown as { slug: string; name: string }) }))
  if (!orgs.length) redirect('/onboarding')
  if (orgs.length === 1) redirect(`/o/${orgs[0].slug}`)
  return (
    <main className="mx-auto max-w-lg px-5 py-16">
      <Logo />
      <h1 className="mt-8 text-3xl">Choose a workspace</h1>
      <ul className="mt-6 space-y-2">
        {orgs.map((o) => (
          <li key={o.slug}><Link href={`/o/${o.slug}`} className="card flex items-center justify-between p-4 font-semibold hover:bg-sunk">{o.name}{' '}<span className="text-sm font-normal capitalize text-soft">{o.role}</span></Link></li>
        ))}
      </ul>
      <Link href="/onboarding" className="btn btn-ghost mt-4">Add an organization</Link>
    </main>
  )
}
