import { redirect } from 'next/navigation'
import { ProfileFields } from '@/components/profile-fields'
import { Logo } from '@/components/ui'
import { parseProfile } from '@/lib/profile'
import { supabaseServer } from '@/lib/supabase/server'

export const metadata = { title: 'Set up your organization' }

async function createOrg(form: FormData) {
  'use server'
  const name = String(form.get('name') ?? '').trim().slice(0, 120)
  const profile = parseProfile(form)
  if (name.length < 2 || !profile) redirect('/onboarding?error=1')
  const supabase = await supabaseServer()
  const { data, error } = await supabase.rpc('create_org', { p_name: name, p_profile: profile })
  if (error || !data) redirect('/onboarding?error=1')
  redirect(`/o/${data}`)
}

export default async function Onboarding({ searchParams }: { searchParams: Promise<{ error?: string }> }) {
  const { error } = await searchParams
  return (
    <main className="mx-auto max-w-2xl px-5 py-10">
      <Logo />
      <h1 className="mt-8 text-4xl">Tell us who you are</h1>
      <p className="mt-2 text-soft">Two minutes here decides which controls apply, which regulators your policies name, and what your customised system costs.</p>
      <form action={createOrg} className="mt-8 space-y-6">
        <label className="block text-sm font-semibold">Organization name
          <input name="name" required minLength={2} maxLength={120} className="input mt-2" />
        </label>
        <ProfileFields />
        {error && <p role="alert" className="text-sm text-high">Please fill in the name, sector, size and budget.</p>}
        <button className="btn btn-primary px-5 py-3 text-base">Create workspace</button>
      </form>
    </main>
  )
}
