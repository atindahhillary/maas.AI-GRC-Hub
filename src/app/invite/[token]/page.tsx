import { redirect } from 'next/navigation'
import { Logo } from '@/components/ui'
import { supabaseServer } from '@/lib/supabase/server'

export const metadata = { title: 'Join your team' }

export default async function Invite({ params, searchParams }: { params: Promise<{ token: string }>; searchParams: Promise<{ invalid?: string }> }) {
  const { token } = await params
  const { invalid } = await searchParams

  async function accept() {
    'use server'
    const supabase = await supabaseServer()
    const { data, error } = await supabase.rpc('accept_invite', { p_token: token })
    redirect(error ? `/invite/${token}?invalid=1` : `/o/${data}`)
  }

  return (
    <main className="mx-auto max-w-md px-5 py-16">
      <Logo />
      <h1 className="mt-8 text-3xl">Join your team</h1>
      <p className="mt-2 text-soft">Accepting adds this account to the organization that invited you. The invite must match the email you signed in with, and it lasts 7 days.</p>
      {invalid && <p role="alert" className="mt-4 text-sm text-high">This invite is not valid for this account, or it has expired.</p>}
      <form action={accept}><button className="btn btn-primary mt-6 px-5 py-3">Accept invite</button></form>
    </main>
  )
}
