'use client'

import { useState } from 'react'
import { supabaseBrowser } from '@/lib/supabase/browser'
import { safeNext } from '@/components/auth-form'
import { Logo } from '@/components/ui'

export default function Mfa() {
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault()
    setBusy(true)
    setError('')
    const code = String(new FormData(e.currentTarget).get('code')).replace(/\s/g, '')
    const supabase = supabaseBrowser()
    const { data } = await supabase.auth.mfa.listFactors()
    const factor = data?.totp[0]
    if (!factor) { location.href = '/app'; return }
    const { error } = await supabase.auth.mfa.challengeAndVerify({ factorId: factor.id, code })
    if (error) { setError('That code did not work. Try the next one.'); setBusy(false); return }
    location.href = safeNext(new URLSearchParams(location.search).get('next') ?? undefined)
  }

  return (
    <main className="grid min-h-dvh place-items-center px-5">
      <form onSubmit={submit} className="w-full max-w-sm space-y-4">
        <Logo />
        <h1 className="text-3xl">Enter your code</h1>
        <p className="text-soft">Open your authenticator app for the 6-digit code.</p>
        <input name="code" required inputMode="numeric" autoComplete="one-time-code" pattern="[0-9 ]{6,7}" aria-label="6-digit code" className="input text-center text-xl tracking-[0.3em]" />
        {error && <p role="alert" className="text-sm text-high">{error}</p>}
        <button disabled={busy} className="btn btn-primary w-full py-2.5">Verify</button>
      </form>
    </main>
  )
}
