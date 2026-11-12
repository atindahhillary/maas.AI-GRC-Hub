'use client'

import { Eye, EyeOff } from 'lucide-react'
import Link from 'next/link'
import { useEffect, useRef, useState } from 'react'
import { supabaseBrowser } from '@/lib/supabase/browser'
import { Logo } from './ui'

// Only same-site paths, so a crafted link cannot bounce a user off to another site.
export function safeNext(next?: string) {
  const base = 'https://app.invalid'
  try {
    return next?.startsWith('/') && new URL(next, base).origin === base ? next : '/app'
  } catch {
    return '/app'
  }
}

// Beta: no login. Each browser gets a Supabase anonymous user, so RLS and the ledger still hold.
// Runs in the browser so Supabase rate-limits per visitor IP, not per Vercel server IP.
// Bot check: with a Turnstile site key set, Supabase only accepts the sign-in with a fresh Turnstile token.
const TURNSTILE_KEY = process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY
type Turnstile = { render: (el: HTMLElement, o: { sitekey: string; callback: (t: string) => void; 'error-callback': () => void }) => void }

export function GuestStart({ next }: { next?: string }) {
  const [error, setError] = useState('')
  const box = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const fail = () => setError('Guest access is not available right now. Please try again shortly.')
    const start = (captchaToken?: string) =>
      supabaseBrowser().auth.signInAnonymously(captchaToken ? { options: { captchaToken } } : undefined).then(({ error }) => {
        if (error) fail()
        else location.replace(safeNext(next))
      })
    if (!TURNSTILE_KEY) { start(); return }
    const script = document.createElement('script')
    script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'
    script.onload = () => (window as unknown as { turnstile: Turnstile }).turnstile.render(box.current!, { sitekey: TURNSTILE_KEY, callback: start, 'error-callback': fail })
    script.onerror = fail
    document.head.append(script)
  }, [next])
  return (
    <main className="grid min-h-dvh place-items-center px-5">
      <div className="text-center">
        <Logo />
        {error ? <p role="alert" className="mt-6 text-sm text-high">{error}</p> : <p className="mt-6 text-soft">Checking you are human, then opening your guest workspace</p>}
        <div ref={box} className="mt-4 flex justify-center" />
      </div>
    </main>
  )
}

export function AuthForm({ mode, next, notice }: { mode: 'signin' | 'signup'; next?: string; notice?: string }) {
  const [error, setError] = useState('')
  const [sent, setSent] = useState(false)
  const [busy, setBusy] = useState(false)
  const [show, setShow] = useState(false)
  const signup = mode === 'signup'

  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault()
    setBusy(true)
    setError('')
    const form = new FormData(e.currentTarget)
    const email = String(form.get('email'))
    const password = String(form.get('password'))
    const supabase = supabaseBrowser()
    if (signup) {
      const { data, error } = await supabase.auth.signUp({
        email, password,
        options: { emailRedirectTo: `${location.origin}/auth/callback?next=${encodeURIComponent(safeNext(next))}` },
      })
      if (error) { setError(error.message); setBusy(false); return }
      if (data.session) { location.href = safeNext(next); return }
      setSent(true)
    } else {
      const { error } = await supabase.auth.signInWithPassword({ email, password })
      if (error) { setError('Those details did not match.'); setBusy(false); return }
      location.href = safeNext(next)
      return
    }
    setBusy(false)
  }

  return (
    <main className="grid min-h-dvh lg:grid-cols-2">
      <section className="hidden flex-col justify-between border-r border-line bg-rail p-10 lg:flex">
        <Logo />
        <blockquote className="max-w-md text-3xl font-bold leading-tight tracking-tight">
          Your customers do not need another promise. They need something they can check.
        </blockquote>
        <p className="text-sm text-faint">Every organization gets its own isolated workspace.</p>
      </section>
      <section className="grid place-items-center px-5 py-10">
        <div className="w-full max-w-sm">
          <div className="mb-8 lg:hidden"><Logo /></div>
          {sent ? (
            <div className="rise">
              <h1 className="text-3xl">Check your email</h1>
              <p className="mt-2 text-soft">We sent a confirmation link. Open it to activate your account.</p>
            </div>
          ) : (
            <form onSubmit={submit} className="rise space-y-4">
              <div>
                <h1 className="text-3xl">{signup ? 'Create your account' : 'Welcome back'}</h1>
                <p className="mt-1 text-soft">{signup ? 'You will set up your organization next.' : 'Sign in to your workspace.'}</p>
              </div>
              {notice && <p className="rounded-lg bg-brand-soft px-3 py-2 text-sm text-brand">{notice}</p>}
              <label className="block text-sm font-medium">Work email
                <input name="email" type="email" required autoComplete="email" className="input mt-1" />
              </label>
              <div className="text-sm font-medium">
                <label htmlFor="password">Password</label>
                <span className="relative mt-1 block">
                  <input id="password" aria-describedby={signup ? 'password-hint' : undefined} name="password" type={show ? 'text' : 'password'} required minLength={12} autoComplete={signup ? 'new-password' : 'current-password'} className="input pr-10" />
                  <button type="button" onClick={() => setShow(!show)} aria-label={show ? 'Hide password' : 'Show password'} className="absolute inset-y-0 right-0 grid w-10 place-items-center text-faint hover:text-ink">
                    {show ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
                  </button>
                </span>
                {signup && <span id="password-hint" className="mt-1 block text-xs font-normal text-faint">At least 12 characters.</span>}
              </div>
              {error && <p role="alert" className="text-sm text-high">{error}</p>}
              <button disabled={busy} className="btn btn-primary w-full py-2.5">{busy ? 'One moment' : signup ? 'Create account' : 'Sign in'}</button>
              {signup && <p className="text-center text-xs text-faint">By creating an account you accept our <Link href="/privacy" className="font-semibold text-brand">privacy notice</Link>. This is a beta, so please send us feedback.</p>}
              <p className="text-center text-sm text-soft">
                {signup ? 'Already have an account?' : 'New here?'}{' '}
                <Link href={`${signup ? '/signin' : '/signup'}${next ? `?next=${encodeURIComponent(next)}` : ''}`} className="font-semibold text-brand">{signup ? 'Sign in' : 'Create an account'}</Link>
              </p>
            </form>
          )}
        </div>
      </section>
    </main>
  )
}
