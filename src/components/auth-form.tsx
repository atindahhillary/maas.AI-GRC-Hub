'use client'

import { Eye, EyeOff } from 'lucide-react'
import Link from 'next/link'
import { useState } from 'react'
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
