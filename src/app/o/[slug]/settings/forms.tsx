'use client'

import { useActionState, useEffect, useState, useTransition } from 'react'
import { CopyButton } from '@/components/copy'
import { supabaseBrowser } from '@/lib/supabase/browser'
import { createInvite, removeMember, updateProfile } from '../actions'

export function ProfileForm({ slug, name, disabled, children }: { slug: string; name: string; disabled: boolean; children: React.ReactNode }) {
  const [state, action, pending] = useActionState(updateProfile.bind(null, slug), {})
  return (
    <form action={action} className="space-y-5">
      <fieldset disabled={disabled} className="space-y-5">
        <label className="block text-sm font-semibold">Organization name
          <input name="name" defaultValue={name} required minLength={2} className="input mt-2" />
        </label>
        {children}
        <button disabled={pending} className="btn btn-primary">{pending ? 'Saving' : 'Save profile'}</button>
      </fieldset>
      {state.error && <p role="alert" className="text-sm text-high">{state.error}</p>}
      <p role="status" className="text-sm text-low empty:hidden">{state.ok}</p>
    </form>
  )
}

export function InviteForm({ slug }: { slug: string }) {
  const [state, action, pending] = useActionState(createInvite.bind(null, slug), {})
  const link = state.ok && typeof location !== 'undefined' ? `${location.origin}${state.ok}` : ''
  return (
    <form action={action} className="mt-3 space-y-2">
      <label className="block text-sm font-medium">Colleague's email
        <input name="email" type="email" required placeholder="colleague@example.org" className="input mt-1" />
      </label>
      <div className="flex gap-2">
        <select name="role" aria-label="Role" defaultValue="analyst" className="input">
          <option value="viewer">Viewer, read only</option>
          <option value="analyst">Analyst, can edit</option>
          <option value="admin">Admin, can manage</option>
        </select>
        <button disabled={pending} className="btn btn-ghost">Invite</button>
      </div>
      {state.error && <p role="alert" className="text-sm text-high">{state.error}</p>}
      {link && (
        <div className="relative rounded-lg bg-sunk p-3 pr-16 text-xs">
          <p className="font-semibold">Send this link. It is shown only once.</p>
          <p className="mt-1 break-all font-mono text-soft">{link}</p>
          <CopyButton text={link} />
        </div>
      )}
    </form>
  )
}

export function MemberRemove({ slug, userId }: { slug: string; userId: string }) {
  const [pending, start] = useTransition()
  const [error, setError] = useState('')
  return (
    <span className="shrink-0 text-right">
      <button disabled={pending} onClick={() => { if (confirm('Remove this person from the organization?')) start(async () => { setError((await removeMember(slug, userId)).error ?? '') }) }} className="text-xs font-medium text-faint hover:text-high">Remove</button>
      {error && <span role="alert" className="block text-xs text-high">{error}</span>}
    </span>
  )
}

export function Mfa() {
  const [enabled, setEnabled] = useState<boolean | null>(null)
  const [enroll, setEnroll] = useState<{ id: string; qr: string; secret: string } | null>(null)
  const [error, setError] = useState('')
  const [pending, start] = useTransition()
  const supabase = supabaseBrowser()

  useEffect(() => {
    supabase.auth.mfa.listFactors().then(({ data }) => setEnabled((data?.totp.length ?? 0) > 0))
  }, [])

  const begin = () => start(async () => {
    const { data, error } = await supabase.auth.mfa.enroll({ factorType: 'totp' })
    if (error) { setError(error.message); return }
    setEnroll({ id: data.id, qr: data.totp.qr_code, secret: data.totp.secret })
  })

  const confirm = (form: FormData) => start(async () => {
    const { error } = await supabase.auth.mfa.challengeAndVerify({ factorId: enroll!.id, code: String(form.get('code')).replace(/\s/g, '') })
    if (error) { setError('That code did not work. Try the next one.'); return }
    setEnroll(null)
    setEnabled(true)
  })

  if (enabled) return <p className="rounded-lg bg-low-soft px-3 py-2 text-sm text-low">Two-factor sign-in is on for this account.</p>
  return (
    <div className="text-sm">
      <p className="text-soft">Protect this workspace with an authenticator app.</p>
      {!enroll && <button disabled={pending || enabled === null} onClick={begin} className="btn btn-primary mt-2">Turn on two-factor</button>}
      {enroll && (
        <form action={confirm} className="mt-2 space-y-2">
          {/* The QR is an inline SVG data URL returned by Supabase Auth. */}
          <img src={enroll.qr} alt="Authenticator setup QR code" className="size-40 rounded-lg bg-white p-1" />
          <p className="break-all font-mono text-xs text-faint">{enroll.secret}</p>
          <label className="block text-sm font-medium">6-digit code
            <input name="code" required inputMode="numeric" autoComplete="one-time-code" className="input mt-1" />
          </label>
          <button disabled={pending} className="btn btn-primary">Confirm</button>
        </form>
      )}
      {error && <p role="alert" className="mt-2 text-sm text-high">{error}</p>}
    </div>
  )
}
