'use client'

import { Globe, Radar, ShieldCheck } from 'lucide-react'
import { useActionState, useState, useTransition } from 'react'
import { addDomain, runScan, verifyDomain } from '../actions'

export function AddDomain({ slug }: { slug: string }) {
  const [state, action, pending] = useActionState(addDomain.bind(null, slug), {})
  return (
    <form action={action} className="flex flex-wrap items-end gap-2">
      <label className="block min-w-40 flex-1 text-sm font-medium">Add a domain
        <input name="domain" required placeholder="example.org" className="input mt-1" />
      </label>
      <button disabled={pending} className="btn btn-ghost">Add</button>
      {state.error && <p role="alert" className="w-full text-sm text-high">{state.error}</p>}
    </form>
  )
}

export function DomainRow({ slug, domain: d, canAdmin, canTest }: { slug: string; domain: { id: string; domain: string; token: string; verified_at: string | null }; canAdmin: boolean; canTest: boolean }) {
  const [message, setMessage] = useState('')
  const [pending, start] = useTransition()
  const run = (fn: () => Promise<{ error?: string; ok?: string }>) => start(async () => {
    setMessage('Working, this can take about 30 seconds.')
    const res = await fn()
    setMessage(res.error ?? res.ok ?? '')
  })
  return (
    <div className="rounded-lg border border-line p-3">
      <div className="flex items-center justify-between gap-2">
        <span className="flex min-w-0 items-center gap-2 text-sm font-semibold"><Globe className="size-4 shrink-0 text-faint" /><span className="truncate">{d.domain}</span></span>
        {d.verified_at
          ? <span className="inline-flex items-center gap-1 text-xs font-semibold text-low"><ShieldCheck className="size-3.5" /> Verified</span>
          : <span className="text-xs font-semibold text-med">Unverified</span>}
      </div>
      {!d.verified_at && (
        <div className="mt-2 text-xs text-soft">
          <p>Add this TXT record at your DNS provider:</p>
          <dl className="mt-1 grid grid-cols-[auto_1fr] gap-x-2 rounded-md bg-sunk p-2 font-mono">
            <dt className="text-faint">Name</dt><dd className="break-all">_maas-verify.{d.domain}</dd>
            <dt className="text-faint">Value</dt><dd className="break-all">maas-verify={d.token}</dd>
          </dl>
          {canAdmin && <button disabled={pending} onClick={() => run(() => verifyDomain(slug, d.id))} className="btn btn-primary mt-2">{pending ? 'Checking' : 'Verify ownership'}</button>}
        </div>
      )}
      {d.verified_at && canTest && <button disabled={pending} onClick={() => run(() => runScan(slug, d.id))} className="btn btn-primary mt-2 w-full"><Radar className="size-4" /> {pending ? 'Testing, about 30 seconds' : 'Run live test'}</button>}
      <p role="status" className="mt-2 text-xs text-soft empty:hidden">{message}</p>
    </div>
  )
}
