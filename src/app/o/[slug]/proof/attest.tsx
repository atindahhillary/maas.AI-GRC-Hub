'use client'

import { BadgeCheck, ExternalLink } from 'lucide-react'
import Link from 'next/link'
import { useState, useTransition } from 'react'
import { day } from '@/components/ui'
import { issueAttestation, setPublished } from '../actions'

export function IssueButton({ slug }: { slug: string }) {
  const [pending, start] = useTransition()
  const [error, setError] = useState('')
  return (
    <>
      <button disabled={pending} onClick={() => start(async () => { setError((await issueAttestation(slug)).error ?? '') })} className="btn btn-primary w-full"><BadgeCheck className="size-4" /> {pending ? 'Signing' : 'Sign attestation'}</button>
      {error && <p role="alert" className="mt-2 text-xs text-high">{error}</p>}
    </>
  )
}

interface Row { id: string; payload: { provenScore: number; claimedScore: number }; published: boolean; issued_at: string; expires_at: string; key_id: string }

export function AttestationRow({ slug, a, canAdmin }: { slug: string; a: Row; canAdmin: boolean }) {
  const [pending, start] = useTransition()
  const [error, setError] = useState('')
  const expired = new Date(a.expires_at) < new Date()
  return (
    <li className="flex flex-wrap items-center gap-3 py-2.5 text-sm">
      <span className="min-w-52 flex-1">
        <span className="font-medium">Issued {day(a.issued_at)}</span>
        <span className="block text-xs text-faint">Proven {a.payload.provenScore}, claimed {a.payload.claimedScore}, {expired ? 'expired' : 'expires'} {day(a.expires_at)}</span>
      </span>
      {a.published && <Link href={`/trust/${slug}`} target="_blank" className="inline-flex items-center gap-1 text-xs font-semibold text-brand">Trust page <ExternalLink className="size-3" /></Link>}
      {canAdmin && <button disabled={pending} onClick={() => start(async () => { setError((await setPublished(slug, a.id, !a.published)).error ?? '') })} className="btn btn-ghost">{a.published ? 'Unpublish' : 'Publish'}</button>}
      {error && <p role="alert" className="w-full text-xs text-high">{error}</p>}
    </li>
  )
}
