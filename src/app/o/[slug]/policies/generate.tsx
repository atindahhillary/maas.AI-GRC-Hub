'use client'

import { useState, useTransition } from 'react'
import { approvePolicy, generatePolicy } from '../actions'

export function GenerateButton({ slug, templateId, label, primary }: { slug: string; templateId: string; label: string; primary: boolean }) {
  const [pending, start] = useTransition()
  const [error, setError] = useState('')
  return (
    <>
      <button disabled={pending} onClick={() => start(async () => { setError((await generatePolicy(slug, templateId)).error ?? '') })} className={`btn ${primary ? 'btn-primary' : 'btn-ghost'}`}>{pending ? 'Writing' : label}</button>
      {error && <p role="alert" className="text-xs text-high">{error}</p>}
    </>
  )
}

export function ApproveButton({ slug, id }: { slug: string; id: string }) {
  const [pending, start] = useTransition()
  const [error, setError] = useState('')
  return (
    <>
      <button disabled={pending} className="btn btn-primary" onClick={() => {
        if (confirm('Approve this policy? Your name, the time and a hash of the text are recorded permanently.')) start(async () => { setError((await approvePolicy(slug, id)).error ?? '') })
      }}>{pending ? 'Approving' : 'Approve'}</button>
      {error && <p role="alert" className="text-xs text-high">{error}</p>}
    </>
  )
}
