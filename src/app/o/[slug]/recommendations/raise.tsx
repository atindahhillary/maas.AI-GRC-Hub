'use client'

import { useState, useTransition } from 'react'
import { raiseRisk } from '../actions'

export function RaiseButton({ slug, recKey }: { slug: string; recKey: string }) {
  const [pending, start] = useTransition()
  const [error, setError] = useState('')
  return (
    <div>
      <button disabled={pending} className="btn btn-ghost" onClick={(e) => {
        const row = e.currentTarget.closest('li')
        start(async () => { setError((await raiseRisk(slug, recKey)).error ?? ''); row?.focus() })
      }}>{pending ? 'Adding' : 'Add to register'}</button>
      {error && <p role="alert" className="mt-1 text-xs text-high">{error}</p>}
    </div>
  )
}
