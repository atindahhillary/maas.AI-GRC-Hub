'use client'

import { useState } from 'react'

export function CopyButton({ text }: { text: string }) {
  const [done, setDone] = useState(false)
  return (
    <button type="button" onClick={async () => { await navigator.clipboard.writeText(text); setDone(true); setTimeout(() => setDone(false), 1500) }}
      className="absolute right-2 top-2 rounded-md border border-line bg-card px-2 py-1 text-xs font-medium text-soft hover:text-ink">
      <span aria-live="polite">{done ? 'Copied' : 'Copy'}</span>
    </button>
  )
}
