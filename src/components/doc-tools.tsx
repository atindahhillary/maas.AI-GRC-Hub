'use client'

import { Download, Printer } from 'lucide-react'

export const PrintButton = () => <button onClick={() => window.print()} className="btn btn-ghost"><Printer className="size-4" /> Print or PDF</button>

export function SaveMarkdown({ name, text }: { name: string; text: string }) {
  return (
    <button className="btn btn-ghost" onClick={() => {
      const url = URL.createObjectURL(new Blob([text], { type: 'text/markdown' }))
      const a = document.createElement('a')
      a.href = url
      a.download = name
      a.click()
      URL.revokeObjectURL(url)
    }}><Download className="size-4" /> Markdown</button>
  )
}
