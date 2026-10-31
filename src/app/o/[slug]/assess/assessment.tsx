'use client'

import { BadgeCheck, ChevronDown, FileUp, ScanSearch } from 'lucide-react'
import { useState, useTransition } from 'react'
import { PageHead, day } from '@/components/ui'
import type { Control, Domain } from '@/lib/content/types'
import type { Answer, Assurance, EvidenceRow } from '@/lib/posture'
import { supabaseBrowser } from '@/lib/supabase/browser'
import { answerControl, evidenceLink, recordEvidence } from '../actions'

interface Item { control: Omit<Control, 'appliesIf'>; answer?: Answer; assurance: Assurance; evidence: EvidenceRow[] }

const OPTIONS = [['yes', 'Yes', 'bg-low-soft text-low'], ['partial', 'Partly', 'bg-med-soft text-med'], ['no', 'No', 'bg-high-soft text-high'], ['na', 'N/A', 'bg-sunk text-soft']] as const
const ASSURANCE: Record<Assurance, string | null> = { tested: 'Machine tested', evidenced: 'Evidenced', claimed: 'Claimed only', none: null }
const FW: Record<string, string> = { iso27001: 'ISO 27001', nistCsf: 'NIST CSF', cisV8: 'CIS v8', kenyaDpa: 'Kenya DPA', gdpr: 'GDPR', nistAiRmf: 'NIST AI RMF', iso42001: 'ISO 42001', euAiAct: 'EU AI Act' }

function Row({ slug, orgId, item, canWrite }: { slug: string; orgId: string; item: Item; canWrite: boolean }) {
  const { control: c, assurance, evidence } = item
  const [open, setOpen] = useState(false)
  const [status, setStatus] = useState(item.answer?.status)
  const [note, setNote] = useState(item.answer?.note ?? '')
  const [error, setError] = useState('')
  const [pending, start] = useTransition()

  const save = (next: string, text = note) => start(async () => {
    setStatus(next as Answer['status'])
    const res = await answerControl(slug, c.id, next, text)
    setError(res.error ?? '')
  })

  const upload = (file: File) => start(async () => {
    setError('')
    const path = `${orgId}/${c.id}/${crypto.randomUUID()}-${file.name.replace(/[^\w.-]/g, '_').slice(-80)}`
    const { error } = await supabaseBrowser().storage.from('evidence').upload(path, file)
    if (error) { setError(error.message); return }
    const res = await recordEvidence(slug, c.id, path, file.name)
    setError(res.error ?? '')
  })

  const openFile = (path: string) => start(async () => {
    const res = await evidenceLink(slug, path)
    if (res.ok) window.open(res.ok, '_blank', 'noopener')
    else setError(res.error ?? '')
  })

  const refs = Object.entries(c.frameworks).flatMap(([k, ids]) => ((ids ?? []) as string[]).map((id) => `${FW[k]} ${id}`))
  return (
    <li className="border-b border-line last:border-0">
      <div className="flex flex-wrap items-center gap-3 px-4 py-3">
        <button onClick={() => setOpen(!open)} aria-expanded={open} className="flex min-w-60 flex-1 items-start gap-2 text-left">
          <ChevronDown className={`mt-0.5 size-4 shrink-0 text-faint transition ${open ? 'rotate-180' : ''}`} />
          <span>
            <span className="text-sm font-medium">{c.question}</span>
            <span className="mt-0.5 flex flex-wrap items-center gap-x-2 text-xs text-faint">
              <span className="font-mono">{c.id}</span>
              {ASSURANCE[assurance] && <span className={`inline-flex items-center gap-1 ${assurance === 'claimed' ? 'text-med' : 'text-low'}`}>{assurance === 'tested' ? <ScanSearch className="size-3" /> : <BadgeCheck className="size-3" />}{ASSURANCE[assurance]}</span>}
            </span>
          </span>
        </button>
        <div role="group" aria-label={c.title} className="flex gap-1">
          {OPTIONS.map(([v, label, tone]) => (
            <button key={v} type="button" aria-pressed={status === v} disabled={!canWrite} onClick={() => save(v)} className={`rounded-md border px-2.5 py-1 text-xs font-semibold transition ${status === v ? `${tone} border-current` : 'border-line text-soft hover:bg-sunk'}`}>{label}</button>
          ))}
        </div>
      </div>
      {open && (
        <div className="grid gap-4 border-t border-line bg-sunk/40 px-4 py-4 text-sm lg:grid-cols-2">
          <div className="space-y-3">
            <div><div className="eyebrow">Why it matters</div><p className="mt-1 text-soft">{c.why}</p></div>
            <div><div className="eyebrow">How to fix it</div><p className="mt-1 text-soft">{c.howToFix}</p></div>
            {refs.length > 0 && <div><div className="eyebrow">Maps to</div><p className="mt-1 text-xs text-faint">{refs.join(', ')}</p></div>}
          </div>
          <div className="space-y-3">
            <div>
              <div className="eyebrow">Evidence an auditor would accept</div>
              <ul className="mt-1 list-disc pl-4 text-soft">{c.evidenceExamples.map((e) => <li key={e}>{e}</li>)}</ul>
            </div>
            {evidence.length > 0 && (
              <ul className="space-y-2 text-xs">
                {evidence.map((e) => (
                  <li key={e.id} className="flex items-center justify-between gap-2">
                    <button onClick={() => openFile(e.storage_path)} className="truncate font-medium text-brand hover:underline">{e.name}</button>
                    <span className="shrink-0 font-mono text-faint" title={e.sha256}>{e.sha256.slice(0, 10)}, {day(e.created_at)}</span>
                  </li>
                ))}
              </ul>
            )}
            {canWrite && <>
              <label className="btn btn-ghost w-fit cursor-pointer has-focus-visible:outline-2 has-focus-visible:outline-brand">
                <FileUp className="size-4" /> {pending ? 'Working' : 'Attach evidence'}
                <input type="file" className="sr-only" disabled={pending} accept=".pdf,.png,.jpg,.jpeg,.txt,.csv,.docx,.xlsx" onChange={(e) => { const f = e.target.files?.[0]; if (f) upload(f); e.target.value = '' }} />
              </label>
              <label className="block text-xs font-medium">Note
                <textarea rows={2} value={note} onChange={(e) => setNote(e.target.value)} onBlur={() => status && note !== (item.answer?.note ?? '') && save(status)} className="input mt-1" />
              </label>
            </>}
          </div>
        </div>
      )}
      {error && <p role="alert" className="px-4 pb-3 text-sm text-high">{error}</p>}
    </li>
  )
}

export function Assessment({ slug, orgId, items, labels, answered, total, canWrite }: { slug: string; orgId: string; items: Item[]; labels: Record<Domain, string>; answered: number; total: number; canWrite: boolean }) {
  const domains = [...new Set(items.map((i) => i.control.domain))]
  const [domain, setDomain] = useState<Domain>(domains[0])
  // A snapshot, so answering does not pull the focused row out from under a keyboard user.
  const [todo, setTodo] = useState<Set<string> | null>(null)
  const list = items.filter((i) => i.control.domain === domain && (!todo || todo.has(i.control.id)))
  return (
    <div>
      <PageHead title="Assessment" sub={`Tailored to your organization: ${total} controls apply. Answers save as you go.`}>
        <label className="btn btn-ghost cursor-pointer"><input type="checkbox" checked={!!todo} onChange={(e) => setTodo(e.target.checked ? new Set(items.filter((i) => !i.answer).map((i) => i.control.id)) : null)} className="accent-[#4c9bff]" /> Unanswered only</label>
      </PageHead>
      <div className="mb-4">
        <div className="mb-1 flex justify-between text-xs text-soft"><span>{answered} of {total} answered</span><span className="tabular-nums">{Math.round((answered / Math.max(total, 1)) * 100)}%</span></div>
        <div className="h-2 overflow-hidden rounded-full bg-sunk"><div className="h-full rounded-full bg-brand transition-all" style={{ width: `${(answered / Math.max(total, 1)) * 100}%` }} /></div>
      </div>
      <div className="grid gap-4 lg:grid-cols-[13rem_minmax(0,1fr)]">
        <div className="flex flex-wrap gap-1 lg:flex-col" role="group" aria-label="Control domains">
          {domains.map((d) => {
            const all = items.filter((i) => i.control.domain === d)
            const done = all.filter((i) => i.answer).length
            return (
              <button key={d} type="button" aria-pressed={d === domain} onClick={() => setDomain(d)} className={`flex shrink-0 items-center justify-between gap-3 rounded-lg border px-3 py-2 text-left text-sm font-medium ${d === domain ? 'border-brand bg-brand-soft text-ink' : 'border-transparent text-soft hover:bg-sunk'}`}>
                {labels[d]}<span className={`text-xs tabular-nums ${done === all.length ? 'text-low' : 'text-faint'}`}><span className="sr-only">, </span>{done}/{all.length}<span className="sr-only"> answered</span></span>
              </button>
            )
          })}
        </div>
        <ul className="card min-w-0">
          {list.map((i) => <Row key={i.control.id} slug={slug} orgId={orgId} item={i} canWrite={canWrite} />)}
          {!list.length && <li className="p-8 text-center text-sm text-soft">All done in this area.</li>}
        </ul>
      </div>
    </div>
  )
}
