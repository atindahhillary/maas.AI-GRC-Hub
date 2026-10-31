'use client'

import { ArrowRight, Download, Info, Plus, Trash2, X } from 'lucide-react'
import { useActionState, useEffect, useMemo, useRef, useState, useTransition } from 'react'
import { Heatmap } from '@/components/heatmap'
import { Empty, LevelBadge, PageHead, Panel, ScoreChip, day } from '@/components/ui'
import { IMPACT, LIKELIHOOD, currentScore, level, risksToCsv, riskRef, score, type Risk } from '@/lib/risk'
import { addExampleRisks, deleteRisk, saveRisk } from '../actions'

const CATEGORIES = ['Security', 'Third-Party', 'Operational', 'Compliance', 'Privacy', 'AI', 'Strategic']

const Scale = ({ name, label, labels, value, onChange, optional }: { name: string; label: string; labels: string[]; value: number | null; onChange: (n: number | null) => void; optional?: boolean }) => (
  <label className="block text-sm font-medium">{label}{!optional && ' *'}
    <select name={name} value={value ?? ''} onChange={(e) => onChange(e.target.value ? Number(e.target.value) : null)} required={!optional} className="input mt-1">
      <option value="">{optional ? 'Not assessed yet' : 'Choose'}</option>
      {labels.map((l, i) => <option key={l} value={i + 1}>{i + 1}, {l}</option>)}
    </select>
  </label>
)

function Editor({ slug, risk, onClose }: { slug: string; risk: Risk | null; onClose: () => void }) {
  const [state, action, pending] = useActionState(saveRisk.bind(null, slug, risk?.id ?? null), {})
  const [l, setL] = useState<number | null>(risk?.likelihood ?? null)
  const [i, setI] = useState<number | null>(risk?.impact ?? null)
  const [rl, setRl] = useState<number | null>(risk?.residual_likelihood ?? null)
  const [ri, setRi] = useState<number | null>(risk?.residual_impact ?? null)
  const ref = useRef<HTMLDialogElement>(null)
  useEffect(() => { ref.current?.showModal() }, [])
  useEffect(() => { if (state.ok) ref.current?.close() }, [state])
  const inherent = l && i ? score(l, i) : null
  const residual = rl && ri ? score(rl, ri) : null
  return (
    <dialog ref={ref} aria-labelledby="risk-editor-title" onClose={onClose} className="m-auto w-[min(44rem,calc(100vw-2rem))] rounded-xl border border-line bg-card p-0 text-ink backdrop:bg-black/60">
      <form action={action} className="space-y-4 p-5">
        <div className="flex items-center justify-between">
          <h2 id="risk-editor-title" className="text-lg">{risk ? riskRef(risk.seq) : 'New risk'}</h2>
          <button type="button" onClick={() => ref.current?.close()} aria-label="Close" className="text-faint hover:text-ink"><X className="size-5" /></button>
        </div>
        <p className="text-xs text-soft">Fields marked * are required.</p>
        <label className="block text-sm font-medium">Risk description *
          <textarea name="description" required minLength={3} rows={2} defaultValue={risk?.description} placeholder="Asset, threat, and what happens" className="input mt-1" />
        </label>
        <label className="block text-sm font-medium">Consequence
          <textarea name="consequence" rows={2} defaultValue={risk?.consequence} className="input mt-1" />
        </label>
        <div className="grid gap-3 sm:grid-cols-2">
          <label className="block text-sm font-medium">Category
            <select name="category" defaultValue={risk?.category ?? 'Security'} className="input mt-1">{CATEGORIES.map((c) => <option key={c}>{c}</option>)}</select>
          </label>
          <label className="block text-sm font-medium">Risk owner
            <input name="owner" defaultValue={risk?.owner} className="input mt-1" />
          </label>
        </div>
        <fieldset className="rounded-lg border border-line p-3">
          <legend className="px-1 text-sm font-semibold">Inherent risk, before controls</legend>
          <div className="grid items-end gap-3 sm:grid-cols-[1fr_1fr_auto]">
            <Scale name="likelihood" label="Likelihood" labels={LIKELIHOOD} value={l} onChange={setL} />
            <Scale name="impact" label="Impact" labels={IMPACT} value={i} onChange={setI} />
            <div className="flex items-center gap-2 pb-1"><ScoreChip score={inherent} /><LevelBadge value={inherent ? level(inherent) : null} /></div>
          </div>
        </fieldset>
        <label className="block text-sm font-medium">Existing controls
          <textarea name="existing_controls" rows={2} defaultValue={risk?.existing_controls} className="input mt-1" />
        </label>
        <div className="grid gap-3 sm:grid-cols-3">
          <label className="block text-sm font-medium">Response strategy
            <select name="strategy" defaultValue={risk?.strategy ?? 'Mitigate'} className="input mt-1">{['Mitigate', 'Accept', 'Transfer', 'Avoid'].map((s) => <option key={s}>{s}</option>)}</select>
          </label>
          <label className="block text-sm font-medium">Status
            <select name="status" defaultValue={risk?.status ?? 'Open'} className="input mt-1">{['Open', 'In Progress', 'Closed', 'Accepted'].map((s) => <option key={s}>{s}</option>)}</select>
          </label>
          <label className="block text-sm font-medium">Target date
            <input type="date" name="target_date" defaultValue={risk?.target_date ?? ''} className="input mt-1" />
          </label>
        </div>
        <label className="block text-sm font-medium">Mitigation actions
          <textarea name="mitigation" rows={2} defaultValue={risk?.mitigation} className="input mt-1" />
        </label>
        <fieldset className="rounded-lg border border-line p-3">
          <legend className="px-1 text-sm font-semibold">Residual risk, after controls</legend>
          <div className="grid items-end gap-3 sm:grid-cols-[1fr_1fr_auto]">
            <Scale name="residual_likelihood" label="Residual likelihood" labels={LIKELIHOOD} value={rl} onChange={setRl} optional />
            <Scale name="residual_impact" label="Residual impact" labels={IMPACT} value={ri} onChange={setRi} optional />
            <div className="flex items-center gap-2 pb-1"><ScoreChip score={residual} /><LevelBadge value={residual ? level(residual) : null} /></div>
          </div>
        </fieldset>
        {state.error && <p role="alert" className="text-sm text-high">{state.error}</p>}
        <div className="flex justify-end gap-2">
          <button type="button" onClick={() => ref.current?.close()} className="btn btn-ghost">Cancel</button>
          <button disabled={pending} className="btn btn-primary">{pending ? 'Saving' : 'Save risk'}</button>
        </div>
      </form>
    </dialog>
  )
}

export function RiskRegister({ slug, risks, canWrite, canDelete }: { slug: string; risks: Risk[]; canWrite: boolean; canDelete: boolean }) {
  const [editing, setEditing] = useState<Risk | 'new' | null>(null)
  const [filter, setFilter] = useState('All')
  const [guide, setGuide] = useState(false)
  const [busy, start] = useTransition()
  const [error, setError] = useState('')
  const rows = useMemo(() => risks.filter((r) => filter === 'All' || (filter === 'Open' ? r.status !== 'Closed' : level(currentScore(r)) === filter)).sort((a, b) => currentScore(b) - currentScore(a)), [risks, filter])

  function exportCsv() {
    const url = URL.createObjectURL(new Blob([risksToCsv(risks)], { type: 'text/csv' }))
    const a = document.createElement('a')
    a.href = url
    a.download = `${slug}-risk-register.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div>
      <PageHead title="Risk Register" sub="Likelihood times impact drives everything here. Controls bring inherent risk down to the residual risk you actually carry.">
        <button onClick={() => setGuide(!guide)} className="btn btn-ghost"><Info className="size-4" /> {guide ? 'Hide guide' : 'Why it matters'}</button>
        {risks.length > 0 && <button onClick={exportCsv} className="btn btn-ghost"><Download className="size-4" /> Export CSV</button>}
        {canWrite && <button onClick={() => setEditing('new')} className="btn btn-primary"><Plus className="size-4" /> Add risk</button>}
      </PageHead>

      {guide && (
        <div className="mb-4 grid gap-3 lg:grid-cols-[1fr_1fr]">
          <Panel title="Why keep a risk register">
            <ul className="space-y-2 text-sm text-soft">
              <li><strong className="text-ink">Better decisions.</strong> Leadership spends limited time and money on what actually threatens the business, not on whatever is loudest this week.</li>
              <li><strong className="text-ink">Commercial need.</strong> Cyber insurance applications, customer security questionnaires and compliance audits increasingly ask for one.</li>
              <li><strong className="text-ink">A paper trail.</strong> If a risk ever materializes, you can show it was identified and tracked.</li>
            </ul>
          </Panel>
          <Panel title="Scoring matrix"><Heatmap /></Panel>
        </div>
      )}

      <div className="mb-3 flex flex-wrap gap-1.5" role="group" aria-label="Filter risks">
        {['All', 'Open', 'High', 'Medium', 'Low'].map((f) => (
          <button key={f} onClick={() => setFilter(f)} aria-pressed={filter === f} className={`rounded-lg border px-3 py-1.5 text-sm font-medium ${filter === f ? 'border-brand bg-brand-soft text-brand' : 'border-transparent text-soft hover:bg-sunk'}`}>{f}</button>
        ))}
      </div>

      {error && <p role="alert" className="mb-3 text-sm text-high">{error}</p>}
      {risks.length === 0 ? (
        <Empty title="Your register is empty">
          <p>Add your first risk, raise one from a recommendation, or load three worked examples to see how scoring behaves.</p>
          {canWrite && <button disabled={busy} onClick={() => start(async () => { setError((await addExampleRisks(slug)).error ?? '') })} className="btn btn-ghost mt-4">Load worked examples</button>}
        </Empty>
      ) : (
        <div id="risk-table" tabIndex={0} role="region" aria-label="Risks" className="card overflow-x-auto">
          <table className="w-full min-w-[60rem] text-left text-sm">
            <thead className="text-xs text-faint">
              <tr className="border-b border-line">
                {['Risk', 'Description', 'Category', 'Inherent', '', 'Residual', 'Owner', 'Target', 'Status'].map((h, i) => <th key={i} className="px-3 py-2.5 font-medium">{h || <span className="sr-only">Change</span>}</th>)}
                <th className="w-8"><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} className="border-b border-line last:border-0 hover:bg-sunk/50">
                  <td className="px-3 py-2.5 font-mono text-xs">
                    {canWrite ? <button onClick={() => setEditing(r)} className="font-semibold text-brand hover:underline">{riskRef(r.seq)}</button> : riskRef(r.seq)}
                  </td>
                  <td className="max-w-80 px-3 py-2.5"><span className="line-clamp-2">{r.description}</span></td>
                  <td className="px-3 py-2.5 text-soft">{r.category}</td>
                  <td className="px-3 py-2.5"><span className="inline-flex items-center gap-2"><ScoreChip score={r.inherent_score} /><LevelBadge value={r.inherent_level} /></span></td>
                  <td className="px-1 text-faint"><ArrowRight className="size-3.5" role="img" aria-label="becomes" /></td>
                  <td className="px-3 py-2.5"><span className="inline-flex items-center gap-2"><ScoreChip score={r.residual_score} /><LevelBadge value={r.residual_level} /></span></td>
                  <td className="px-3 py-2.5 text-soft">{r.owner || '-'}</td>
                  <td className="whitespace-nowrap px-3 py-2.5 text-soft">{r.target_date ? day(r.target_date) : '-'}</td>
                  <td className="whitespace-nowrap px-3 py-2.5 text-soft">{r.status}</td>
                  <td className="pr-2">
                    {canDelete && <button aria-label={`Delete ${riskRef(r.seq)}`} disabled={busy} onClick={() => { if (confirm(`Delete ${riskRef(r.seq)}? The ledger keeps a record of the deletion.`)) start(async () => { setError((await deleteRisk(slug, r.id)).error ?? ''); document.getElementById('risk-table')?.focus() }) }} className="text-faint hover:text-high"><Trash2 className="size-4" /></button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {editing && <Editor slug={slug} risk={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
    </div>
  )
}
