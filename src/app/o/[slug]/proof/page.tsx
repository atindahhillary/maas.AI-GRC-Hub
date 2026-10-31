import { BadgeCheck, CircleAlert, FileSignature, Link2 } from 'lucide-react'
import Link from 'next/link'
import { Empty, PageHead, Panel, day, shortHash } from '@/components/ui'
import { Ring } from '@/components/charts'
import { atLeast } from '@/lib/access'
import { loadState } from '@/lib/load'
import { controlById, posture } from '@/lib/posture'
import { AttestationRow, IssueButton } from './attest'

export const metadata = { title: 'Proof' }

export default async function Proof({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params
  const { supabase, org, role, states, evidence } = await loadState(slug)
  const p = posture(states)
  const [{ data: chainRows }, { data: attestations }, { data: ledger }] = await Promise.all([
    supabase.rpc('verify_ledger', { p_org: org.id }),
    supabase.from('attestations').select('id, payload, published, issued_at, expires_at, key_id').eq('org_id', org.id).order('issued_at', { ascending: false }).limit(10),
    supabase.from('ledger').select('seq, event, subject, hash, created_at').eq('org_id', org.id).order('seq', { ascending: false }).limit(25),
  ])
  const chain = (chainRows as { ok: boolean; entries: number; head: string; broken_at: number | null }[] | null)?.[0]
  const counts = { tested: 0, evidenced: 0, claimed: 0 }
  states.forEach((s) => { if (s.assurance in counts) counts[s.assurance as keyof typeof counts]++ })
  return (
    <div className="space-y-3">
      <PageHead title="Proof" sub="What you can show, not just what you say. Share a signed attestation with customers, boards and insurers." />
      <div className="grid gap-3 lg:grid-cols-3">
        <Panel title="Assurance">
          <div className="flex items-center gap-4">
            <Ring value={p.proven} label="Proven" />
            <dl className="flex-1 space-y-1 text-sm">
              <div className="flex justify-between"><dt className="text-soft">Machine tested</dt><dd className="font-semibold tabular-nums">{counts.tested}</dd></div>
              <div className="flex justify-between"><dt className="text-soft">Evidenced</dt><dd className="font-semibold tabular-nums">{counts.evidenced}</dd></div>
              <div className="flex justify-between"><dt className="text-soft">Claimed only</dt><dd className="font-semibold tabular-nums">{counts.claimed}</dd></div>
            </dl>
          </div>
        </Panel>
        <Panel title="Ledger integrity">
          <div className={`flex items-start gap-2 rounded-lg p-3 text-sm ${chain?.ok ? 'bg-low-soft text-low' : 'bg-high-soft text-high'}`}>
            {chain?.ok ? <BadgeCheck className="size-4 shrink-0" /> : <CircleAlert className="size-4 shrink-0" />}
            <span>{chain?.ok ? `Chain intact, ${chain.entries} entries recomputed just now.` : `Chain broken at entry ${chain?.broken_at}.`}</span>
          </div>
          {chain?.head && <p className="mt-2 text-xs text-faint">Head <code className="font-mono">{shortHash(chain.head)}</code></p>}
          <p className="mt-2 text-xs text-soft">Each change is hashed with the one before it, so a later edit breaks the chain. Signed attestations pin the head, which guards it even against database administrators.</p>
        </Panel>
        <Panel title="Attestation">
          <p className="text-sm text-soft">Signs your current scores, latest live test, approved policies and ledger head with Ed25519. Valid for 90 days.</p>
          {atLeast(role, 'admin') && <div className="mt-3"><IssueButton slug={slug} /></div>}
        </Panel>
      </div>

      {(attestations ?? []).length > 0 && (
        <Panel title="Signed attestations">
          <ul className="divide-y divide-line">
            {attestations!.map((a) => <AttestationRow key={a.id} slug={slug} a={a} canAdmin={atLeast(role, 'admin')} />)}
          </ul>
        </Panel>
      )}

      <div className="grid gap-3 lg:grid-cols-2">
        <Panel title={`Evidence vault, ${evidence.length} files`}>
          {evidence.length ? (
            <ul className="divide-y divide-line text-sm">
              {evidence.slice(0, 25).map((e) => (
                <li key={e.id} className="py-2">
                  <div className="flex justify-between gap-2"><span className="truncate font-medium">{e.name}</span><span className="shrink-0 text-xs text-faint">{day(e.created_at)}</span></div>
                  <div className="flex justify-between gap-2 text-xs text-faint"><span className="truncate">{e.control_id}, {controlById.get(e.control_id)?.title}</span></div>
                  <code className="mt-0.5 block break-all font-mono text-xs text-faint">{e.sha256}</code>
                </li>
              ))}
            </ul>
          ) : <p className="py-6 text-center text-sm text-soft">Attach evidence from the <Link href={`/o/${slug}/assess`} className="font-semibold text-brand">assessment</Link>. Each file is hashed on arrival.</p>}
        </Panel>
        <Panel title="Audit ledger">
          {(ledger ?? []).length ? (
            <ul tabIndex={0} aria-label="Audit ledger entries" className="max-h-96 divide-y divide-line overflow-auto text-xs">
              {ledger!.map((l) => (
                <li key={l.seq} className="flex items-center gap-3 py-1.5">
                  <span className="w-8 shrink-0 text-right font-mono text-faint">{l.seq}</span>
                  <span className="min-w-0 flex-1 truncate"><span className="font-medium">{l.event}</span> <span className="text-faint">{l.subject.length > 24 ? '' : l.subject}</span></span>
                  <code className="hidden shrink-0 font-mono text-faint sm:block">{l.hash.slice(0, 10)}</code>
                  <span className="shrink-0 text-faint">{day(l.created_at)}</span>
                </li>
              ))}
            </ul>
          ) : <Empty title="Nothing recorded yet" />}
        </Panel>
      </div>
      <p className="flex items-start gap-2 text-xs text-faint"><Link2 className="size-3.5 shrink-0" /><FileSignature className="size-3.5 shrink-0" /> An attestation proves what was tested and declared on a date. It does not guarantee a breach cannot happen.</p>
    </div>
  )
}
