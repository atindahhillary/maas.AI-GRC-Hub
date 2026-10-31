import { Bot, Cloud, Fingerprint, Globe, HardDrive, Lock, Mail, type LucideIcon } from 'lucide-react'
import { CopyButton } from '@/components/copy'
import { PageHead } from '@/components/ui'
import type { Guardrail } from '@/lib/content/types'
import { loadState } from '@/lib/load'
import { guardrails } from '@/lib/posture'

export const metadata = { title: 'Guardrails' }

const KIND: Record<Guardrail['kind'], [string, LucideIcon]> = {
  email: ['Email', Mail], web: ['Web', Globe], identity: ['Identity', Fingerprint], cloud: ['Cloud', Cloud],
  endpoint: ['Devices', HardDrive], data: ['Data', Lock], ai: ['AI', Bot],
}

export default async function Guardrails({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params
  const { supabase, org, states, scan } = await loadState(slug)
  const { data: verified } = await supabase.from('domains').select('domain').eq('org_id', org.id).not('verified_at', 'is', null).limit(1).maybeSingle()
  const domain = verified?.domain ?? 'example.org'
  const list = guardrails(org.profile, states, scan)
  const needed = list.filter((g) => g.needed).length
  return (
    <div>
      <PageHead title="Guardrails" sub={`${needed} of ${list.length} are needed now, based on your own findings. Each one is ready to paste, and says how to prove it is on.`} />
      <ul className="grid gap-3 xl:grid-cols-2">
        {list.map(({ guardrail: g, needed, reasons }) => {
          const [kind, Icon] = KIND[g.kind]
          const code = g.snippet?.code.replaceAll('{domain}', domain)
          return (
            <li key={g.id} className="card flex min-w-0 flex-col p-4">
              <div className="flex items-start gap-3">
                <span className="grid size-9 shrink-0 place-items-center rounded-lg bg-brand-soft text-brand"><Icon className="size-4" aria-hidden /></span>
                <div className="min-w-0 flex-1">
                  <h2 className="text-sm font-semibold tracking-normal">{g.title}</h2>
                  <p className="text-xs text-faint">{kind}</p>
                </div>
                {needed ? <span className="rounded-md bg-high-soft px-2 py-0.5 text-xs font-semibold text-high">Needed</span> : <span className="rounded-md bg-sunk px-2 py-0.5 text-xs font-semibold text-soft">Suggested</span>}
              </div>
              <p className="mt-3 text-sm text-soft">{g.problem}</p>
              <p className="mt-2 text-sm">{g.action}</p>
              {reasons.length > 0 && <p className="mt-2 text-xs text-med">Raised by: {reasons.join(', ')}</p>}
              {code && (
                <div className="relative mt-3 min-w-0">
                  <pre tabIndex={0} aria-label={`${g.title} code`} className="max-h-64 overflow-auto rounded-lg bg-paper p-3 pr-16 font-mono text-xs leading-relaxed"><code>{code}</code></pre>
                  <CopyButton text={code} />
                </div>
              )}
              <p className="mt-3 border-t border-line pt-2 text-xs text-soft"><strong className="text-ink">Prove it:</strong> {g.verify}</p>
            </li>
          )
        })}
      </ul>
    </div>
  )
}
