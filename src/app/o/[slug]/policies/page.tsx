import { Bot, FileText, Scale, ShieldCheck } from 'lucide-react'
import Link from 'next/link'
import { PageHead, day } from '@/components/ui'
import { atLeast } from '@/lib/access'
import { POLICIES } from '@/lib/content/policies'
import { loadState } from '@/lib/load'
import { GenerateButton } from './generate'

export const metadata = { title: 'Policies' }

const ICON = { security: ShieldCheck, ai: Bot, privacy: Scale }

export default async function Policies({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params
  const { supabase, org, role } = await loadState(slug)
  const { data } = await supabase.from('policies').select('id, template_id, version, status, approved_at, review_due').eq('org_id', org.id).order('version', { ascending: false })
  const templates = POLICIES.filter((t) => !t.appliesIf || t.appliesIf(org.profile))
  return (
    <div>
      <PageHead title="Policies" sub={`SMART security and AI policies written for ${org.name}. Every clause has a measure, a target, an owner and a deadline. They are drafts for your review, not legal advice.`} />
      <ul className="grid gap-3 lg:grid-cols-2">
        {templates.map((t) => {
          const versions = (data ?? []).filter((p) => p.template_id === t.id)
          const latest = versions[0]
          const approved = versions.find((p) => p.status === 'approved')
          const Icon = ICON[t.kind] ?? FileText
          return (
            <li key={t.id} className="card flex flex-col p-4">
              <div className="flex items-start gap-3">
                <span className="grid size-9 shrink-0 place-items-center rounded-lg bg-brand-soft text-brand"><Icon className="size-4" aria-hidden /></span>
                <div className="min-w-0 flex-1">
                  <h2 className="text-sm font-semibold tracking-normal">{t.title}</h2>
                  <p className="mt-1 text-sm text-soft">{t.summary}</p>
                </div>
                {approved ? <span className="rounded-md bg-low-soft px-2 py-0.5 text-xs font-semibold text-low">Approved</span> : latest ? <span className="rounded-md bg-med-soft px-2 py-0.5 text-xs font-semibold text-med">Draft</span> : null}
              </div>
              <div className="mt-auto flex flex-wrap items-center gap-2 pt-3">
                {latest && <Link href={`/o/${slug}/policies/${latest.id}`} className="btn btn-primary">Open v{latest.version}</Link>}
                {atLeast(role, 'analyst') && <GenerateButton slug={slug} templateId={t.id} label={latest ? 'New version' : 'Generate'} primary={!latest} />}
                {approved && <span className="text-xs text-faint">Review due {day(approved.review_due)}</span>}
              </div>
            </li>
          )
        })}
      </ul>
    </div>
  )
}
