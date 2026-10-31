'use client'

import { ClipboardCheck, FileText, Fingerprint, LayoutDashboard, Layers, ListChecks, Radar, Settings, ShieldAlert, ShieldCheck } from 'lucide-react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'

const ITEMS = [
  ['', 'Overview', LayoutDashboard],
  ['/risks', 'Risk Register', ShieldAlert],
  ['/assess', 'Assessment', ClipboardCheck],
  ['/tests', 'Live Tests', Radar],
  ['/recommendations', 'Recommendations', ListChecks],
  ['/guardrails', 'Guardrails', ShieldCheck],
  ['/policies', 'Policies', FileText],
  ['/blueprint', 'Custom System', Layers],
  ['/proof', 'Proof', Fingerprint],
  ['/settings', 'Settings', Settings],
] as const

export function Nav({ slug, badges }: { slug: string; badges: Record<string, number> }) {
  const path = usePathname()
  return (
    <nav aria-label="Workspace" className="no-print flex flex-wrap gap-1 lg:flex-col">
      {ITEMS.map(([href, label, Icon]) => {
        const to = `/o/${slug}${href}`
        const active = href ? path.startsWith(to) : path === to
        return (
          <Link key={href} href={to} aria-current={active ? 'page' : undefined}
            className={`flex shrink-0 items-center gap-2.5 rounded-lg border px-3 py-2 text-sm font-medium transition ${active ? 'border-brand bg-brand-soft text-ink' : 'border-transparent text-soft hover:bg-sunk hover:text-ink'}`}>
            <Icon className={`size-4 ${active ? 'text-brand' : ''}`} aria-hidden />
            <span className="flex-1">{label}</span>
            {!!badges[href] && <span className="rounded-full bg-brand px-1.5 text-xs font-bold tabular-nums text-brand-ink">{badges[href]}</span>}
          </Link>
        )
      })}
    </nav>
  )
}

