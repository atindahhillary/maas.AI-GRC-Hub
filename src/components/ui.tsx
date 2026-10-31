import Link from 'next/link'
import { LEVEL_STYLE, level, type Level } from '@/lib/risk'

export function Logo() {
  return (
    <Link href="/" className="inline-flex items-center gap-2.5 font-bold tracking-tight text-ink">
      <svg viewBox="0 0 32 32" className="size-7" aria-hidden>
        <path d="M16 2 28 6.5v9.8c0 7-4.9 11.9-12 13.7C8.9 28.2 4 23.3 4 16.3V6.5z" fill="#123a6b" stroke="#4c9bff" strokeWidth="1.5" />
        <path d="M10 21V12l6 6 6-6v9" fill="none" stroke="#eef3fa" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      <span>maas.AI <span className="font-medium text-soft">GRC Hub</span></span>
    </Link>
  )
}

export function LevelBadge({ value }: { value: Level | null }) {
  if (!value) return <span className="text-faint">Not set</span>
  return <span className={`inline-block rounded-md px-2 py-0.5 text-xs font-semibold ${LEVEL_STYLE[value]}`}>{value}</span>
}

export function ScoreChip({ score }: { score: number | null }) {
  if (score === null) return <span className="text-faint">-</span>
  return <span className={`inline-grid size-8 place-items-center rounded-lg text-sm font-bold tabular-nums ${LEVEL_STYLE[level(score)]}`}>{score}</span>
}

export function PageHead({ title, sub, children }: { title: string; sub?: string; children?: React.ReactNode }) {
  return (
    <header className="mb-5 flex flex-wrap items-end justify-between gap-4">
      <div className="max-w-2xl">
        <h1 className="text-2xl">{title}</h1>
        {sub && <p className="mt-1 text-sm text-soft">{sub}</p>}
      </div>
      {children && <div className="no-print flex flex-wrap gap-2">{children}</div>}
    </header>
  )
}

export function Panel({ title, action, className = '', children }: { title: string; action?: React.ReactNode; className?: string; children: React.ReactNode }) {
  return (
    <section className={`card flex min-w-0 flex-col p-4 ${className}`}>
      <div className="mb-3 flex items-center justify-between gap-3">
        <h2 className="text-sm font-semibold tracking-normal">{title}</h2>
        {action}
      </div>
      {children}
    </section>
  )
}

export function Empty({ title, children }: { title: string; children?: React.ReactNode }) {
  return (
    <div className="card grid place-items-center px-6 py-14 text-center">
      <h2 className="text-lg">{title}</h2>
      <div className="mt-2 max-w-md text-sm text-soft">{children}</div>
    </div>
  )
}

export const shortHash = (h: string) => `${h.slice(0, 10)}...${h.slice(-6)}`
export const day = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' }) : '-')
