'use client'

import { useEffect, useState } from 'react'

// Validated with the dataviz palette checker against the card surface #0e1726.
export const SERIES: Record<string, string> = {
  Security: '#3987e5', 'Third-Party': '#d95926', Operational: '#199e70', Compliance: '#c98500',
  Privacy: '#d55181', AI: '#9085e9', Strategic: '#e66767',
}

export interface Point { label: string; value: number }

const W = 520, H = 210, L = 30, R = 10, T = 10, B = 24

// One series on a fixed 0 to 100 axis, with a crosshair and tooltip.
export function TrendChart({ points, unit }: { points: Point[]; unit: string }) {
  const [hover, setHover] = useState<number | null>(null)
  useEffect(() => {
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') setHover(null) }
    addEventListener('keydown', esc)
    return () => removeEventListener('keydown', esc)
  }, [])
  const x = (i: number) => L + (points.length < 2 ? (W - L - R) / 2 : (i * (W - L - R)) / (points.length - 1))
  const y = (v: number) => T + ((100 - v) * (H - T - B)) / 100
  const line = points.map((p, i) => `${i ? 'L' : 'M'}${x(i)} ${y(p.value)}`).join('')
  const area = `${line}L${x(points.length - 1)} ${y(0)}L${x(0)} ${y(0)}Z`
  const active = hover === null ? null : points[hover]
  return (
    <div className="relative">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label={`${unit}: ${points.map((p) => `${p.label} ${p.value}`).join(', ')}`}
        onMouseLeave={() => setHover(null)}
        onMouseMove={(e) => {
          const box = e.currentTarget.getBoundingClientRect()
          const px = ((e.clientX - box.left) / box.width) * W
          const step = points.length < 2 ? 1 : (W - L - R) / (points.length - 1)
          setHover(Math.max(0, Math.min(points.length - 1, Math.round((px - L) / step))))
        }}>
        <defs>
          <linearGradient id="trend-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="#3987e5" stopOpacity="0.32" />
            <stop offset="1" stopColor="#3987e5" stopOpacity="0" />
          </linearGradient>
        </defs>
        {[0, 25, 50, 75, 100].map((v) => (
          <g key={v}>
            <line x1={L} x2={W - R} y1={y(v)} y2={y(v)} stroke="#1d2a3e" strokeWidth="1" />
            <text x={L - 6} y={y(v) + 3.5} textAnchor="end" fontSize="10" fill="#7387a3">{v}</text>
          </g>
        ))}
        {points.length > 1 && <path d={area} fill="url(#trend-fill)" />}
        {points.length > 1 && <path d={line} fill="none" stroke="#3987e5" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />}
        {points.map((p, i) => <circle key={i} cx={x(i)} cy={y(p.value)} r={hover === i ? 5 : 3.5} fill="#3987e5" stroke="#0e1726" strokeWidth="2" />)}
        {points.map((p, i) => (i === 0 || i === points.length - 1 || points.length <= 6) && (
          <text key={i} x={x(i)} y={H - 7} textAnchor="middle" fontSize="10" fill="#7387a3">{p.label}</text>
        ))}
        {hover !== null && <line x1={x(hover)} x2={x(hover)} y1={T} y2={y(0)} stroke="#7387a3" strokeDasharray="3 3" />}
      </svg>
      <details className="mt-2 text-xs text-soft">
        <summary className="cursor-pointer">Show data table</summary>
        <table className="mt-1 w-full text-left">
          <caption className="sr-only">{unit} by date</caption>
          <thead><tr><th scope="col" className="font-medium">Date</th><th scope="col" className="font-medium">{unit}</th></tr></thead>
          <tbody>{points.map((p, i) => <tr key={i}><td>{p.label}</td><td className="tabular-nums">{p.value}</td></tr>)}</tbody>
        </table>
      </details>
      {active && (
        <div className="pointer-events-none absolute top-1 rounded-lg border border-line bg-sunk px-2.5 py-1.5 text-xs shadow-lg" style={{ left: `clamp(0px, calc(${(x(hover!) / W) * 100}% - 3.5rem), calc(100% - 7rem))` }}>
          <div className="text-soft">{active.label}</div>
          <div className="font-bold tabular-nums">{active.value} {unit}</div>
        </div>
      )}
    </div>
  )
}

export function Donut({ slices, total, centerLabel }: { slices: { label: string; value: number }[]; total: number; centerLabel: string }) {
  const [hover, setHover] = useState<string | null>(null)
  const r = 42, c = 2 * Math.PI * r, gap = 1.6
  let offset = 0
  const shown = slices.find((s) => s.label === hover)
  return (
    <div className="flex flex-wrap items-center justify-center gap-5">
      <div className="relative size-40 shrink-0">
        <svg viewBox="0 0 100 100" className="-rotate-90" role="img" aria-label={`${centerLabel}: ${slices.map((s) => `${s.label} ${s.value}`).join(', ')}`}>
          {slices.map((s) => {
            const len = (s.value / total) * c
            const seg = (
              <circle key={s.label} cx="50" cy="50" r={r} fill="none" stroke={SERIES[s.label] ?? '#7387a3'} strokeWidth={hover === s.label ? 13 : 11}
                strokeDasharray={`${Math.max(len - gap, 0.5)} ${c}`} strokeDashoffset={-offset}
                onMouseEnter={() => setHover(s.label)} onMouseLeave={() => setHover(null)} />
            )
            offset += len
            return seg
          })}
        </svg>
        <div className="pointer-events-none absolute inset-0 grid place-content-center text-center">
          <div className="text-3xl font-bold tabular-nums">{shown?.value ?? total}</div>
          <div className="text-xs text-soft">{shown?.label ?? centerLabel}</div>
        </div>
      </div>
      <ul className="min-w-32 space-y-1.5 text-xs">
        {slices.map((s) => (
          <li key={s.label} className="flex items-center gap-2" onMouseEnter={() => setHover(s.label)} onMouseLeave={() => setHover(null)}>
            <span className="size-2.5 rounded-full" style={{ background: SERIES[s.label] ?? '#7387a3' }} />
            <span className="flex-1 text-soft">{s.label}</span>
            <span className="font-semibold tabular-nums">{s.value} ({Math.round((s.value / total) * 100)}%)</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

export function Ring({ value, label }: { value: number; label: string }) {
  const r = 42, c = 2 * Math.PI * r
  return (
    <div className="relative size-32 shrink-0">
      <svg viewBox="0 0 100 100" className="-rotate-90" role="img" aria-label={`${label}: ${value} percent`}>
        <circle cx="50" cy="50" r={r} fill="none" stroke="#162132" strokeWidth="9" />
        <circle cx="50" cy="50" r={r} fill="none" stroke="#199e70" strokeWidth="9" strokeLinecap="round" strokeDasharray={`${(value / 100) * c} ${c}`} />
      </svg>
      <div className="absolute inset-0 grid place-content-center text-center">
        <div className="text-2xl font-bold tabular-nums">{value}%</div>
        <div className="text-xs text-soft">{label}</div>
      </div>
    </div>
  )
}
