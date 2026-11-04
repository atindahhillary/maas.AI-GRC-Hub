import Link from 'next/link'
import { ArrowRight, BadgeCheck, FileSignature, Link2, ScanSearch, type LucideIcon } from 'lucide-react'
import { Ring } from '@/components/charts'
import { Logo, ScoreChip } from '@/components/ui'

const STEPS = [
  ['Test', 'Prove you own your domain, then run live checks on email spoofing, encryption, web hardening and exposed secrets. Answer a plain-English assessment tailored to your sector, size and tools.'],
  ['Score', 'Every gap becomes a risk scored the way a senior analyst would: likelihood times impact, inherent to residual, with an owner and a deadline. Your dashboard shows what you claim and what you can prove.'],
  ['Fix', 'Get prioritized recommendations, paste-ready guardrails, a custom security system for your budget, and SMART security and AI policies written for your organization.'],
  ['Prove', 'Evidence is hashed, every change lands in a tamper-evident ledger, and results are signed into an attestation anyone can check against our public key.'],
]

const PROOF: [LucideIcon, string, string][] = [
  [ScanSearch, 'Machine tested', 'Results come from our scanner on a domain you proved you own, and your team cannot edit them.'],
  [Link2, 'Tamper-evident', 'Each change is chained by hash to the one before, so a later edit by anyone without full database rights breaks the chain.'],
  [FileSignature, 'Signed by maas.AI', 'Attestations carry an Ed25519 signature tied to a domain you proved you own. Our public key is all anyone needs to check one.'],
]

const FRAMEWORKS = ['ISO/IEC 27001', 'NIST CSF 2.0', 'CIS Controls', 'Kenya DPA 2019', 'GDPR', 'NIST AI RMF', 'ISO/IEC 42001', 'EU AI Act']

export default function Home() {
  return (
    <div className="overflow-x-clip">
      <nav aria-label="Primary" className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-5 py-5">
        <span className="flex items-center gap-2"><Logo /><span className="rounded-full border border-brand/50 px-2 py-0.5 text-xs font-semibold text-brand">Beta</span></span>
        <div className="flex items-center gap-2">
          <Link href="/signin" className="btn btn-ghost">Sign in</Link>
          <Link href="/signup" className="btn btn-primary">Create account</Link>
        </div>
      </nav>

      <main>
      <section className="mx-auto grid max-w-6xl items-center gap-12 px-5 pb-20 pt-10 lg:grid-cols-[1.15fr_1fr] lg:pt-16">
        <div className="rise">
          <h1 className="text-[clamp(2.6rem,6vw,4.8rem)] leading-[1.02] tracking-[-0.035em]">
            Saying you are secure is easy. <span className="text-brand">Prove it.</span>
          </h1>
          <p className="mt-6 max-w-xl text-lg text-soft">
            maas.AI GRC Hub gives every organization its own security workspace to run tests, see what to fix, and hand customers, boards and insurers signed proof.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Link href="/signup" className="btn btn-primary px-5 py-3 text-base">Start your assessment <ArrowRight className="size-4" /></Link>
            <Link href="/verify" className="btn btn-ghost px-5 py-3 text-base">Verify an attestation</Link>
          </div>
        </div>

        <div className="card rise p-5 shadow-[0_30px_80px_-30px_rgba(76,155,255,0.3)]" style={{ animationDelay: '120ms' }}>
          <div className="mb-4 flex items-center justify-between">
            <div className="text-sm font-semibold">Security posture</div>
            <span className="eyebrow">Illustration</span>
          </div>
          <div className="flex items-center gap-5">
            <Ring value={52} label="Proven" />
            <p className="text-sm text-soft">You claim <strong className="text-ink">78%</strong> and can prove <strong className="text-ink">52%</strong>. The gap is what you say but cannot yet show.</p>
          </div>
          <div className="mt-5 space-y-3 border-t border-line pt-4 text-sm">
            <div className="flex items-center gap-3"><ScoreChip score={20} /><span className="min-w-0 flex-1 truncate">Internet-facing server unpatched</span><ArrowRight className="size-3.5 text-faint" /><ScoreChip score={10} /></div>
            <div className="flex items-center gap-3"><ScoreChip score={16} /><span className="min-w-0 flex-1 truncate">No DMARC, domain can be spoofed</span><ArrowRight className="size-3.5 text-faint" /><ScoreChip score={4} /></div>
          </div>
          <div className="mt-4 flex items-center gap-2 rounded-lg bg-low-soft px-3 py-2 text-xs font-medium text-low">
            <BadgeCheck className="size-4 shrink-0" /> Signed attestation, tied to your verified domain
          </div>
        </div>
      </section>

      <section className="border-y border-line bg-rail">
        <div className="mx-auto max-w-6xl px-5 py-20">
          <h2 className="max-w-2xl text-4xl">One loop, from the first test to proof you can hand over.</h2>
          <ol className="mt-10 divide-y divide-line">
            {STEPS.map(([name, body], i) => (
              <li key={name} className="grid gap-2 py-6 md:grid-cols-[4rem_12rem_1fr] md:items-baseline">
                <span className="font-mono text-sm text-faint">0{i + 1}</span>
                <h3 className="text-2xl">{name}</h3>
                <p className="max-w-2xl text-soft">{body}</p>
              </li>
            ))}
          </ol>
        </div>
      </section>

      <section className="mx-auto grid max-w-6xl gap-10 px-5 py-20 lg:grid-cols-3">
        <div>
          <h2 className="text-4xl">What proof means here.</h2>
          <p className="mt-4 text-soft">Reassurance is a sentence. Proof is something a stranger can check. We hold ourselves to the second one, including being clear about the limits.</p>
        </div>
        <div className="grid gap-4 sm:grid-cols-3 lg:col-span-2">
          {PROOF.map(([Icon, title, body]) => (
            <div key={title} className="card p-5">
              <Icon className="size-5 text-brand" />
              <h3 className="mt-3 text-base">{title}</h3>
              <p className="mt-1.5 text-sm text-soft">{body}</p>
            </div>
          ))}
          <p className="text-sm text-soft sm:col-span-3">
            An attestation proves what was tested and declared on a date. It is not a guarantee that a breach cannot happen, and it does not replace a penetration test or a certification audit.
          </p>
        </div>
      </section>

      <section className="border-t border-line bg-rail">
        <div className="mx-auto max-w-6xl px-5 py-16">
          <p className="eyebrow">Controls mapped to</p>
          <div className="mt-4 flex flex-wrap gap-x-8 gap-y-2 text-lg font-semibold">
            {FRAMEWORKS.map((f) => <span key={f}>{f}</span>)}
          </div>
          <div className="mt-10 flex flex-wrap items-center justify-between gap-4">
            <p className="text-2xl font-bold tracking-tight">Find out your real number in an afternoon.</p>
            <Link href="/signup" className="btn btn-primary px-5 py-3 text-base">Create your workspace</Link>
          </div>
        </div>
      </section>

      </main>

      <footer className="mx-auto flex max-w-6xl flex-wrap justify-between gap-3 px-5 py-8 text-sm text-faint">
        <span>maas.AI GRC Hub</span>
        <span>Generated documents are drafts for human review, not legal advice.</span>
        <span className="flex gap-4"><a href="/privacy" className="hover:text-ink">Privacy</a><a href="mailto:atindahhillary@gmail.com?subject=maas.AI%20GRC%20Hub%20beta%20feedback" className="hover:text-ink">Send feedback</a></span>
      </footer>
    </div>
  )
}
