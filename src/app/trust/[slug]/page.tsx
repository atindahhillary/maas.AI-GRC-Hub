import { BadgeCheck, CircleAlert, ScanSearch, ShieldCheck } from 'lucide-react'
import Link from 'next/link'
import { notFound } from 'next/navigation'
import { Logo, day, shortHash } from '@/components/ui'
import { verifySignature, type AttestationPayload } from '@/lib/attest'
import { supabaseAnon } from '@/lib/supabase/server'

export const dynamic = 'force-dynamic'

async function load(slug: string) {
  const { data } = await supabaseAnon().rpc('trust_page', { p_slug: slug })
  return (data as { canonical: string; signature: string; key_id: string }[] | null)?.[0] ?? null
}

export async function generateMetadata({ params }: { params: Promise<{ slug: string }> }) {
  const a = await load((await params).slug)
  return { title: a ? `${(JSON.parse(a.canonical) as AttestationPayload).scan?.domain} trust page` : 'Trust page', robots: { index: false } }
}

export default async function Trust({ params }: { params: Promise<{ slug: string }> }) {
  const a = await load((await params).slug)
  if (!a) notFound()
  // Everything shown comes from the signed bytes, never from editable columns.
  const { slug } = await params
  const p = JSON.parse(a.canonical) as AttestationPayload
  const valid = verifySignature(a.canonical, a.signature) && p.slug === slug
  const current = new Date(p.expiresAt).getTime() > Date.now()
  const good = valid && current
  const bundle = JSON.stringify({ canonical: a.canonical, signature: a.signature, keyId: a.key_id })
  return (
    <main className="mx-auto max-w-3xl px-5 py-10">
      <Logo />
      <header className="mt-10">
        <p className="eyebrow">Security attestation</p>
        <h1 className="mt-1 break-words text-4xl">{p.scan?.domain ?? 'Unverified organization'}</h1>
        <p className="mt-1 text-sm text-soft">Domain ownership verified by DNS. Name stated by the organization: {p.org}</p>
        <div className={`mt-4 flex items-start gap-3 rounded-xl p-4 ${good ? 'bg-low-soft text-low' : 'bg-high-soft text-high'}`}>
          {good ? <BadgeCheck className="mt-0.5 size-5 shrink-0" /> : <CircleAlert className="mt-0.5 size-5 shrink-0" />}
          <div className="text-sm">
            <p className="font-bold">{!valid ? 'Signature failed. Do not rely on this page.' : !current ? `Expired on ${day(p.expiresAt)}. Ask for a current attestation.` : `Signature valid. Current until ${day(p.expiresAt)}.`}</p>
            <p>Issued {day(p.issuedAt)} by maas.AI GRC Hub, key {a.key_id}.</p>
          </div>
        </div>
      </header>

      <section className="mt-6 grid gap-4 sm:grid-cols-2">
        <div className="card p-5">
          <h2 className="flex items-center gap-2 text-base font-bold"><ShieldCheck className="size-4 text-brand" /> Posture</h2>
          <div className="mt-3 flex gap-8">
            <div><div className="eyebrow">Claimed</div><div className="text-3xl font-bold tabular-nums text-soft">{p.claimedScore}</div></div>
            <div><div className="eyebrow">Backed by evidence or test</div><div className="text-4xl font-bold tabular-nums text-brand">{p.provenScore}</div></div>
          </div>
          <p className="mt-3 text-sm text-soft">{p.controlsProven} of {p.controlsApplicable} controls are backed by evidence or a live test. Evidence files are hashed, not reviewed by maas.AI.</p>
        </div>
        <div className="card p-5">
          <h2 className="flex items-center gap-2 text-base font-bold"><ScanSearch className="size-4 text-brand" /> Live test</h2>
          {p.scan ? <>
            <div className="mt-3 text-3xl font-bold tabular-nums">{p.scan.score}<span className="text-base text-faint"> / 100</span></div>
            <p className="mt-3 text-sm text-soft">{p.scan.domain}, owner verified. {p.scan.passed} of {p.scan.total} checks passed on {day(p.scan.at)}.</p>
          </> : <p className="mt-3 text-sm text-soft">No live test is included in this attestation.</p>}
        </div>
      </section>

      {p.policiesApproved.length > 0 && (
        <section className="card mt-4 p-5">
          <h2 className="text-base">Approved policies</h2>
          <ul className="mt-2 grid gap-1 text-sm text-soft sm:grid-cols-2">{p.policiesApproved.map((t) => <li key={t}>{t}</li>)}</ul>
        </section>
      )}

      <section className="card mt-4 p-5 text-sm">
        <h2 className="text-base">Check it yourself</h2>
        <p className="mt-1 text-soft">Audit ledger: {p.ledger.entries} entries, head <code className="font-mono">{shortHash(p.ledger.head)}</code>.</p>
        <p className="mt-2 text-soft">Copy this signed bundle into the <Link href="/verify" className="font-semibold text-brand">verifier</Link>, or check it offline against our <a className="font-semibold text-brand" href="/.well-known/maas-attestation-key.json">public key</a>.</p>
        <textarea readOnly rows={4} value={bundle} aria-label="Signed bundle" className="input mt-3 font-mono text-xs" />
      </section>

      <p className="mt-6 text-sm text-faint">
        This records what was tested and declared on the dates shown. Claimed scores are the organization&apos;s own statements. It is not a guarantee against breach, a penetration test, or a certification.
      </p>
    </main>
  )
}
