import { BadgeCheck, CircleAlert } from 'lucide-react'
import { Logo } from '@/components/ui'
import { publicKeyInfo, verifySignature } from '@/lib/attest'
import { supabaseAnon } from '@/lib/supabase/server'

export const metadata = { title: 'Verify an attestation' }

type Result = { valid: false; reason: string } | { valid: true; domain: string; org: string; issued: string; expires: string; proven: number }

async function check(raw: string): Promise<Result> {
  try {
    const { canonical, signature } = JSON.parse(raw)
    if (typeof canonical !== 'string' || typeof signature !== 'string') return { valid: false, reason: 'That is not a signed bundle.' }
    if (!verifySignature(canonical, signature)) return { valid: false, reason: 'The content was changed, or it was not signed by us.' }
    const p = JSON.parse(canonical)
    if (new Date(p.expiresAt) < new Date()) return { valid: false, reason: `This attestation expired on ${String(p.expiresAt).slice(0, 10)}.` }
    const { data: live } = await supabaseAnon().rpc('attestation_live', { p_signature: signature })
    if (!live) return { valid: false, reason: 'The signature is genuine, but this attestation has been withdrawn or was never published.' }
    return { valid: true, domain: p.scan?.domain, org: p.org, issued: p.issuedAt, expires: p.expiresAt, proven: p.provenScore }
  } catch {
    return { valid: false, reason: 'That is not valid JSON.' }
  }
}

export default async function Verify({ searchParams }: { searchParams: Promise<{ bundle?: string }> }) {
  const { bundle } = await searchParams
  const result = bundle ? await check(bundle.slice(0, 20000)) : null
  return (
    <main className="mx-auto max-w-2xl px-5 py-10">
      <Logo />
      <h1 className="mt-10 text-4xl">Verify an attestation</h1>
      <p className="mt-2 text-soft">Paste the signed bundle from a trust page. We check its Ed25519 signature against our public key, <code className="font-mono text-sm">{publicKeyInfo().keyId}</code>, its expiry, and that it has not been withdrawn.</p>
      <form method="get" className="mt-6 space-y-3">
        <textarea name="bundle" required rows={7} defaultValue={bundle} aria-label="Signed bundle" className="input font-mono text-xs" />
        <button className="btn btn-primary">Verify</button>
      </form>
      {result && (
        <div role="status" className={`mt-5 flex gap-3 rounded-xl p-4 text-sm ${result.valid ? 'bg-low-soft text-low' : 'bg-high-soft text-high'}`}>
          {result.valid ? <BadgeCheck className="size-5 shrink-0" /> : <CircleAlert className="size-5 shrink-0" />}
          {result.valid
            ? <p><strong>Valid.</strong> Issued for {result.domain}, a domain whose owner was verified. The organization calls itself {result.org}. Issued {result.issued.slice(0, 10)}, backed by evidence or test {result.proven}, expires {result.expires.slice(0, 10)}.</p>
            : <p><strong>Not valid.</strong> {result.reason}</p>}
        </div>
      )}
    </main>
  )
}
