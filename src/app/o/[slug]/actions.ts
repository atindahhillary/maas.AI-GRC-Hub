'use server'

import { createHash, randomBytes } from 'node:crypto'
import { revalidatePath } from 'next/cache'
import { redirect } from 'next/navigation'
import { requireRole } from '@/lib/access'
import { signPayload, type AttestationPayload } from '@/lib/attest'
import { POLICIES } from '@/lib/content/policies'
import { parseProfile } from '@/lib/profile'
import { loadState } from '@/lib/load'
import { posture, recommendations } from '@/lib/posture'
import { renderPolicy } from '@/lib/policy'
import { runChecks, scanScore } from '@/lib/scan/checks'
import { dns } from '@/lib/scan/fetch'
import { supabaseService } from '@/lib/supabase/server'

export type ActionResult = { error?: string; ok?: string }

const text = (v: FormDataEntryValue | null, max: number) => String(v ?? '').trim().slice(0, max)
const scale = (v: FormDataEntryValue | null) => {
  const n = Number(v)
  return Number.isInteger(n) && n >= 1 && n <= 5 ? n : null
}
const date = (v: FormDataEntryValue | null) => (/^\d{4}-\d{2}-\d{2}$/.test(String(v ?? '')) ? String(v) : null)
const safe = async (fn: () => Promise<ActionResult | void>): Promise<ActionResult> => {
  try {
    return (await fn()) ?? {}
  } catch (e) {
    // redirect() and notFound() signal through exceptions and must keep travelling.
    if (e && typeof e === 'object' && 'digest' in e) throw e
    return { error: e instanceof Error ? e.message : 'Something went wrong.' }
  }
}

// Risk register -------------------------------------------------------------------------------

export async function saveRisk(slug: string, id: string | null, _: ActionResult, form: FormData): Promise<ActionResult> {
  return safe(async () => {
    const { supabase, org } = await requireRole(slug, 'analyst')
    const likelihood = scale(form.get('likelihood'))
    const impact = scale(form.get('impact'))
    const description = text(form.get('description'), 2000)
    if (!likelihood || !impact || description.length < 3) return { error: 'Describe the risk, then set likelihood and impact from 1 to 5.' }
    const STRATEGY = ['Mitigate', 'Accept', 'Transfer', 'Avoid']
    const STATUS = ['Open', 'In Progress', 'Closed', 'Accepted']
    const row = {
      org_id: org.id,
      description,
      consequence: text(form.get('consequence'), 2000),
      category: text(form.get('category'), 40) || 'Security',
      likelihood, impact,
      existing_controls: text(form.get('existing_controls'), 2000),
      strategy: STRATEGY.includes(String(form.get('strategy'))) ? String(form.get('strategy')) : 'Mitigate',
      mitigation: text(form.get('mitigation'), 2000),
      owner: text(form.get('owner'), 120),
      target_date: date(form.get('target_date')),
      status: STATUS.includes(String(form.get('status'))) ? String(form.get('status')) : 'Open',
      residual_likelihood: scale(form.get('residual_likelihood')),
      residual_impact: scale(form.get('residual_impact')),
      last_reviewed: new Date().toISOString().slice(0, 10),
    }
    const { error } = id
      ? await supabase.from('risks').update(row).eq('id', id).eq('org_id', org.id)
      : await supabase.from('risks').insert(row)
    if (error) return { error: error.message }
    revalidatePath(`/o/${slug}`, 'layout')
    return { ok: 'Saved' }
  })
}

export async function deleteRisk(slug: string, id: string) {
  return safe(async () => {
    const { supabase, org } = await requireRole(slug, 'admin')
    const { error } = await supabase.from('risks').delete().eq('id', id).eq('org_id', org.id)
    if (error) return { error: error.message }
    revalidatePath(`/o/${slug}`, 'layout')
  })
}

export async function raiseRisk(slug: string, key: string) {
  return safe(async () => {
    const { supabase, org, states, scan } = await loadState(slug, 'analyst')
    const rec = recommendations(states, scan).find((r) => r.key === key)
    if (!rec) return { error: 'That recommendation no longer applies.' }
    const { error } = await supabase.from('risks').insert({
      org_id: org.id, source_ref: rec.key, description: rec.risk.description, consequence: rec.risk.consequence,
      category: rec.risk.category, likelihood: rec.risk.likelihood, impact: rec.risk.impact,
      strategy: rec.risk.strategy, mitigation: rec.risk.mitigation,
    })
    if (error && error.code !== '23505') return { error: error.message }
    revalidatePath(`/o/${slug}`, 'layout')
  })
}

export async function addExampleRisks(slug: string) {
  return safe(async () => {
    const { supabase, org } = await requireRole(slug, 'analyst')
    const today = new Date().toISOString().slice(0, 10)
    const { error } = await supabase.from('risks').insert([
      { org_id: org.id, source_ref: 'example:1', description: 'Unpatched vulnerability on an internet-facing server could be exploited', consequence: 'Delayed patch cycle leaves a route to data theft or ransomware', category: 'Security', likelihood: 4, impact: 5, existing_controls: 'Monthly vulnerability scanning, web application firewall in place', mitigation: 'Accelerate patch SLA to 14 days for critical CVEs', residual_likelihood: 2, residual_impact: 5, status: 'In Progress', last_reviewed: today },
      { org_id: org.id, source_ref: 'example:2', description: 'Key vendor providing critical software support could go out of business or discontinue service', consequence: 'Vendor dependence with limited alternatives stalls operations', category: 'Third-Party', likelihood: 2, impact: 4, existing_controls: 'Annual vendor financial health check, source code escrow agreement', mitigation: 'Identify and vet a backup vendor, negotiate longer-term support contract', residual_likelihood: 1, residual_impact: 4, last_reviewed: today },
      { org_id: org.id, source_ref: 'example:3', description: 'Office Wi-Fi router is old and could fail, disrupting work for a few hours', consequence: 'Router is past typical service life, staff lose connectivity', category: 'Operational', likelihood: 3, impact: 1, existing_controls: 'Backup router kept in a closet', mitigation: 'Order a new router as a planned replacement', residual_likelihood: 1, residual_impact: 1, last_reviewed: today },
    ])
    if (error && error.code !== '23505') return { error: error.message }
    revalidatePath(`/o/${slug}`, 'layout')
  })
}

// Assessment ----------------------------------------------------------------------------------

export async function answerControl(slug: string, controlId: string, status: string, note: string) {
  return safe(async () => {
    const { supabase, org, user } = await requireRole(slug, 'analyst')
    if (!['yes', 'partial', 'no', 'na'].includes(status) || !/^[A-Z]{2,3}-\d{2}$/.test(controlId)) return { error: 'Invalid answer.' }
    const { error } = await supabase.from('answers').upsert({
      org_id: org.id, control_id: controlId, status, note: note.slice(0, 2000), answered_by: user.id, updated_at: new Date().toISOString(),
    })
    if (error) return { error: error.message }
    revalidatePath(`/o/${slug}`, 'layout')
  })
}

// The hash is taken here from the stored bytes, so it records what is really in the vault.
export async function recordEvidence(slug: string, controlId: string, path: string, name: string) {
  return safe(async () => {
    const { supabase, org, user } = await requireRole(slug, 'analyst')
    if (!path.startsWith(`${org.id}/`) || !/^[A-Z]{2,3}-\d{2}$/.test(controlId)) return { error: 'Invalid upload.' }
    const { data, error } = await supabase.storage.from('evidence').download(path)
    if (error || !data) return { error: 'Upload could not be read back.' }
    const bytes = Buffer.from(await data.arrayBuffer())
    const { error: insertError } = await supabaseService().from('evidence').insert({
      org_id: org.id, control_id: controlId, name: name.slice(0, 200), storage_path: path,
      sha256: createHash('sha256').update(bytes).digest('hex'), size_bytes: bytes.length, uploaded_by: user.id,
    })
    if (insertError) return { error: insertError.message }
    revalidatePath(`/o/${slug}`, 'layout')
  })
}

export async function evidenceLink(slug: string, path: string) {
  return safe(async () => {
    const { supabase, org } = await requireRole(slug, 'viewer')
    if (!path.startsWith(`${org.id}/`)) return { error: 'Not found.' }
    const { data, error } = await supabase.storage.from('evidence').createSignedUrl(path, 60)
    if (error || !data) return { error: 'Could not open the file.' }
    return { ok: data.signedUrl }
  })
}

// Domains and live tests ------------------------------------------------------------------------

export async function addDomain(slug: string, _: ActionResult, form: FormData): Promise<ActionResult> {
  return safe(async () => {
    const { supabase, org } = await requireRole(slug, 'admin')
    const domain = text(form.get('domain'), 253).toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '')
    if (!/^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)) return { error: 'Enter a domain such as example.org.' }
    const { error } = await supabase.from('domains').insert({ org_id: org.id, domain })
    if (error) return { error: error.code === '23505' ? 'That domain is already added.' : error.message }
    revalidatePath(`/o/${slug}/tests`)
  })
}

export async function verifyDomain(slug: string, domainId: string) {
  return safe(async () => {
    const { supabase, org } = await requireRole(slug, 'admin')
    const { data: d } = await supabase.from('domains').select('id, domain, token').eq('id', domainId).eq('org_id', org.id).single()
    if (!d) return { error: 'Domain not found.' }
    const found = await dns(`_maas-verify.${d.domain}`, 'TXT')
    if (!found.records.includes(`maas-verify=${d.token}`)) return { error: 'TXT record not found yet. DNS changes can take a few minutes.' }
    await supabaseService().from('domains').update({ verified_at: new Date().toISOString() }).eq('id', d.id)
    revalidatePath(`/o/${slug}/tests`)
    return { ok: 'Domain verified' }
  })
}

export async function runScan(slug: string, domainId: string) {
  return safe(async () => {
    const { supabase, org, user } = await requireRole(slug, 'analyst')
    const { data: d } = await supabase.from('domains').select('id, domain, verified_at').eq('id', domainId).eq('org_id', org.id).single()
    // Ownership proof is what authorizes us to probe a site at all.
    if (!d?.verified_at) return { error: 'Verify that you own this domain before testing it.' }
    const since = new Date(Date.now() - 10 * 60 * 1000).toISOString()
    const { count } = await supabase.from('scans').select('id', { count: 'exact', head: true }).eq('org_id', org.id).gte('created_at', since)
    if ((count ?? 0) >= 3) return { error: 'Three tests ran in the last 10 minutes. Please wait a little.' }
    const results = await runChecks(d.domain)
    const { error } = await supabaseService().from('scans').insert({
      org_id: org.id, domain_id: d.id, domain: d.domain, score: scanScore(results), results, started_by: user.id,
    })
    if (error) return { error: error.message }
    revalidatePath(`/o/${slug}`, 'layout')
  })
}

// Policies --------------------------------------------------------------------------------------

export async function generatePolicy(slug: string, templateId: string) {
  return safe(async () => {
    const { supabase, org } = await requireRole(slug, 'analyst')
    const tpl = POLICIES.find((p) => p.id === templateId)
    if (!tpl) return { error: 'Unknown policy.' }
    const { data: last } = await supabase.from('policies').select('version').eq('org_id', org.id).eq('template_id', tpl.id)
      .order('version', { ascending: false }).limit(1).maybeSingle()
    const { error } = await supabase.from('policies').insert({
      org_id: org.id, template_id: tpl.id, title: tpl.title, version: (last?.version ?? 0) + 1, body: renderPolicy(tpl, org.name, org.profile),
    })
    if (error) return { error: error.message }
    revalidatePath(`/o/${slug}/policies`)
  })
}

export async function approvePolicy(slug: string, policyId: string) {
  return safe(async () => {
    const { supabase, org, user } = await requireRole(slug, 'admin')
    const { data: p } = await supabase.from('policies').select('id, body, template_id, version').eq('id', policyId).eq('org_id', org.id).eq('status', 'draft').single()
    if (!p) return { error: 'Only a draft can be approved.' }
    const service = supabaseService()
    await service.from('policies').update({ status: 'retired' }).eq('org_id', org.id).eq('template_id', p.template_id).eq('status', 'approved')
    const months = (p.body as { reviewMonths: number }).reviewMonths
    const due = new Date()
    due.setMonth(due.getMonth() + months)
    const { error } = await service.from('policies').update({
      status: 'approved', approved_by: user.id, approved_by_email: user.email, approved_at: new Date().toISOString(),
      content_sha256: createHash('sha256').update(JSON.stringify(p.body)).digest('hex'), review_due: due.toISOString().slice(0, 10),
    }).eq('id', p.id)
    if (error) return { error: error.message }
    revalidatePath(`/o/${slug}`, 'layout')
  })
}

// Proof -----------------------------------------------------------------------------------------

export async function issueAttestation(slug: string) {
  return safe(async () => {
    const { supabase, org, states, scan } = await loadState(slug, 'admin')
    const p = posture(states)
    if (p.answered < p.total) return { error: `Answer every control first, ${p.total - p.answered} are left.` }
    const { data: chain } = await supabase.rpc('verify_ledger', { p_org: org.id }).single<{ ok: boolean; entries: number; head: string }>()
    if (!chain?.ok) return { error: 'The ledger failed verification, so nothing can be attested.' }
    const { data: approved } = await supabase.from('policies').select('title').eq('org_id', org.id).eq('status', 'approved')
    const issuedAt = new Date()
    const expiresAt = new Date(issuedAt.getTime() + 90 * 86400000)
    const payload: AttestationPayload = {
      version: 1, org: org.name, slug: org.slug, issuedAt: issuedAt.toISOString(), expiresAt: expiresAt.toISOString(),
      claimedScore: p.claimed, provenScore: p.proven, controlsApplicable: p.total, controlsProven: p.provenCount,
      frameworks: ['ISO/IEC 27001:2022', 'NIST CSF 2.0', 'CIS Controls v8'],
      scan: scan ? {
        domain: scan.domain, at: scan.created_at, score: scan.score,
        passed: scan.results.filter((r) => r.outcome === 'pass').length,
        total: scan.results.filter((r) => r.outcome !== 'info').length,
      } : null,
      policiesApproved: (approved ?? []).map((a) => a.title).sort(),
      ledger: { entries: Number(chain.entries), head: chain.head },
    }
    const { canonical, signature, keyId } = signPayload(payload)
    const { error } = await supabaseService().from('attestations').insert({
      org_id: org.id, slug: org.slug, payload, canonical, signature, key_id: keyId,
      issued_at: payload.issuedAt, expires_at: payload.expiresAt,
    })
    if (error) return { error: error.message }
    revalidatePath(`/o/${slug}/proof`)
    return { ok: 'Attestation signed' }
  })
}

export async function setPublished(slug: string, id: string, published: boolean) {
  return safe(async () => {
    const { supabase, org } = await requireRole(slug, 'admin')
    const { error } = await supabase.from('attestations').update({ published }).eq('id', id).eq('org_id', org.id)
    if (error) return { error: error.message }
    await supabase.from('orgs').update({ trust_enabled: published }).eq('id', org.id)
    revalidatePath(`/o/${slug}/proof`)
  })
}

// Settings --------------------------------------------------------------------------------------

export async function updateProfile(slug: string, _: ActionResult, form: FormData): Promise<ActionResult> {
  return safe(async () => {
    const { supabase, org } = await requireRole(slug, 'admin')
    const profile = parseProfile(form)
    if (!profile) return { error: 'Please complete every field.' }
    const { error } = await supabase.from('orgs').update({ name: text(form.get('name'), 120) || org.name, profile }).eq('id', org.id)
    if (error) return { error: error.message }
    revalidatePath(`/o/${slug}`, 'layout')
    return { ok: 'Profile saved. Controls, guardrails and blueprint have been re-tailored.' }
  })
}

export async function createInvite(slug: string, _: ActionResult, form: FormData): Promise<ActionResult> {
  return safe(async () => {
    const { supabase, org, user } = await requireRole(slug, 'admin')
    const email = text(form.get('email'), 254).toLowerCase()
    const role = String(form.get('role'))
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || !['admin', 'analyst', 'viewer'].includes(role)) return { error: 'Enter an email and a role.' }
    const token = randomBytes(24).toString('base64url')
    const { error } = await supabase.from('invites').insert({
      org_id: org.id, email, role, created_by: user.id, token_hash: createHash('sha256').update(token).digest('hex'),
    })
    if (error) return { error: error.message }
    revalidatePath(`/o/${slug}/settings`)
    // Shown once: only the hash is stored.
    return { ok: `/invite/${token}` }
  })
}

export async function removeMember(slug: string, userId: string) {
  return safe(async () => {
    const { supabase, org } = await requireRole(slug, 'admin')
    const { error, count } = await supabase.from('members').delete({ count: 'exact' }).eq('org_id', org.id).eq('user_id', userId)
    if (error) return { error: error.message }
    if (!count) return { error: 'The owner cannot be removed.' }
    revalidatePath(`/o/${slug}/settings`)
  })
}

export async function signOut() {
  const { supabaseServer } = await import('@/lib/supabase/server')
  await (await supabaseServer()).auth.signOut()
  redirect('/')
}

