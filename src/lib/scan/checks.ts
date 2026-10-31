import { dns, get, tlsInfo, type Fetched } from './fetch'

export type Outcome = 'pass' | 'warn' | 'fail' | 'info'
export interface CheckResult { id: string; group: 'Email' | 'Encryption' | 'Web' | 'Exposure'; title: string; outcome: Outcome; detail: string; weight: 1 | 2 | 3 }
export type CheckDef = Pick<CheckResult, 'id' | 'group' | 'title' | 'weight'>

// Header values are never stored in full, results may be shown on a public trust page.
const first = (h: string | string[] | undefined) => (Array.isArray(h) ? h[0] : h)
const has = (res: Fetched | null, name: string) => !!first(res?.headers[name])

async function homepage(domain: string): Promise<{ res: Fetched | null; host: string }> {
  for (const host of [domain, `www.${domain}`]) {
    const res = await get(`https://${host}/`).catch(() => null)
    if (!res) continue
    if (res.status >= 300 && res.status < 400) {
      const loc = first(res.headers.location) ?? ''
      const target = loc.startsWith('/') ? null : new URL(loc, `https://${host}`)
      // Follow one hop, only inside the verified domain.
      if (target && target.protocol === 'https:' && (target.hostname === domain || target.hostname.endsWith(`.${domain}`))) {
        const next = await get(target.href).catch(() => null)
        if (next) return { res: next, host: target.hostname }
      }
    }
    return { res, host }
  }
  return { res: null, host: domain }
}

export async function runChecks(domain: string): Promise<CheckResult[]> {
  const [txt, dmarc, mx, caa, apex, selectors, tlsApex, http] = await Promise.all([
    dns(domain, 'TXT'),
    dns(`_dmarc.${domain}`, 'TXT'),
    dns(domain, 'MX'),
    dns(domain, 'CAA'),
    dns(domain, 'A'),
    Promise.all(['google', 'selector1', 'selector2', 'default', 'k1', 'mail', 's1', 's2'].map((s) => dns(`${s}._domainkey.${domain}`, 'TXT').catch(() => null))),
    tlsInfo(domain),
    get(`http://${domain}/`).catch(() => null),
  ])
  const { res, host } = await homepage(domain)
  const tlsInfoFor = tlsApex.protocol || host === domain ? tlsApex : await tlsInfo(host)
  const origin = `https://${host}`
  const [env, git, sectxt] = await Promise.all([
    get(`${origin}/.env`).catch(() => null),
    get(`${origin}/.git/HEAD`).catch(() => null),
    get(`${origin}/.well-known/security.txt`).catch(() => null),
  ])
  const out: CheckResult[] = []
  const add = (r: CheckResult) => out.push(r)

  const spf = txt.records.filter((r) => /^v=spf1/i.test(r))
  add({
    id: 'dns.spf', group: 'Email', title: 'SPF sender policy', weight: 3,
    ...(spf.length === 1 && /[-~]all/.test(spf[0]) ? { outcome: 'pass', detail: 'One SPF record that ends with a restrictive all.' }
      : spf.length === 1 ? { outcome: 'warn', detail: 'SPF exists but does not end in -all or ~all, so anyone may still send as you.' }
      : spf.length > 1 ? { outcome: 'fail', detail: 'More than one SPF record. Receivers treat this as an error.' }
      : { outcome: mx.records.length ? 'fail' : 'warn', detail: 'No SPF record. Anyone can send mail that claims to be from this domain.' }) as Pick<CheckResult, 'outcome' | 'detail'>,
  })
  const dm = dmarc.records.find((r) => /^v=DMARC1/i.test(r))
  const policy = dm?.match(/;\s*p=(\w+)/i)?.[1]?.toLowerCase()
  add({
    id: 'dns.dmarc', group: 'Email', title: 'DMARC enforcement', weight: 3,
    ...(policy === 'reject' || policy === 'quarantine' ? { outcome: 'pass', detail: `DMARC is enforcing with p=${policy}.` }
      : policy === 'none' ? { outcome: 'warn', detail: 'DMARC is monitoring only (p=none), spoofed mail is still delivered.' }
      : { outcome: 'fail', detail: 'No DMARC record. Attackers can impersonate this domain in phishing mail.' }) as Pick<CheckResult, 'outcome' | 'detail'>,
  })
  add({
    id: 'dns.dkim', group: 'Email', title: 'DKIM signing', weight: 2,
    ...(selectors.some((s) => s?.records.some((r) => /p=/.test(r))) ? { outcome: 'pass', detail: 'A DKIM key was found on a common selector.' }
      : { outcome: 'info', detail: 'No DKIM key on common selectors. Your provider may use a custom selector, so check this by hand.' }) as Pick<CheckResult, 'outcome' | 'detail'>,
  })
  add({ id: 'dns.dnssec', group: 'Email', title: 'DNSSEC', weight: 1, outcome: apex.secure ? 'pass' : 'warn', detail: apex.secure ? 'DNS answers are cryptographically validated.' : 'DNS answers are not signed, so they can be forged in transit.' })
  add({ id: 'dns.caa', group: 'Email', title: 'CAA certificate rule', weight: 1, outcome: caa.records.length ? 'pass' : 'warn', detail: caa.records.length ? 'CAA limits which authorities may issue certificates.' : 'Any certificate authority may issue for this domain.' })

  const https = !!tlsInfoFor.protocol
  add({ id: 'tls.https', group: 'Encryption', title: 'Valid HTTPS certificate', weight: 3, outcome: https && tlsInfoFor.authorized ? 'pass' : 'fail', detail: !https ? 'HTTPS is not reachable on this domain.' : tlsInfoFor.authorized ? 'The certificate chain validates.' : `The certificate does not validate (${tlsInfoFor.error}).` })
  add({ id: 'tls.version', group: 'Encryption', title: 'Modern TLS', weight: 2, outcome: tlsInfoFor.protocol === 'TLSv1.3' ? 'pass' : tlsInfoFor.protocol === 'TLSv1.2' ? 'warn' : 'fail', detail: tlsInfoFor.protocol ? `Negotiated ${tlsInfoFor.protocol}.` : 'No TLS connection was made.' })
  const days = tlsInfoFor.validTo ? Math.floor((Date.parse(tlsInfoFor.validTo) - Date.now()) / 86400000) : null
  add({ id: 'tls.expiry', group: 'Encryption', title: 'Certificate expiry', weight: 2, outcome: days === null || days < 7 ? 'fail' : days < 21 ? 'warn' : 'pass', detail: days === null ? 'Could not read the certificate.' : `${days} days until the certificate expires.` })
  const httpLoc = first(http?.headers.location) ?? ''
  add({ id: 'tls.redirect', group: 'Encryption', title: 'HTTP redirects to HTTPS', weight: 2, outcome: http && http.status >= 300 && http.status < 400 && httpLoc.startsWith('https://') ? 'pass' : http ? 'fail' : 'info', detail: !http ? 'Plain HTTP is not reachable.' : httpLoc.startsWith('https://') ? 'Plain HTTP visitors are moved to HTTPS.' : 'Plain HTTP is served without a redirect, so traffic can be read or changed.' })

  const hsts = first(res?.headers['strict-transport-security'])
  const maxAge = Number(hsts?.match(/max-age=(\d+)/i)?.[1] ?? 0)
  add({ id: 'web.hsts', group: 'Web', title: 'HSTS', weight: 2, outcome: maxAge >= 15552000 ? 'pass' : hsts ? 'warn' : 'fail', detail: maxAge >= 15552000 ? 'Browsers are told to always use HTTPS.' : hsts ? 'HSTS is set, but for under six months.' : 'Browsers are not told to insist on HTTPS.' })
  const csp = first(res?.headers['content-security-policy'])
  add({ id: 'web.csp', group: 'Web', title: 'Content Security Policy', weight: 2, outcome: csp ? (/unsafe-inline/.test(csp) && /script-src/.test(csp) ? 'warn' : 'pass') : 'fail', detail: csp ? (/unsafe-inline/.test(csp) ? 'CSP is present but allows inline scripts.' : 'CSP limits what the page can load.') : 'No CSP, so an injected script runs unhindered.' })
  add({ id: 'web.nosniff', group: 'Web', title: 'MIME sniffing protection', weight: 1, outcome: has(res, 'x-content-type-options') ? 'pass' : 'fail', detail: has(res, 'x-content-type-options') ? 'X-Content-Type-Options is set.' : 'X-Content-Type-Options is missing.' })
  const frame = has(res, 'x-frame-options') || /frame-ancestors/.test(csp ?? '')
  add({ id: 'web.frame', group: 'Web', title: 'Clickjacking protection', weight: 2, outcome: frame ? 'pass' : 'fail', detail: frame ? 'The site restricts who may frame it.' : 'Any site can embed this page in a frame.' })
  add({ id: 'web.referrer', group: 'Web', title: 'Referrer policy', weight: 1, outcome: has(res, 'referrer-policy') ? 'pass' : 'warn', detail: has(res, 'referrer-policy') ? 'Referrer-Policy is set.' : 'Referrer-Policy is missing, full URLs may leak to other sites.' })
  add({ id: 'web.permissions', group: 'Web', title: 'Permissions policy', weight: 1, outcome: has(res, 'permissions-policy') ? 'pass' : 'warn', detail: has(res, 'permissions-policy') ? 'Permissions-Policy is set.' : 'Permissions-Policy is missing.' })
  const cookies = ([res?.headers['set-cookie']].flat().filter(Boolean)) as string[]
  const weak = cookies.filter((c) => !/;\s*secure/i.test(c) || !/;\s*samesite=/i.test(c))
  add({ id: 'web.cookies', group: 'Web', title: 'Cookie flags', weight: 2, outcome: !cookies.length ? 'info' : weak.length ? 'fail' : 'pass', detail: !cookies.length ? 'The homepage sets no cookies.' : weak.length ? `${weak.length} of ${cookies.length} cookies lack Secure or SameSite.` : 'All homepage cookies carry Secure and SameSite.' })
  const server = first(res?.headers.server) ?? ''
  const leaky = /\d/.test(server) || has(res, 'x-powered-by')
  add({ id: 'web.server', group: 'Web', title: 'Version disclosure', weight: 1, outcome: leaky ? 'warn' : 'pass', detail: leaky ? 'Response headers reveal software versions.' : 'No software versions in response headers.' })

  // A body match avoids false alarms from sites that answer 200 to every path.
  const envExposed = env?.status === 200 && /^[A-Z][A-Z0-9_]{2,}=/m.test(env.body) && !/<html/i.test(env.body)
  add({ id: 'exposure.env', group: 'Exposure', title: 'Exposed .env secrets file', weight: 3, outcome: envExposed ? 'fail' : 'pass', detail: envExposed ? 'A .env file is publicly readable. Rotate every secret in it today.' : 'No readable .env file at the web root.' })
  const gitExposed = git?.status === 200 && /^ref: refs\//.test(git.body)
  add({ id: 'exposure.git', group: 'Exposure', title: 'Exposed .git folder', weight: 3, outcome: gitExposed ? 'fail' : 'pass', detail: gitExposed ? 'The .git folder is public, your source code can be downloaded.' : 'No readable .git folder at the web root.' })
  const hasSec = sectxt?.status === 200 && /^contact:/im.test(sectxt.body)
  add({ id: 'exposure.securitytxt', group: 'Exposure', title: 'security.txt contact', weight: 1, outcome: hasSec ? 'pass' : 'warn', detail: hasSec ? 'Researchers know how to reach you.' : 'No security.txt, so researchers have no clear way to report a flaw.' })
  return out
}

// info results carry no weight: the test could not decide either way.
export function scanScore(results: CheckResult[]): number {
  const scored = results.filter((r) => r.outcome !== 'info')
  const total = scored.reduce((s, r) => s + r.weight, 0)
  const got = scored.reduce((s, r) => s + r.weight * (r.outcome === 'pass' ? 1 : r.outcome === 'warn' ? 0.5 : 0), 0)
  return total ? Math.round((got / total) * 100) : 0
}

export const CHECK_RISK: Record<string, { description: string; consequence: string; likelihood: 1 | 2 | 3 | 4 | 5; impact: 1 | 2 | 3 | 4 | 5; mitigation: string; category: string }> = {
  'dns.spf': { description: 'Domain has no effective SPF policy, so attackers can send mail that appears to come from it', consequence: 'Staff, customers and partners receive convincing phishing or invoice fraud from your own domain', likelihood: 4, impact: 4, mitigation: 'Publish one SPF record listing approved senders, ending in -all', category: 'Security' },
  'dns.dmarc': { description: 'Domain has no enforced DMARC policy, so spoofed mail is still delivered', consequence: 'Business email compromise and reputational damage from impersonation', likelihood: 4, impact: 4, mitigation: 'Publish DMARC at p=none, review reports, then move to quarantine and reject', category: 'Security' },
  'tls.https': { description: 'Website HTTPS is missing or the certificate does not validate', consequence: 'Credentials and data can be intercepted, browsers warn visitors away', likelihood: 3, impact: 4, mitigation: 'Install a valid certificate with automatic renewal', category: 'Security' },
  'tls.redirect': { description: 'Website serves plain HTTP without redirecting to HTTPS', consequence: 'Sessions and form data can be read or altered in transit', likelihood: 3, impact: 3, mitigation: 'Redirect all HTTP traffic to HTTPS and enable HSTS', category: 'Security' },
  'web.csp': { description: 'Website has no Content Security Policy', consequence: 'A cross-site scripting flaw can steal sessions and customer data', likelihood: 3, impact: 3, mitigation: 'Deploy a CSP in report-only mode, then enforce it', category: 'Security' },
  'web.frame': { description: 'Website can be framed by any other site', consequence: 'Clickjacking can trick users into unintended actions', likelihood: 2, impact: 3, mitigation: 'Set frame-ancestors in CSP or X-Frame-Options', category: 'Security' },
  'web.hsts': { description: 'Browsers are not told to insist on HTTPS for this site', consequence: 'A first visit on hostile Wi-Fi can be downgraded and intercepted', likelihood: 2, impact: 3, mitigation: 'Send Strict-Transport-Security with a max-age of at least 180 days', category: 'Security' },
  'web.cookies': { description: 'Website cookies lack Secure or SameSite flags', consequence: 'Session cookies can leak or be abused in cross-site attacks', likelihood: 3, impact: 3, mitigation: 'Set Secure, HttpOnly and SameSite on all session cookies', category: 'Security' },
  'exposure.env': { description: 'A .env file with secrets is publicly readable on the website', consequence: 'Database, API and cloud credentials are open to anyone', likelihood: 5, impact: 5, mitigation: 'Remove the file, block dotfiles at the web server, rotate every secret', category: 'Security' },
  'exposure.git': { description: 'The .git folder is publicly readable on the website', consequence: 'Source code and any committed credentials can be downloaded', likelihood: 5, impact: 4, mitigation: 'Remove .git from the web root, block dotfiles, rotate committed secrets', category: 'Security' },
}
