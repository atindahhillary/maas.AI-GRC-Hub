import { lookup } from 'node:dns/promises'
import { BlockList, isIP } from 'node:net'
import https from 'node:https'
import http from 'node:http'
import tls from 'node:tls'

// SSRF defence: the scanner only ever connects to public addresses. The check runs inside
// the socket's own DNS lookup, so a DNS change after verification (rebinding) cannot slip past.
const BLOCKED = new BlockList()
for (const [net, bits] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 3]] as const) BLOCKED.addSubnet(net, bits, 'ipv4')
for (const [net, bits] of [['::', 96], ['64:ff9b::', 96], ['100::', 64], ['2001::', 32], ['2001:db8::', 32], ['2002::', 16], ['fc00::', 7], ['fe80::', 10], ['fec0::', 10], ['ff00::', 8]] as const) BLOCKED.addSubnet(net, bits, 'ipv6')

export function isPublicIp(ip: string): boolean {
  const version = isIP(ip)
  return version !== 0 && !BLOCKED.check(ip, version === 4 ? 'ipv4' : 'ipv6')
}

type LookupCb = (err: NodeJS.ErrnoException | null, address?: unknown, family?: number) => void

export function safeLookup(hostname: string, options: unknown, cb: LookupCb) {
  const all = typeof options === 'object' && options !== null && (options as { all?: boolean }).all
  lookup(hostname, { all: true }).then(
    (addrs) => {
      const blocked = addrs.find((a) => !isPublicIp(a.address))
      if (blocked || addrs.length === 0) return cb(Object.assign(new Error('blocked address'), { code: 'EBLOCKED' }))
      if (all) cb(null, addrs)
      else cb(null, addrs[0].address, addrs[0].family)
    },
    (err) => cb(err),
  )
}

export interface Fetched { status: number; headers: Record<string, string | string[] | undefined>; body: string }

const MAX_BODY = 64 * 1024

export function get(url: string, timeoutMs = 8000): Promise<Fetched> {
  const u = new URL(url)
  const lib = u.protocol === 'https:' ? https : http
  return new Promise((resolve, reject) => {
    const req = lib.request(
      u,
      { method: 'GET', lookup: safeLookup as never, timeout: timeoutMs, headers: { 'user-agent': 'maasAI-GRC-Scanner/1.0 (owner-verified scan)', accept: '*/*' } },
      (res) => {
        const chunks: Buffer[] = []
        let size = 0
        res.on('data', (c: Buffer) => {
          size += c.length
          if (size <= MAX_BODY) chunks.push(c)
          else res.destroy()
        })
        const done = () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') })
        res.on('end', done)
        res.on('close', done)
      },
    )
    req.on('timeout', () => req.destroy(new Error('timeout')))
    req.on('error', reject)
    req.end()
  })
}

export interface TlsInfo { protocol: string | null; validTo: string | null; authorized: boolean; error?: string }

export function tlsInfo(host: string, timeoutMs = 8000): Promise<TlsInfo> {
  return new Promise((resolve) => {
    // Verification off on purpose: this probe sends no data and must connect to a bad cert to report it.
    const socket = tls.connect({ host, port: 443, servername: host, lookup: safeLookup as never, timeout: timeoutMs, rejectUnauthorized: false })
    const finish = (info: TlsInfo) => { socket.destroy(); resolve(info) }
    socket.once('secureConnect', () => {
      const cert = socket.getPeerCertificate()
      finish({ protocol: socket.getProtocol(), validTo: cert?.valid_to ?? null, authorized: socket.authorized, error: socket.authorizationError ? String(socket.authorizationError) : undefined })
    })
    socket.once('timeout', () => finish({ protocol: null, validTo: null, authorized: false, error: 'timeout' }))
    socket.once('error', (e) => finish({ protocol: null, validTo: null, authorized: false, error: e.message }))
  })
}

export interface DnsAnswer { ok: boolean; secure: boolean; records: string[] }

// DNS over HTTPS gives us the DNSSEC validation flag, which node:dns does not expose.
export async function dns(name: string, type: string): Promise<DnsAnswer> {
  const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}&do=1`, {
    headers: { accept: 'application/dns-json' },
    signal: AbortSignal.timeout(6000),
  })
  if (!res.ok) throw new Error(`DNS lookup failed for ${name}`)
  const data = (await res.json()) as { Status: number; AD?: boolean; Answer?: { type: number; data: string }[] }
  const wanted: Record<string, number> = { TXT: 16, MX: 15, CAA: 257, A: 1, AAAA: 28 }
  const records = (data.Answer ?? []).filter((a) => a.type === wanted[type]).map((a) => a.data.replace(/^"|"$/g, '').replace(/"\s*"/g, ''))
  return { ok: data.Status === 0, secure: !!data.AD, records }
}
