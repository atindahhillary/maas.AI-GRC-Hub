// Preloaded into `next start` by journey.cjs only. runScan re-reads _maas-verify.<domain> over DNS-over-HTTPS on every
// scan, and nobody here can publish that TXT record for example.com, so this answers that one name from the emulator DB.
// Every other lookup, including all of the scan's own checks, still goes to the real network.
const NAME = 'https://cloudflare-dns.com/dns-query?name=_maas-verify.example.com&'
const realFetch = globalThis.fetch

globalThis.fetch = async (input, init) => {
  if (!String(input?.url ?? input).startsWith(NAME)) return realFetch(input, init)
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY
  const res = await realFetch(`${process.env.NEXT_PUBLIC_SUPABASE_URL}/rest/v1/domains?select=token&domain=eq.example.com`, { headers: { apikey: key, authorization: `Bearer ${key}` } })
  const answer = (await res.json()).map((d) => ({ type: 16, data: `"maas-verify=${d.token}"` }))
  return new Response(JSON.stringify({ Status: 0, AD: false, Answer: answer }), { headers: { 'content-type': 'application/dns-json' } })
}
