// Independent check of a trust page, using nothing from this app.
// Usage: node scripts/verify-attestation.mjs <attestation.json> <key.json>
// Both files are downloadable from the public trust page.
import { readFileSync } from 'node:fs'
import { createPublicKey, verify } from 'node:crypto'

const [attestation, keyInfo] = process.argv.slice(2).map((p) => JSON.parse(readFileSync(p, 'utf8')))
const key = createPublicKey({ key: Buffer.from(keyInfo.publicKey, 'base64'), format: 'der', type: 'spki' })
const ok = verify(null, Buffer.from(attestation.canonical), key, Buffer.from(attestation.signature, 'base64'))
const expired = ok && new Date(JSON.parse(attestation.canonical).expiresAt) < new Date()
console.log(!ok ? 'INVALID: do not trust this attestation.' : expired ? 'EXPIRED: genuine, but no longer current.' : 'VALID: signed by this key, content unchanged. This offline check cannot see a withdrawal.')
process.exit(ok && !expired ? 0 : 1)
