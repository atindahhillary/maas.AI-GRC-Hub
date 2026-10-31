import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto'

export interface AttestationPayload {
  version: 1
  org: string
  slug: string
  issuedAt: string
  expiresAt: string
  claimedScore: number
  provenScore: number
  controlsApplicable: number
  controlsProven: number
  frameworks: string[]
  scan: { domain: string; at: string; score: number; passed: number; total: number } | null
  policiesApproved: string[]
  ledger: { entries: number; head: string }
}

// Sorted keys, so the signed bytes never depend on key order after a database round trip.
export function canonicalize(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`
  if (value && typeof value === 'object') {
    const obj = value as Record<string, unknown>
    return `{${Object.keys(obj).sort().map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`).join(',')}}`
  }
  return JSON.stringify(value)
}

const keyPair = () => {
  const der = Buffer.from(process.env.ATTESTATION_PRIVATE_KEY ?? '', 'base64')
  if (!der.length) throw new Error('ATTESTATION_PRIVATE_KEY is not set')
  const privateKey = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' })
  return { privateKey, publicKey: createPublicKey(privateKey) }
}

export function publicKeyInfo() {
  const spki = keyPair().publicKey.export({ format: 'der', type: 'spki' })
  return { algorithm: 'Ed25519', format: 'spki-der-base64', keyId: createHash('sha256').update(spki).digest('hex').slice(0, 16), publicKey: spki.toString('base64') }
}

export function signPayload(payload: AttestationPayload) {
  const canonical = canonicalize(payload)
  const signature = sign(null, Buffer.from(canonical), keyPair().privateKey).toString('base64')
  return { canonical, signature, keyId: publicKeyInfo().keyId }
}

export function verifySignature(canonical: string, signature: string, publicKeyB64 = publicKeyInfo().publicKey) {
  try {
    const key = createPublicKey({ key: Buffer.from(publicKeyB64, 'base64'), format: 'der', type: 'spki' })
    return verify(null, Buffer.from(canonical), key, Buffer.from(signature, 'base64'))
  } catch {
    return false
  }
}
