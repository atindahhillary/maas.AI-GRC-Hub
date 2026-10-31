// Prints a new Ed25519 private key for ATTESTATION_PRIVATE_KEY. Store it as a server secret, never commit it.
import { generateKeyPairSync } from 'node:crypto'

const { privateKey } = generateKeyPairSync('ed25519')
console.log(privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'))
