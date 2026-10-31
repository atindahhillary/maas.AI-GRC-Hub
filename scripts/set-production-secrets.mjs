// Moves the two production secrets into Vercel without ever printing them.
// Run it yourself: the logins open your browser the first time.
import { generateKeyPairSync } from 'node:crypto'
import { spawnSync } from 'node:child_process'

const REF = 'rhcevrmhcifnrkmuiryb'
const TARGET = ['--project', 'maas-ai-grc-hub', '--scope', 'atindlets']
const NAMES = ['SUPABASE_SERVICE_ROLE_KEY', 'ATTESTATION_PRIVATE_KEY']

function must(args, options) {
  const res = spawnSync('npx', ['--yes', ...args], { shell: true, encoding: 'utf8', ...options })
  if (res.status !== 0) throw new Error(`npx ${args.slice(0, 3).join(' ')} failed:\n${res.stderr ?? ''}`)
  return res.stdout
}

must(['supabase', 'login'], { stdio: 'inherit' })
must(['vercel', 'login'], { stdio: 'inherit' })

const keys = JSON.parse(must(['supabase', 'projects', 'api-keys', '--project-ref', REF, '--reveal', '-o', 'json'], { stdio: 'pipe' }))
const service = keys.find((k) => k.name === 'service_role')?.api_key
if (!service) throw new Error('No service_role key found on this Supabase project.')
const signing = generateKeyPairSync('ed25519').privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64')

for (const [name, input] of [[NAMES[0], service], [NAMES[1], signing]]) {
  must(['vercel', 'env', 'add', name, '--environment', 'production', '--sensitive', '--force', '--yes', ...TARGET], { input, stdio: 'pipe' })
}

// Only Vercel's own list counts as success.
const list = must(['vercel', 'env', 'ls', '--environment', 'production', ...TARGET], { stdio: 'pipe' })
const missing = NAMES.filter((n) => !list.includes(n))
if (missing.length) throw new Error(`Vercel does not list: ${missing.join(', ')}`)
console.log(`Vercel now lists ${NAMES.join(' and ')}. Tell Claude to redeploy.`)
