// Moves the two production secrets into Vercel without ever printing them.
// Run it yourself: npx logins open your browser the first time.
import { generateKeyPairSync } from 'node:crypto'
import { spawnSync } from 'node:child_process'

const REF = 'rhcevrmhcifnrkmuiryb'
const SCOPE = 'atindlets'
const PROJECT = 'maas-ai-grc-hub'

const run = (args, options = {}) => {
  const res = spawnSync('npx', ['--yes', ...args], { shell: true, encoding: 'utf8', stdio: options.input === undefined && !options.capture ? 'inherit' : 'pipe', ...options })
  if (res.status !== 0) throw new Error(`Failed: npx ${args.slice(0, 3).join(' ')}`)
  return res.stdout
}

run(['supabase', 'login'])
run(['vercel', 'login'])
run(['vercel', 'link', '--yes', '--project', PROJECT, '--scope', SCOPE])

const keys = JSON.parse(run(['supabase', 'projects', 'api-keys', '--project-ref', REF, '--reveal', '-o', 'json'], { capture: true }))
const service = keys.find((k) => k.name === 'service_role')?.api_key
if (!service) throw new Error('No service_role key found on this Supabase project.')
const signing = generateKeyPairSync('ed25519').privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64')

for (const [name, input] of [['SUPABASE_SERVICE_ROLE_KEY', service], ['ATTESTATION_PRIVATE_KEY', signing]]) {
  run(['vercel', 'env', 'add', name, 'production', '--sensitive', '--force', '--yes', '--scope', SCOPE], { input })
  console.log(`Saved ${name}`)
}
console.log('Done. Tell Claude to redeploy.')
