import { publicKeyInfo } from '@/lib/attest'
import { supabaseService } from '@/lib/supabase/server'

export const dynamic = 'force-dynamic'

// Proves the server secrets work without exposing any data: only booleans leave.
export async function GET() {
  let database = false
  let signing = false
  try {
    const { error } = await supabaseService().from('orgs').select('id', { head: true, count: 'exact' })
    database = !error
  } catch {}
  try {
    signing = !!publicKeyInfo().keyId
  } catch {}
  const ok = database && signing
  return Response.json({ ok, database, signing }, { status: ok ? 200 : 503, headers: { 'cache-control': 'no-store' } })
}
