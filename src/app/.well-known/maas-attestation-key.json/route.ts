import { publicKeyInfo } from '@/lib/attest'

export const GET = () => Response.json(publicKeyInfo(), { headers: { 'cache-control': 'public, max-age=3600', 'access-control-allow-origin': '*' } })
