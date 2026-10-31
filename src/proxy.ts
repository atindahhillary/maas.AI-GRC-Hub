import { createServerClient } from '@supabase/ssr'
import { NextResponse, type NextRequest } from 'next/server'

const SUPABASE_ORIGIN = new URL(process.env.NEXT_PUBLIC_SUPABASE_URL!).origin

// Refreshes the session cookie, sets a per-request CSP and keeps signed-out visitors out of workspaces.
export async function proxy(request: NextRequest) {
  const nonce = btoa(crypto.randomUUID())
  const dev = process.env.NODE_ENV === 'development'
  const csp = [
    `default-src 'self'`,
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${dev ? " 'unsafe-eval'" : ''}`,
    `style-src 'self' 'unsafe-inline'`,
    `img-src 'self' data:`,
    `font-src 'self'`,
    `connect-src 'self' ${SUPABASE_ORIGIN}${dev ? ' ws:' : ''}`,
    `object-src 'none'`,
    `base-uri 'self'`,
    `form-action 'self'`,
    `frame-ancestors 'none'`,
  ].join('; ')
  request.headers.set('x-nonce', nonce)
  request.headers.set('content-security-policy', csp)
  let response = NextResponse.next({ request })
  const withCsp = (res: NextResponse) => (res.headers.set('content-security-policy', csp), res)
  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY!,
    {
      cookieOptions: { secure: !dev },
      cookies: {
        getAll: () => request.cookies.getAll(),
        setAll: (list) => {
          list.forEach(({ name, value }) => request.cookies.set(name, value))
          response = NextResponse.next({ request })
          list.forEach(({ name, value, options }) => response.cookies.set(name, value, options))
        },
      },
    },
  )
  const { data } = await supabase.auth.getUser()
  const path = request.nextUrl.pathname
  const gated = path.startsWith('/o/') || path === '/app' || path === '/onboarding' || path.startsWith('/invite/')
  if (!data.user && gated) {
    const to = request.nextUrl.clone()
    to.pathname = '/signin'
    to.search = `?next=${encodeURIComponent(path)}`
    const redirect = NextResponse.redirect(to)
    response.cookies.getAll().forEach((c) => redirect.cookies.set(c))
    return withCsp(redirect)
  }
  return withCsp(response)
}

export const config = { matcher: ['/((?!_next/static|_next/image|favicon|.well-known).*)'] }
