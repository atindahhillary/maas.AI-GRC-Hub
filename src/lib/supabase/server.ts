import { createServerClient } from '@supabase/ssr'
import { createClient } from '@supabase/supabase-js'
import { cookies } from 'next/headers'

const url = process.env.NEXT_PUBLIC_SUPABASE_URL!
const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY!

// Acts as the signed-in user, so every query is bound by row level security.
export async function supabaseServer() {
  const store = await cookies()
  return createServerClient(url, key, {
    cookies: {
      getAll: () => store.getAll(),
      setAll: (list) => {
        // Server Components cannot set cookies, the proxy refreshes the session instead.
        try {
          list.forEach(({ name, value, options }) => store.set(name, value, options))
        } catch {}
      },
    },
  })
}

// Bypasses RLS. Only for writing machine-verified facts, always after requireRole().
export function supabaseService() {
  return createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!, {
    auth: { persistSession: false, autoRefreshToken: false },
  })
}

// Anonymous read for public trust pages.
export function supabaseAnon() {
  return createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } })
}
