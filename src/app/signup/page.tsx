import { redirect } from 'next/navigation'

// Beta: login removed, old /signup links open a guest workspace. To restore, render <AuthForm mode="signup" />.
export default async function SignUp({ searchParams }: { searchParams: Promise<{ next?: string }> }) {
  const { next } = await searchParams
  redirect(next ? `/signin?next=${encodeURIComponent(next)}` : '/signin')
}
