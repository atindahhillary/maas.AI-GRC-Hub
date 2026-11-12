import { GuestStart } from '@/components/auth-form'

export const metadata = { title: 'Open the hub' }

// Beta: login removed. To bring it back, render <AuthForm mode="signin" /> here again.
export default async function SignIn({ searchParams }: { searchParams: Promise<{ next?: string }> }) {
  const { next } = await searchParams
  return <GuestStart next={next} />
}
