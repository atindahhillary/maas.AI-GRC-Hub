import { AuthForm } from '@/components/auth-form'

export const metadata = { title: 'Sign in' }

export default async function SignIn({ searchParams }: { searchParams: Promise<{ next?: string; confirmed?: string }> }) {
  const { next, confirmed } = await searchParams
  return <AuthForm mode="signin" next={next} notice={confirmed ? 'Email confirmed. Sign in to continue.' : undefined} />
}
