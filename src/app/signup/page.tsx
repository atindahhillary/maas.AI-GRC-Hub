import { AuthForm } from '@/components/auth-form'

export const metadata = { title: 'Create account' }

export default async function SignUp({ searchParams }: { searchParams: Promise<{ next?: string }> }) {
  const { next } = await searchParams
  return <AuthForm mode="signup" next={next} />
}
