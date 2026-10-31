import { LogOut } from 'lucide-react'
import { Nav } from '@/components/nav'
import { Logo } from '@/components/ui'
import { loadState } from '@/lib/load'
import { recommendations } from '@/lib/posture'
import { signOut } from './actions'

export default async function OrgLayout({ params, children }: { params: Promise<{ slug: string }>; children: React.ReactNode }) {
  const { slug } = await params
  const { org, role, user, states, scan } = await loadState(slug)
  const open = recommendations(states, scan).length
  return (
    <div className="min-h-dvh lg:grid lg:grid-cols-[15rem_minmax(0,1fr)]">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-50 focus:rounded-md focus:bg-brand focus:px-3 focus:py-2 focus:text-brand-ink">Skip to content</a>
      <aside className="no-print flex flex-col gap-4 border-b border-line bg-rail p-3 lg:sticky lg:top-0 lg:h-dvh lg:overflow-y-auto lg:border-b-0 lg:border-r lg:p-4">
        <div className="px-1 lg:py-1"><Logo /></div>
        <Nav slug={slug} badges={{ '/recommendations': open }} />
        <div className="mt-auto hidden rounded-lg border border-line bg-card p-3 text-xs lg:block">
          <div className="truncate font-semibold">{user.email}</div>
          <div className="capitalize text-faint">{role}</div>
          <form action={signOut}><button className="mt-2 inline-flex items-center gap-1.5 text-soft hover:text-ink"><LogOut className="size-3.5" /> Sign out</button></form>
        </div>
      </aside>
      <div className="min-w-0">
        <header className="no-print flex items-center justify-between gap-3 border-b border-line px-5 py-3">
          <div className="min-w-0">
            <div className="truncate font-semibold">{org.name}</div>
            <div className="text-xs text-faint">{scan ? `Last live test ${new Date(scan.created_at).toLocaleDateString('en-GB', { day: 'numeric', month: 'short' })} on ${scan.domain}` : 'No live test yet'}</div>
          </div>
          <form action={signOut} className="lg:hidden"><button className="btn btn-ghost" aria-label="Sign out"><LogOut className="size-4" /></button></form>
        </header>
        <main id="main" tabIndex={-1} className="p-4 lg:p-5">{children}</main>
      </div>
    </div>
  )
}
