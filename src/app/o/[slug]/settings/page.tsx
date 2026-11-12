import { PageHead, Panel, day } from '@/components/ui'
import { ProfileFields } from '@/components/profile-fields'
import { atLeast } from '@/lib/access'
import { loadState } from '@/lib/load'
import { InviteForm, MemberRemove, Mfa, ProfileForm } from './forms'

export const metadata = { title: 'Settings' }

export default async function Settings({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params
  const { supabase, org, role, user } = await loadState(slug)
  const admin = atLeast(role, 'admin')
  // Beta guests have no email, so invites and two-factor have nothing to attach to.
  const guest = !!user.is_anonymous
  const [{ data: members }, { data: invites }] = await Promise.all([
    supabase.from('members').select('user_id, email, role').eq('org_id', org.id).order('created_at'),
    admin ? supabase.from('invites').select('id, email, role, expires_at').eq('org_id', org.id).is('accepted_at', null) : Promise.resolve({ data: [] }),
  ])
  return (
    <div>
      <PageHead title="Settings" />
      <div className="grid gap-3 xl:grid-cols-[1.5fr_1fr]">
        <Panel title="Organization profile">
          <p className="mb-4 text-sm text-soft">This tailors your controls, guardrails, policies and custom system.</p>
          <ProfileForm slug={slug} name={org.name} disabled={!admin}><ProfileFields profile={org.profile} /></ProfileForm>
        </Panel>
        <div className="space-y-3">
          {!guest && <Panel title="Your sign-in"><Mfa /></Panel>}
          <Panel title="Team">
            <ul className="divide-y divide-line text-sm">
              {(members ?? []).map((m) => (
                <li key={m.user_id} className="flex items-center justify-between gap-2 py-2">
                  <span className="min-w-0 truncate">{m.email || 'Guest'}<span className="ml-2 text-xs capitalize text-faint">{m.role}</span></span>
                  {admin && m.role !== 'owner' && m.user_id !== user.id && <MemberRemove slug={slug} userId={m.user_id} />}
                </li>
              ))}
              {(invites ?? []).map((i) => (
                <li key={i.id} className="flex justify-between gap-2 py-2 text-soft"><span className="truncate">{i.email}</span><span className="shrink-0 text-xs text-faint">Invited, until {day(i.expires_at)}</span></li>
              ))}
            </ul>
            {admin && !guest && <InviteForm slug={slug} />}
          </Panel>
        </div>
      </div>
    </div>
  )
}
