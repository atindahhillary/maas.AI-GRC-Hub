import { Logo } from '@/components/ui'

export const metadata = { title: 'Privacy' }

const CONTACT = 'atindahhillary@gmail.com'

const SECTIONS: [string, string[]][] = [
  ['What we collect', [
    'Your email address and a password, which is stored only as a secure hash by our sign-in provider.',
    'What your organization enters: its profile, assessment answers, risk register, policies, domains and live test results.',
    'Evidence files you upload. Each file is fingerprinted with a SHA-256 hash and stored privately.',
    'A tamper-evident record of changes made in your workspace, including who made them.',
  ]],
  ['Why we use it', [
    'Only to run your workspace: score your posture, generate recommendations, policies and attestations, and show them to the people in your organization.',
    'We do not sell data, show ads, or send your organization\'s data to AI providers.',
  ]],
  ['Who can see it', [
    'Only members of your organization, enforced by the database itself.',
    'If your organization publishes a trust page, anyone with the link can see the summary on it: scores, the verified domain and approved policy names. Never your answers, risks or files.',
  ]],
  ['Where it is stored', [
    'In the European Union, with Supabase in Frankfurt, Germany. The website runs on Vercel. This means data leaves Kenya, which the Kenya Data Protection Act 2019 allows with appropriate safeguards.',
  ]],
  ['How long we keep it', [
    'For as long as your account is active. Ask us to delete your account or organization and we will do it within 30 days.',
  ]],
  ['Your rights', [
    `You can ask to see, correct or delete your data at ${CONTACT}. If you are unhappy with our answer, you can complain to the Office of the Data Protection Commissioner in Kenya, or your local regulator.`,
  ]],
  ['Cookies', [
    'We only use the cookies needed to keep you signed in. No tracking or advertising cookies.',
  ]],
  ['This is a beta', [
    'maas.AI GRC Hub is in early testing. There are no automatic backups yet, so keep your own copies of important evidence files, and please do not upload anything you could not afford to lose.',
  ]],
]

export default function Privacy() {
  return (
    <main className="mx-auto max-w-2xl px-5 py-10">
      <Logo />
      <h1 className="mt-10 text-4xl">Privacy notice</h1>
      <p className="mt-2 text-soft">Last updated 4 November 2026. Plain language, no surprises.</p>
      {SECTIONS.map(([heading, lines]) => (
        <section key={heading} className="mt-8">
          <h2 className="text-lg">{heading}</h2>
          <ul className="mt-2 list-disc space-y-1.5 pl-5 text-soft">{lines.map((l) => <li key={l}>{l}</li>)}</ul>
        </section>
      ))}
      <p className="mt-10 text-sm text-faint">Questions: <a className="font-semibold text-brand" href={`mailto:${CONTACT}`}>{CONTACT}</a></p>
    </main>
  )
}
