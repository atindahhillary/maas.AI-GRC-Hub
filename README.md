# maas.AI GRC Hub

A multi-tenant governance, risk and compliance hub. Each organization creates an account and gets its own workspace to run real tests, manage risk, get tailored fixes, and prove its posture with signed evidence.

The principle: **reassurance is a sentence, proof is something a stranger can check.**

## What it does

| Area | What you get |
|---|---|
| Overview | Live KPI dashboard, risk distribution, regulatory footprint, priority findings, least proven areas, events timeline |
| Risk Register | Likelihood x impact scoring, inherent to residual risk, owners, deadlines, matrix, CSV export. Bands: Low 1-7, Medium 8-14, High 15-25 |
| Assessment | Plain-English controls tailored to the org's sector, size, data and platforms, mapped to ISO 27001, NIST CSF 2.0, CIS v8, Kenya DPA, GDPR, NIST AI RMF, ISO 42001 and the EU AI Act |
| Live Tests | 20 checks on an owner-verified domain: SPF, DMARC, DKIM, DNSSEC, CAA, TLS, security headers, cookies, exposed `.env` and `.git`, security.txt |
| Recommendations | Findings ranked by risk then effort, one click into the register |
| Guardrails | Paste-ready DNS, web server, identity, cloud and AI guardrails, each with how to prove it is on |
| Policies | SMART security and AI policies written for the org, each clause with a measure, target, owner and deadline, with approval and version history |
| Custom System | A phased security system design matched to size, platforms and budget |
| Proof | Claimed vs proven score, SHA-256 evidence vault, hash-chained audit ledger, Ed25519 signed attestations, public trust page and verifier |

## Claimed vs proven

Every control has an assurance level: machine tested, evidenced, claimed, or none. The dashboard shows both scores, so nobody confuses what they say with what they can show. Only a passing live test or evidence less than a year old counts as proven, and marking a control N/A does not raise the proven score. Evidence files are hashed, not reviewed by maas.AI, so public pages call this "backed by evidence or a test".

## Honest limits

- An attestation proves what was tested and declared on a date. It does not guarantee a breach cannot happen, and it does not replace a penetration test or a certification audit.
- Live tests see only what is public from the outside. The hub does not detect intrusions or monitor networks.
- The ledger catches edits by anyone without full database rights. A database administrator could still rewrite it, unless someone compares it with a signed bundle they kept. Publishing ledger heads to an outside log would close this gap and is not built yet.
- Generated policies are drafts for human review, not legal advice. Policies and guardrails are produced by a rules engine, so no customer security data goes to an AI provider.
- Framework mappings are a reference, not a certification claim.

## Stack

Next.js 16 (App Router), React 19, TypeScript, Tailwind 4, Supabase (Auth, Postgres row-level security, Storage). Hosted on Vercel.

## Run it

Needs Docker Desktop for the local Supabase stack. On Windows that needs WSL.

```bash
npm install
npx supabase init
npx supabase start
npx supabase db reset
npm run keys
```

Put the API URL, publishable key and service role key from `supabase start`, plus the key from `npm run keys`, into `.env.local` (see `.env.example`), then:

```bash
npm run dev
```

Open http://localhost:3100.

## Test it

```bash
npm test
```

The full browser journey runs real Postgres row-level security through a local Supabase emulator, with no Docker needed:

```bash
node tests/e2e/journey.cjs
```

## Security model

- Tenancy is enforced in Postgres by row-level security on every table, not in application code.
- Facts that prove something (scans, evidence records, attestations, domain verification) are written only by the server after a role check. Members can read them, never forge them.
- The scanner only touches domains proven by a DNS TXT record, only connects to public IP addresses, and checks that inside the socket's DNS lookup to stop rebinding.
- A user with two-factor enabled gets no data from an aal1 session, enforced in the database.

Report a vulnerability through GitHub security advisories on this repository.

## Going live

See [docs/DEPLOY.md](docs/DEPLOY.md).

## Credits

World map data from [@svg-maps/world](https://github.com/VictorCazanave/svg-maps), CC BY 4.0.
