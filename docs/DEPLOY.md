# Going live

## 1. Database

Create a dedicated Supabase project. Do not share one with another app: this one holds customers' security weaknesses, and sharing would also share the user pool. Use a Pro project so backups exist.

Apply everything in `supabase/migrations/` in order, then run the security advisor.

## 2. Auth settings

In Supabase Auth:

- Keep email confirmation on.
- Set the Site URL to the production URL, and allow `https://<your-domain>/**` as a redirect.
- Set up custom SMTP. The built-in sender is rate limited to a few emails an hour.
- Set the minimum password length to 12 and turn on leaked password protection.
- Keep TOTP multi-factor enabled.

## 3. Secrets

Set these in Vercel. Never commit them, this repository is public.

| Name | Scope |
|---|---|
| `NEXT_PUBLIC_SUPABASE_URL` | Public |
| `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` | Public |
| `SUPABASE_SERVICE_ROLE_KEY` | Server only |
| `ATTESTATION_PRIVATE_KEY` | Server only, generate with `npm run keys` |

Treat `ATTESTATION_PRIVATE_KEY` as the crown jewel: whoever holds it can sign attestations in your name. Keep an offline backup. Rotating it invalidates the signature check on existing attestations until they are reissued.

## 4. After deploy

1. Sign up, create an org, and confirm a second account cannot open the first org's URL.
2. Run the Live Test against your own production domain and fix what it finds.
3. Publish your own trust page, so the product shows what it sells.

## Before real customers

- Legal review of the terms, privacy notice and data processing agreement. Supabase has no Africa region, so Kenyan data protection rules on cross-border transfer apply.
- An independent penetration test.
- A lead auditor's read of the control mappings.
