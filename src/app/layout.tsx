import '@fontsource-variable/inter'
import './globals.css'
import type { Metadata } from 'next'

// The CSP nonce is per request, so nothing can be prerendered or its scripts would be blocked.
export const dynamic = 'force-dynamic'

export const metadata: Metadata = {
  title: { default: 'maas.AI GRC Hub', template: '%s | maas.AI GRC Hub' },
  description: 'Run real security tests, manage risk, generate SMART policies and prove your posture with signed evidence.',
  icons: { icon: '/favicon.svg' },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-dvh">{children}</body>
    </html>
  )
}
