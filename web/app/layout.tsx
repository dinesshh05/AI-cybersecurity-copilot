import "./globals.css"

export const metadata = {
  title: "AI Cybersecurity Copilot",
  description: "Production-style AI SOC assistant vertical slice",
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}

