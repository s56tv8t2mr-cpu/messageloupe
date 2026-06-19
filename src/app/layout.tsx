import type { Metadata, Viewport } from "next"
import { Geist, Geist_Mono } from "next/font/google"
import { TooltipProvider } from "@/components/ui/tooltip"
import { Toaster } from "@/components/ui/sonner"
import { ThemeProvider } from "@/components/theme-provider"
import { JsonLd } from "@/components/json-ld"
import { SITE_NAME, SITE_URL } from "@/lib/seo"
import "./globals.css"

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
})

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
})

const SHARE_TITLE = "Message Loupe: fake email, BEC and wire fraud checker"
const SHARE_DESCRIPTION =
  "Check a suspicious email for spoofing, business email compromise, invoice fraud, and wire-transfer risk. Analysis runs privately in your browser."

const websiteJsonLd = {
  "@context": "https://schema.org",
  "@type": "WebSite",
  name: SITE_NAME,
  url: SITE_URL,
  description: SHARE_DESCRIPTION,
  inLanguage: "en-US",
}

export const metadata: Metadata = {
  metadataBase: new URL("https://messageloupe.com"),
  title: {
    default: SHARE_TITLE,
    template: "%s · Message Loupe",
  },
  description: SHARE_DESCRIPTION,
  applicationName: "Message Loupe",
  authors: [{ name: "Message Loupe" }],
  keywords: [
    "phishing checker",
    "email scam checker",
    "is this email a scam",
    "check email sender",
    "email authenticity",
    "spoofed email",
    "email header analyzer",
    "business email compromise checker",
    "BEC email checker",
    "wire fraud email checker",
    "invoice fraud email",
  ],
  openGraph: {
    type: "website",
    siteName: "Message Loupe",
    title: SHARE_TITLE,
    description: SHARE_DESCRIPTION,
    url: "https://messageloupe.com",
  },
  twitter: {
    card: "summary_large_image",
    title: SHARE_TITLE,
    description: SHARE_DESCRIPTION,
  },
  robots: {
    index: true,
    follow: true,
  },
}

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#ffffff" },
    { media: "(prefers-color-scheme: dark)", color: "#0a0a0a" },
  ],
  width: "device-width",
  initialScale: 1,
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html
      lang="en"
      suppressHydrationWarning
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="bg-background text-foreground min-h-full flex flex-col">
        <JsonLd data={websiteJsonLd} />
        <ThemeProvider
          attribute="class"
          defaultTheme="dark"
          enableSystem
          disableTransitionOnChange
        >
          <TooltipProvider delayDuration={150}>
            {children}
            <Toaster richColors closeButton position="bottom-right" />
          </TooltipProvider>
        </ThemeProvider>
      </body>
    </html>
  )
}
