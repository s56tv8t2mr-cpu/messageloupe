import type { Metadata, Viewport } from "next"
import { Geist, Geist_Mono } from "next/font/google"
import { TooltipProvider } from "@/components/ui/tooltip"
import { Toaster } from "@/components/ui/sonner"
import { ThemeProvider } from "@/components/theme-provider"
import "./globals.css"

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
})

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
})

// One canonical description, reused across <meta>, OG, and Twitter so
// validators (and humans) see the same thing regardless of where they look.
const SHARE_TITLE = "Message Loupe: is this a fake email? Free phishing checker"
const SHARE_DESCRIPTION =
  "Drop a saved email or paste raw headers and get a plain-English verdict (Safe, Caution, or Likely Fake) in seconds. Your email is not uploaded."

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
    "phishing analysis",
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
