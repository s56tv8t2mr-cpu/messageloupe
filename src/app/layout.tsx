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

export const metadata: Metadata = {
  metadataBase: new URL("https://messageloupe.com"),
  title: {
    default: "Message Loupe — is this email real?",
    template: "%s — Message Loupe",
  },
  description:
    "Drop a .eml file or paste raw email headers. Get a 3-tier verdict in seconds — Safe, Caution, or Danger. Runs entirely in your browser. Nothing leaves your device.",
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
    title: "Message Loupe — is this email real?",
    description:
      "Drop a .eml file. Get a 3-tier verdict in seconds. Runs entirely in your browser.",
    url: "https://messageloupe.com",
  },
  twitter: {
    card: "summary_large_image",
    title: "Message Loupe — is this email real?",
    description:
      "Drop a .eml file. Get a 3-tier verdict in seconds. Runs entirely in your browser.",
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
