import Link from "next/link"
import { ScanSearch, Code2, ShieldCheck } from "lucide-react"

export function SiteFooter() {
  return (
    <footer className="border-border/60 mt-24 border-t">
      <div className="mx-auto flex w-full max-w-5xl flex-col gap-8 px-4 py-10 md:flex-row md:items-start md:justify-between md:px-6">
        <div className="flex flex-col gap-3">
          <Link
            href="/"
            className="text-foreground hover:text-foreground/80 flex items-center gap-2 font-medium tracking-tight transition-colors"
          >
            <ScanSearch className="text-primary size-5" aria-hidden />
            <span>Message Loupe</span>
          </Link>
          <p className="text-muted-foreground flex max-w-sm items-start gap-2 text-sm leading-relaxed">
            <ShieldCheck className="text-success mt-0.5 size-4 shrink-0" aria-hidden />
            <span>
              Runs entirely in your browser. No upload, no logging, no tracking. Your
              email never leaves your device.
            </span>
          </p>
        </div>

        <div className="grid grid-cols-2 gap-x-12 gap-y-2 text-sm sm:grid-cols-2 md:gap-x-16">
          <Link href="/how-to-save-an-email" className="text-muted-foreground hover:text-foreground">
            How to save an email
          </Link>
          <Link href="/methodology" className="text-muted-foreground hover:text-foreground">
            Methodology
          </Link>
          <Link href="/about" className="text-muted-foreground hover:text-foreground">
            About
          </Link>
          <Link href="/privacy" className="text-muted-foreground hover:text-foreground">
            Privacy
          </Link>
          <a
            href="https://github.com/s56tv8t2mr-cpu/messageloupe"
            target="_blank"
            rel="noopener noreferrer"
            className="text-muted-foreground hover:text-foreground inline-flex items-center gap-1.5"
          >
            <Code2 className="size-3.5" aria-hidden /> GitHub
          </a>
        </div>
      </div>
      <div className="border-border/60 border-t">
        <div className="text-muted-foreground mx-auto w-full max-w-5xl px-4 py-4 text-xs md:px-6">
          © {new Date().getFullYear()} Message Loupe. The verdict is advisory, not a
          guarantee — always verify money or credential requests through a channel you
          already trust.
        </div>
      </div>
    </footer>
  )
}
