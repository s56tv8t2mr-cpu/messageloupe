import Link from "next/link"
import { ScanSearch, Code2 } from "lucide-react"

import { Button } from "@/components/ui/button"

export function SiteHeader() {
  return (
    <header className="border-border/60 bg-background/80 sticky top-0 z-30 w-full border-b backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="mx-auto flex h-14 w-full max-w-5xl items-center justify-between px-4 md:px-6">
        <Link
          href="/"
          className="text-foreground hover:text-foreground/80 flex items-center gap-2 font-medium tracking-tight transition-colors"
          aria-label="Message Loupe — home"
        >
          <ScanSearch className="size-5" aria-hidden />
          <span className="text-base">Message Loupe</span>
        </Link>
        <nav className="flex items-center gap-1">
          <Button asChild variant="ghost" size="sm" className="hidden sm:inline-flex">
            <Link href="/methodology">Methodology</Link>
          </Button>
          <Button asChild variant="ghost" size="sm">
            <a
              href="https://github.com/danielbabbitt/messageloupe"
              target="_blank"
              rel="noopener noreferrer"
            >
              <Code2 data-icon="inline-start" />
              GitHub
            </a>
          </Button>
        </nav>
      </div>
    </header>
  )
}
