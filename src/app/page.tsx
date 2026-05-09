import { SiteHeader } from "@/components/site-header"
import { SiteFooter } from "@/components/site-footer"
import { Scanner } from "@/components/scanner"

export default function Home() {
  return (
    <>
      <SiteHeader />
      <main className="flex flex-1 flex-col">
        <section className="mx-auto w-full max-w-3xl px-4 pt-12 pb-6 md:px-6 md:pt-20">
          <h1 className="text-foreground text-balance text-4xl font-semibold tracking-tight md:text-5xl">
            Is this email real?
          </h1>
          <p className="text-muted-foreground mt-4 max-w-xl text-balance text-base leading-relaxed md:text-lg">
            Drop a saved email or paste raw headers. We check 40+ signals and tell you
            whether the sender is who they claim to be, in plain English. Runs entirely
            in your browser. Nothing leaves your device.
          </p>
        </section>

        <section className="mx-auto w-full max-w-3xl px-4 pb-16 md:px-6 md:pb-24">
          <Scanner />
        </section>
      </main>
      <SiteFooter />
    </>
  )
}
