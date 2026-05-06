"use client"

import * as React from "react"
import { toast } from "sonner"
import { motion, AnimatePresence } from "motion/react"
import { FileText, Clipboard, ArrowLeft, AlertCircle, ScanSearch } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Spinner } from "@/components/ui/spinner"
import { cn } from "@/lib/utils"

import { DropZone } from "./drop-zone"
import { PasteHeaders } from "./paste-headers"
import { VerdictCard } from "./verdict-card"
import { UnderTheHood } from "./under-the-hood"
import { SaveEmailHelpSheet } from "./save-email-help-sheet"

import { analyze, type Analysis } from "@/lib/email"

type Mode = "file" | "paste"
type Status = "idle" | "analyzing" | "result"

export function Scanner() {
  const [mode, setMode] = React.useState<Mode>("file")
  const [status, setStatus] = React.useState<Status>("idle")
  const [analysis, setAnalysis] = React.useState<Analysis | null>(null)
  const [filename, setFilename] = React.useState<string | null>(null)
  const [error, setError] = React.useState<string | null>(null)

  const runAnalyze = React.useCallback((source: string, sourceName: string | null) => {
    setError(null)
    setStatus("analyzing")
    // Defer to next tick so the UI can render the spinner before the regex
    // and parser walks block the main thread.
    setTimeout(() => {
      try {
        const result = analyze(source)
        setAnalysis(result)
        setFilename(sourceName)
        setStatus("result")
      } catch (err) {
        const message =
          err instanceof Error ? err.message : "Couldn't analyze that input."
        setError(message)
        setStatus("idle")
        toast.error("Scan failed", { description: message })
      }
    }, 0)
  }, [])

  const handleError = React.useCallback((message: string) => {
    setError(message)
    toast.error("Couldn't load that file", { description: message })
  }, [])

  const reset = () => {
    setStatus("idle")
    setAnalysis(null)
    setFilename(null)
    setError(null)
  }

  if (status === "result" && analysis) {
    return (
      <div className="flex flex-col gap-6">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-sm">
            <FileText className="text-muted-foreground size-4" aria-hidden />
            <span className="text-foreground/80 font-medium">
              {filename ?? "Pasted headers"}
            </span>
          </div>
          <Button variant="ghost" size="sm" onClick={reset}>
            <ArrowLeft data-icon="inline-start" />
            Scan another
          </Button>
        </div>

        <VerdictCard
          verdict={analysis.verdict}
          content={analysis.content}
          analysis={analysis}
        />

        <div className="border-border/60 mt-4 rounded-xl border p-4 sm:p-5">
          <p className="text-muted-foreground mb-2 text-xs font-medium tracking-wide uppercase">
            Under the hood
          </p>
          <UnderTheHood analysis={analysis} />
        </div>
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between gap-3">
        <div className="bg-muted/40 inline-flex rounded-md p-0.5">
          <ModeButton
            active={mode === "file"}
            onClick={() => setMode("file")}
            icon={<FileText />}
          >
            Upload .eml
          </ModeButton>
          <ModeButton
            active={mode === "paste"}
            onClick={() => setMode("paste")}
            icon={<Clipboard />}
          >
            Paste headers
          </ModeButton>
        </div>
        <SaveEmailHelpSheet />
      </div>

      <AnimatePresence mode="wait">
        {status === "analyzing" ? (
          <motion.div
            key="analyzing"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="border-border/60 bg-card/40 flex min-h-56 items-center justify-center rounded-xl border border-dashed p-8 text-center"
          >
            <div className="flex flex-col items-center gap-3">
              <Spinner className="size-5" />
              <p className="text-muted-foreground text-sm">Reading the headers…</p>
            </div>
          </motion.div>
        ) : mode === "file" ? (
          <motion.div
            key="file"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
          >
            <DropZone
              onFile={(text, name) => runAnalyze(text, name)}
              onError={handleError}
              disabled={status !== "idle"}
            />
          </motion.div>
        ) : (
          <motion.div
            key="paste"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
          >
            <PasteHeaders
              onSubmit={(text) => runAnalyze(text, null)}
              disabled={status !== "idle"}
            />
          </motion.div>
        )}
      </AnimatePresence>

      {error ? (
        <Alert variant="destructive">
          <AlertCircle aria-hidden />
          <AlertTitle>That didn&apos;t work</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}

      <p className="text-muted-foreground flex items-start gap-2 text-xs leading-relaxed">
        <ScanSearch className="mt-0.5 size-3.5 shrink-0" aria-hidden />
        Everything happens in your browser. Your email is not uploaded, logged, or
        analyzed by us — we never see it.
      </p>
    </div>
  )
}

function ModeButton({
  active,
  onClick,
  icon,
  children,
}: {
  active: boolean
  onClick: () => void
  icon: React.ReactNode
  children: React.ReactNode
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      data-state={active ? "active" : "inactive"}
      className={cn(
        "inline-flex items-center gap-1.5 rounded px-3 py-1.5 text-xs font-medium transition-colors",
        active
          ? "bg-background text-foreground shadow-sm"
          : "text-muted-foreground hover:text-foreground",
      )}
    >
      <span className="[&>svg]:size-3.5" aria-hidden>
        {icon}
      </span>
      {children}
    </button>
  )
}
