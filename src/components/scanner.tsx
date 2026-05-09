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

import type { Analysis } from "@/lib/email"
import type {
  AnalyzeRequest,
  AnalyzeResponse,
} from "@/lib/email/analyze.worker"

type Mode = "file" | "paste"
type Status = "idle" | "analyzing" | "result"

export function Scanner() {
  const [mode, setMode] = React.useState<Mode>("file")
  const [status, setStatus] = React.useState<Status>("idle")
  const [analysis, setAnalysis] = React.useState<Analysis | null>(null)
  const [filename, setFilename] = React.useState<string | null>(null)
  const [error, setError] = React.useState<string | null>(null)

  const workerRef = React.useRef<Worker | null>(null)
  const requestIdRef = React.useRef(0)
  const pendingRef = React.useRef<{ id: number; sourceName: string | null } | null>(
    null,
  )

  React.useEffect(() => {
    const worker = new Worker(
      new URL("../lib/email/analyze.worker.ts", import.meta.url),
      { type: "module" },
    )
    worker.onmessage = (event: MessageEvent<AnalyzeResponse>) => {
      const data = event.data
      // Ignore responses to canceled requests (user reset, started another scan).
      if (!pendingRef.current || pendingRef.current.id !== data.id) return
      const { sourceName } = pendingRef.current
      pendingRef.current = null
      if (data.ok) {
        setAnalysis(data.result)
        setFilename(sourceName)
        setStatus("result")
      } else {
        setError(data.error)
        setStatus("idle")
        toast.error("Scan failed", { description: data.error })
      }
    }
    worker.onerror = (event) => {
      pendingRef.current = null
      const message = event.message || "Worker crashed while analyzing."
      setError(message)
      setStatus("idle")
      toast.error("Scan failed", { description: message })
    }
    workerRef.current = worker
    return () => {
      worker.terminate()
      workerRef.current = null
    }
  }, [])

  const runAnalyze = React.useCallback((source: string, sourceName: string | null) => {
    const worker = workerRef.current
    if (!worker) return
    setError(null)
    setStatus("analyzing")
    const id = ++requestIdRef.current
    pendingRef.current = { id, sourceName }
    const request: AnalyzeRequest = { id, source }
    worker.postMessage(request)
  }, [])

  const handleError = React.useCallback((message: string) => {
    setError(message)
    toast.error("Couldn't load that file", { description: message })
  }, [])

  const reset = React.useCallback(() => {
    // Cancel any in-flight worker response by dropping the pending id.
    pendingRef.current = null
    setStatus("idle")
    setAnalysis(null)
    setFilename(null)
    setError(null)
  }, [])

  // Global event lets the header trigger reset without lifting state into
  // a context that nothing else needs.
  React.useEffect(() => {
    window.addEventListener("messageloupe:reset", reset)
    return () => window.removeEventListener("messageloupe:reset", reset)
  }, [reset])

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

        <VerdictCard analysis={analysis} />

        <div className="border-border/60 mt-4 rounded-xl border p-4 sm:p-5">
          <p className="text-muted-foreground mb-3 text-[13px] font-medium tracking-wide uppercase">
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

      <p className="text-muted-foreground flex items-start gap-2 text-sm leading-relaxed">
        <ScanSearch className="text-primary mt-0.5 size-4 shrink-0" aria-hidden />
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
        "inline-flex items-center gap-1.5 rounded px-3.5 py-1.5 text-sm font-medium transition-colors",
        active
          ? "bg-background text-foreground shadow-sm"
          : "text-muted-foreground hover:text-foreground",
      )}
    >
      <span className="[&>svg]:size-4" aria-hidden>
        {icon}
      </span>
      {children}
    </button>
  )
}
