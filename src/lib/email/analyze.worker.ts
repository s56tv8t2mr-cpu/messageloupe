/// <reference lib="webworker" />

// Worker entry: runs analyze() off the main thread so a 25 MB .eml never
// blocks the UI. The worker is single-purpose — request in, response out —
// no shared state, no caching. Each request carries an id so the caller can
// safely ignore responses to requests it has since canceled.

import { analyze } from "."
import type { Analysis } from "./types"

export type AnalyzeRequest = { id: number; source: string }
export type AnalyzeResponse =
  | { id: number; ok: true; result: Analysis }
  | { id: number; ok: false; error: string }

const ctx = self as unknown as DedicatedWorkerGlobalScope

ctx.onmessage = (event: MessageEvent<AnalyzeRequest>) => {
  const { id, source } = event.data
  try {
    const result = analyze(source)
    const response: AnalyzeResponse = { id, ok: true, result }
    ctx.postMessage(response)
  } catch (err) {
    const error = err instanceof Error ? err.message : "Couldn't analyze that input."
    const response: AnalyzeResponse = { id, ok: false, error }
    ctx.postMessage(response)
  }
}
