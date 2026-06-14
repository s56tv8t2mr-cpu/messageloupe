// Local-only private corpus runner.
//
// This intentionally lives outside src/**/__tests__, so normal `npm test`
// and CI do not run it. It scans private folders on this machine, writes a
// detailed JSON report to .private-eval/, and fails if known-fake corpora ever
// produce a Safe verdict.

import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs"
import { join, resolve } from "node:path"
import { describe, expect, it } from "vitest"

import { analyze } from "../src/lib/email"
import type { VerdictTier } from "../src/lib/email/types"

interface CorpusConfig {
  name: string
  path: string
  recursive: boolean
  expectNoSafe: boolean
}

interface CorpusRow {
  file: string
  tier?: VerdictTier
  from?: string | null
  to?: string | null
  replyTo?: string | null
  returnPath?: string | null
  spf?: string
  dkim?: string
  dmarc?: string
  service?: string | null
  mxProvider?: string | null
  mxStatus?: string | null
  rdapAgeDays?: number | null
  links?: number
  attachments?: string[]
  signals?: string[]
  error?: string
}

interface CorpusSummary {
  name: string
  path: string
  total: number
  danger: number
  caution: number
  forwarded: number
  safe: number
  errors: number
}

const workspaceRoot = resolve(__dirname, "..")
const outputDir = join(workspaceRoot, ".private-eval")

const defaultCorpora: CorpusConfig[] = [
  {
    name: "Known Fake EMLs",
    path: join(workspaceRoot, "Known Fake EMLs"),
    recursive: false,
    expectNoSafe: true,
  },
  {
    name: "wire-expanded",
    path: join(workspaceRoot, "email-analysis-archive", "wire-expanded-2026-06-01"),
    recursive: false,
    expectNoSafe: true,
  },
]

function extraCorpora(): CorpusConfig[] {
  const raw = process.env.MESSAGE_LOUPE_PRIVATE_CORPORA
  if (!raw) return []

  return raw
    .split(";")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const [nameOrPath, maybePath] = entry.split("=").map((part) => part.trim())
      const corpusPath = maybePath ?? nameOrPath
      return {
        name: maybePath ? nameOrPath : corpusPath,
        path: resolve(workspaceRoot, corpusPath),
        recursive: true,
        expectNoSafe: true,
      }
    })
}

function configuredCorpora(): CorpusConfig[] {
  return [...defaultCorpora, ...extraCorpora()].filter((corpus) => existsSync(corpus.path))
}

function listMessageFiles(folder: string, recursive: boolean): string[] {
  const files: string[] = []
  for (const entry of readdirSync(folder)) {
    const fullPath = join(folder, entry)
    const stat = statSync(fullPath)
    if (stat.isDirectory()) {
      if (recursive) files.push(...listMessageFiles(fullPath, recursive))
      continue
    }
    if (/\.(?:eml|txt)$/i.test(entry)) files.push(fullPath)
  }
  return files.sort((a, b) => a.localeCompare(b))
}

function summarize(name: string, path: string, rows: CorpusRow[]): CorpusSummary {
  return {
    name,
    path,
    total: rows.length,
    danger: rows.filter((row) => row.tier === "danger").length,
    caution: rows.filter((row) => row.tier === "caution").length,
    forwarded: rows.filter((row) => row.tier === "forwarded").length,
    safe: rows.filter((row) => row.tier === "safe").length,
    errors: rows.filter((row) => row.error).length,
  }
}

async function evaluateCorpus(corpus: CorpusConfig): Promise<{ rows: CorpusRow[]; summary: CorpusSummary }> {
  const rows: CorpusRow[] = []
  for (const file of listMessageFiles(corpus.path, corpus.recursive)) {
    try {
      const source = readFileSync(file, "utf8")
      const analysis = await analyze(source)
      rows.push({
        file,
        tier: analysis.verdict.tier,
        from: analysis.parser.sendingEmail,
        to: analysis.parser.recipientEmail,
        replyTo: analysis.parser.replyTo,
        returnPath: analysis.parser.returnPath,
        spf: analysis.parser.spfResult,
        dkim: analysis.parser.dkimResult,
        dmarc: analysis.parser.dmarcResult,
        service: analysis.parser.sendingService,
        mxProvider: analysis.mx?.provider ?? null,
        mxStatus: analysis.mx?.status ?? null,
        rdapAgeDays: analysis.rdap?.ageDays ?? null,
        links: analysis.links.length,
        attachments: analysis.attachments.map((attachment) => attachment.filename),
        signals: analysis.verdict.reasons.map((reason) => reason.signal),
      })
    } catch (error) {
      rows.push({ file, error: String(error) })
    }
  }

  rows.sort((a, b) => {
    if (a.tier === "safe" && b.tier !== "safe") return -1
    if (a.tier !== "safe" && b.tier === "safe") return 1
    return a.file.localeCompare(b.file)
  })

  return { rows, summary: summarize(corpus.name, corpus.path, rows) }
}

describe("private email corpus evaluation", () => {
  it("keeps known fake local corpora from returning Safe", async () => {
    const corpora = configuredCorpora()
    expect(corpora.length, "No private corpus folders were found on this machine.").toBeGreaterThan(0)

    mkdirSync(outputDir, { recursive: true })

    const summaries: CorpusSummary[] = []
    const failures: string[] = []

    for (const corpus of corpora) {
      const { rows, summary } = await evaluateCorpus(corpus)
      summaries.push(summary)

      writeFileSync(
        join(outputDir, `${corpus.name.replace(/[^a-z0-9_-]+/gi, "-")}.json`),
        JSON.stringify({ summary, rows }, null, 2),
        "utf8",
      )

      if (corpus.expectNoSafe && summary.safe > 0) {
        const safeFiles = rows
          .filter((row) => row.tier === "safe")
          .map((row) => row.file)
          .join("\n")
        failures.push(`${corpus.name} returned ${summary.safe} Safe verdict(s):\n${safeFiles}`)
      }
    }

    writeFileSync(
      join(outputDir, "summary.json"),
      JSON.stringify({ generatedAt: new Date().toISOString(), summaries }, null, 2),
      "utf8",
    )

    console.table(summaries)
    expect(failures).toEqual([])
  }, 180000)
})
