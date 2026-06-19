// Small, committed evaluation gate for corpus-level behavior.
//
// The real known-fake corpus stays private on disk. These synthetic fixtures
// are representative cases that let CI catch broad regressions: known-bad
// samples must never become Safe, the danger rate must not fall below the
// baseline, and benign/ham samples must not become Danger.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { analyze } from "../index"
import { __resetMxCacheForTests } from "../mx-lookup"
import { __resetRdapCacheForTests } from "../rdap-lookup"
import type { VerdictTier } from "../types"
import { authResults, buildEml, cleanEsp } from "./fixtures"

interface EvalCase {
  name: string
  eml: string
}

const attachmentBody = (filename: string, contentType: string): string =>
  [
    "Please review the attached file.",
    "",
    `Content-Type: ${contentType}; name="${filename}"`,
    `Content-Disposition: attachment; filename="${filename}"`,
    "",
    "placeholder",
  ].join("\r\n")

const maliciousCorpus: EvalCase[] = [
  {
    name: "domain-shaped anchor mismatch",
    eml: buildEml({
      authResults: authResults({ domain: "example.com" }),
      body: "Click the link to verify.",
      htmlBody:
        '<p>Click <a href="https://attacker.example/login">paypal.com/secure</a> to verify.</p>',
    }),
  },
  {
    name: "BEC banking-change request from public webmail",
    eml: cleanEsp({
      from: "Holly Straub <holly@gmail.com>",
      body:
        "I would like to request an update to my banking information before the next payroll is processed.",
    }),
  },
  {
    name: "fake job offer with document request",
    eml: buildEml({
      from: "Talent Team <careers@new-opportunities-inc.com>",
      authResults: authResults({ domain: "new-opportunities-inc.com" }),
      body:
        "We are pleased to offer you a remote position. Please email a scan of your passport and a copy of your driver's license to begin onboarding.",
    }),
  },
  {
    name: "dangerous HTML attachment",
    eml: buildEml({
      from: "Known Vendor <billing@example.com>",
      authResults: authResults({ domain: "example.com" }),
      body: attachmentBody("invoice.html", "text/html"),
    }),
  },
  {
    name: "wire lure with attachment",
    eml: cleanEsp({
      from: "Vendor Billing <billing@news.vendor.example>",
      subject: "Request for Payment; Invoice",
      body: attachmentBody("leadership-bill.pdf", "application/pdf"),
    }),
  },
]

const hamCorpus: EvalCase[] = [
  {
    name: "legitimate ESP newsletter",
    eml: cleanEsp({
      from: "Acme Newsletter <news@news.acme.com>",
      body: "Read this week's product updates and customer stories.",
    }),
  },
  {
    name: "ordinary direct deposit note",
    eml: cleanEsp({
      from: "Holly Straub <holly@gmail.com>",
      body: "My direct deposit posted today. Thanks for confirming.",
    }),
  },
  {
    name: "known vendor invoice with normal payment process",
    eml: cleanEsp({
      from: "Known Vendor <billing@news.vendor.example>",
      subject: "Invoice available",
      body: "Your invoice balance is due this week. Please use your normal payment process.",
    }),
  },
  {
    name: "non-web footer anchors",
    eml: buildEml({
      authResults: authResults({ domain: "example.com" }),
      body: "Contact support if needed.",
      htmlBody:
        '<p><a href="mailto:support@example.com">support@example.com</a><a href="#unsubscribe">unsubscribe</a></p>',
    }),
  },
]

beforeEach(() => {
  __resetMxCacheForTests()
  __resetRdapCacheForTests()
  vi.stubGlobal(
    "fetch",
    vi.fn((input: RequestInfo | URL) => {
      const url = String(input)
      if (url === "/api/rdap") {
        return Promise.resolve(
          new Response(JSON.stringify({ events: [] }), {
            status: 200,
            headers: { "Content-Type": "application/rdap+json" },
          }),
        )
      }
      return Promise.resolve(
        new Response(JSON.stringify({ Status: 0, Answer: [] }), {
          status: 200,
          headers: { "Content-Type": "application/dns-json" },
        }),
      )
    }),
  )
})

afterEach(() => {
  vi.unstubAllGlobals()
  __resetMxCacheForTests()
  __resetRdapCacheForTests()
})

async function analyzeCorpus(corpus: EvalCase[]): Promise<Array<EvalCase & { tier: VerdictTier }>> {
  return Promise.all(
    corpus.map(async (testCase) => ({
      ...testCase,
      tier: (await analyze(testCase.eml)).verdict.tier,
    })),
  )
}

describe("email corpus evaluation gate", () => {
  it("known-bad corpus never returns Safe and maintains the danger-rate baseline", async () => {
    const results = await analyzeCorpus(maliciousCorpus)
    const safe = results.filter((result) => result.tier === "safe")
    const dangerCount = results.filter((result) => result.tier === "danger").length

    expect(safe.map((result) => result.name)).toEqual([])
    expect(dangerCount / results.length).toBeGreaterThanOrEqual(0.8)
  })

  it("ham corpus stays below the false-positive danger budget", async () => {
    const results = await analyzeCorpus(hamCorpus)
    const danger = results.filter((result) => result.tier === "danger")

    expect(danger.map((result) => result.name)).toEqual([])
  })
})
