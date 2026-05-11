// Regression tests for the verdict rule engine.
//
// Each test exercises one rule path with a synthetic .eml fixture and
// asserts the tier + the presence of the reason signal that should fire.
// The point is to catch behavior drift when the rules in verdict.ts move:
// if a refactor accidentally stops emitting "dmarc-fail" or stops escalating
// to danger on a brand-impersonation match, these will fail loudly.
//
// `analyze()` issues a DNS-over-HTTPS MX lookup for the visible sender
// domain. Tests stub `fetch` globally so no test ever hits the real network.
// The default stub returns "no MX records" — tests that exercise MX-based
// verdicts override with `mockFetchMxAnswer()` per case.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { analyze } from "../index"
import { __resetMxCacheForTests } from "../mx-lookup"
import type { Analysis, VerdictTier } from "../types"
import { authResults, buildEml, cleanEsp } from "./fixtures"

interface Expectations {
  tier?: VerdictTier
  reason?: string
  notReason?: string
  capped?: boolean
  reasonsEmpty?: boolean
}

// Run analyze() on a fixture and assert the bits we care about. Centralizing
// the analyze + assertion shape keeps each test focused on its own fixture
// and prevents the body of every test from looking identical.
async function check(eml: string, e: Expectations): Promise<Analysis> {
  const a = await analyze(eml)
  const signals = a.verdict.reasons.map((r) => r.signal)
  if (e.tier !== undefined) expect(a.verdict.tier).toBe(e.tier)
  if (e.reason !== undefined) expect(signals).toContain(e.reason)
  if (e.notReason !== undefined) expect(signals).not.toContain(e.notReason)
  if (e.capped !== undefined) expect(a.verdict.capped).toBe(e.capped)
  if (e.reasonsEmpty) expect(a.verdict.reasons).toEqual([])
  return a
}

interface MockDnsAnswer { name?: string; type: number; TTL?: number; data: string }
function mockDnsResponse(answers: MockDnsAnswer[]): Response {
  return new Response(JSON.stringify({ Status: 0, Answer: answers }), {
    status: 200,
    headers: { "Content-Type": "application/dns-json" },
  })
}
function mockFetchMxAnswer(answers: MockDnsAnswer[]): void {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(mockDnsResponse(answers)))
}
const mxAnswer = (priority: number, host: string): MockDnsAnswer => ({
  type: 15,
  data: `${priority} ${host}.`,
})

beforeEach(() => {
  __resetMxCacheForTests()
  mockFetchMxAnswer([])
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe("authentication failures", () => {
  it("DMARC fail → danger", async () => {
    await check(
      buildEml({
        from: "Bank Alerts <alerts@bank.example>",
        authResults: authResults({ domain: "bank.example", dmarc: "fail" }),
      }),
      { tier: "danger", reason: "dmarc-fail" },
    )
  })

  it("SPF fail → danger", async () => {
    await check(
      buildEml({
        from: "Sender <user@example.com>",
        authResults: authResults({ domain: "example.com", spf: "fail", dmarc: "none" }),
      }),
      { tier: "danger", reason: "spf-fail" },
    )
  })

  it("SPF softfail → caution", async () => {
    await check(
      buildEml({ authResults: authResults({ domain: "example.com", spf: "softfail" }) }),
      { tier: "caution", reason: "spf-softfail" },
    )
  })

  it("DKIM fail with SPF pass → caution", async () => {
    await check(
      buildEml({ authResults: authResults({ domain: "example.com", dkim: "fail" }) }),
      { tier: "caution", reason: "dkim-fail" },
    )
  })

  it("no auth results at all → caution with no-auth", async () => {
    await check(buildEml({}), { tier: "caution", reason: "no-auth" })
  })
})

describe("display-name impersonation", () => {
  it("brand-impersonation: PayPal display from random domain → danger", async () => {
    await check(
      buildEml({
        from: "PayPal Service <service@random-payments.com>",
        authResults: authResults({ domain: "random-payments.com" }),
      }),
      { tier: "danger", reason: "brand-impersonation" },
    )
  })

  it("brand-impersonation suppressed when domain is on the legit list", async () => {
    await check(
      buildEml({
        from: "PayPal <service@paypal.com>",
        authResults: authResults({ domain: "paypal.com" }),
      }),
      { notReason: "brand-impersonation" },
    )
  })

  it("role-impersonation from a public webmail → danger", async () => {
    await check(
      buildEml({
        from: "Human Resources <hr.notice@gmail.com>",
        authResults: authResults({ domain: "gmail.com" }),
      }),
      { tier: "danger", reason: "role-impersonation-webmail" },
    )
  })

  it("role-impersonation from a typosquat-shape domain → danger", async () => {
    await check(
      buildEml({
        from: "IT Support <support@h3lp-desk-corp-77.com>",
        authResults: authResults({ domain: "h3lp-desk-corp-77.com" }),
      }),
      { tier: "danger", reason: "role-impersonation-sketchy-domain" },
    )
  })

  it("typosquat-shape domain alone (no role/brand match) → caution", async () => {
    await check(
      buildEml({
        from: "John Smith <john@7secure-mail.com>",
        authResults: authResults({ domain: "7secure-mail.com" }),
      }),
      { tier: "caution", reason: "domain-typosquat-shape" },
    )
  })
})

describe("link flags", () => {
  const exampleAuth = authResults({ domain: "example.com" })

  it("anchor/href mismatch → danger", async () => {
    await check(
      buildEml({
        authResults: exampleAuth,
        body: "Click the link to verify.",
        htmlBody:
          '<p>Click <a href="http://attacker.example/login">https://your-bank.com/secure</a> to verify.</p>',
      }),
      { tier: "danger", reason: "suspicious-links" },
    )
  })

  it("raw-IP host link → danger", async () => {
    await check(
      buildEml({
        authResults: exampleAuth,
        body: "Visit http://203.0.113.45/login to access your account.",
      }),
      { tier: "danger", reason: "suspicious-links" },
    )
  })

  it("shortener link alone → caution", async () => {
    await check(
      buildEml({
        authResults: exampleAuth,
        body: "Read more at https://bit.ly/3xyz123 — thanks!",
      }),
      { tier: "caution", reason: "shortener-link" },
    )
  })
})

describe("content classification cap", () => {
  it("clean auth + money language → caution (capped)", async () => {
    await check(
      cleanEsp({
        from: "Acme Billing <billing@news.acme.com>",
        body: "Your invoice balance due is $1,250. Please wire payment to the account on file.",
      }),
      { tier: "caution", capped: true },
    )
  })

  it("clean auth + credentials language → caution (capped)", async () => {
    await check(
      cleanEsp({
        body: "Please verify your account by clicking the link to reset your password.",
      }),
      { tier: "caution", capped: true },
    )
  })
})

describe("job-offer scams", () => {
  it("job offer + document request → danger", async () => {
    await check(
      buildEml({
        from: "Talent Team <careers@new-opportunities-inc.com>",
        authResults: authResults({ domain: "new-opportunities-inc.com" }),
        body: "We are pleased to offer you a remote position. Please email a scan of your passport and a copy of your driver's license to begin onboarding.",
      }),
      { tier: "danger", reason: "job-offer-with-document-request" },
    )
  })

  it("job offer alone → caution", async () => {
    await check(
      cleanEsp({
        from: "Acme Recruiting <careers@news.acme.com>",
        body: "Welcome to the team! Your offer letter is attached. Looking forward to your start date.",
      }),
      { tier: "caution", reason: "job-offer-content" },
    )
  })
})

describe("forwarded-message guard", () => {
  const exampleAuth = authResults({ domain: "example.com" })

  it("subject prefix Fwd: → forwarded tier, no verdict issued", async () => {
    await check(buildEml({ subject: "Fwd: Suspicious email", authResults: exampleAuth }), {
      tier: "forwarded",
    })
  })

  it("body separator '----- Forwarded message -----' → forwarded tier", async () => {
    await check(
      buildEml({
        authResults: exampleAuth,
        body: "FYI:\n\n---------- Forwarded message ----------\nFrom: stranger@phish.example\nSubject: Urgent",
      }),
      { tier: "forwarded" },
    )
  })
})

describe("clean ESP-routed mail", () => {
  it("fully-aligned SendGrid-routed newsletter → safe", async () => {
    await check(cleanEsp(), { tier: "safe", reasonsEmpty: true })
  })
})

describe("Reply-To mismatch", () => {
  // Build a minimal EML with optional reply-to and list-id. Centralizing the
  // header construction here keeps each test focused on the one input that
  // distinguishes it from the others.
  const replyToEml = (opts: {
    from: string
    fromDomain: string
    replyTo?: string
    listId?: string
  }) =>
    buildEml({
      from: opts.from,
      replyTo: opts.replyTo,
      listId: opts.listId,
      authResults: authResults({ domain: opts.fromDomain }),
    })

  // Negative cases: every "no flag" scenario asserts the same three things
  // (null assessment, neither signal fires). Driving them from a table also
  // collapses lines that would otherwise look identical to a duplication
  // detector.
  const NO_FLAG_CASES: Array<{
    name: string
    eml: () => string
  }> = [
    {
      name: "Reply-To on ESP skip-list (sendgrid.net)",
      eml: () =>
        replyToEml({
          from: "Acme <hello@acme.com>",
          fromDomain: "acme.com",
          replyTo: "reply@sendgrid.net",
        }),
    },
    {
      name: "Reply-To on noreply. subdomain",
      eml: () =>
        replyToEml({
          from: "Acme <hello@acme.com>",
          fromDomain: "acme.com",
          replyTo: "do-not-reply@noreply.acme-mail.com",
        }),
    },
    {
      name: "List-Id present (mailing list)",
      eml: () =>
        replyToEml({
          from: "Vendor <hello@vendor-a.example>",
          fromDomain: "vendor-a.example",
          replyTo: "list@vendor-b.example",
          listId: "<announce.vendor-a.example>",
        }),
    },
    {
      name: "same registrable domain (subdomain → parent)",
      eml: () =>
        replyToEml({
          from: "Acme News <hello@news.acme.com>",
          fromDomain: "news.acme.com",
          replyTo: "support@acme.com",
        }),
    },
    {
      name: "Reply-To matches From domain exactly",
      eml: () =>
        replyToEml({
          from: "Acme <hello@acme.com>",
          fromDomain: "acme.com",
          replyTo: "support@acme.com",
        }),
    },
    {
      name: "no Reply-To header",
      eml: () =>
        replyToEml({ from: "Acme <hello@acme.com>", fromDomain: "acme.com" }),
    },
  ]

  it.each(NO_FLAG_CASES)("$name → no flag", async ({ eml }) => {
    const a = await analyze(eml())
    const signals = a.verdict.reasons.map((r) => r.signal)
    expect(a.replyTo.assessment).toBeNull()
    expect(signals).not.toContain("replyto-mismatch")
    expect(signals).not.toContain("replyto-strong-mismatch")
  })

  it("same local-part, different domain → strong, danger", async () => {
    const a = await check(
      replyToEml({
        from: "Andrew Campbell <andrew@longisland.com>",
        fromDomain: "longisland.com",
        replyTo: "andrew@ceocoach-int.com",
      }),
      { tier: "danger", reason: "replyto-strong-mismatch" },
    )
    expect(a.replyTo.assessment).toBe("strong")
    expect(a.replyTo.domain).toBe("ceocoach-int.com")
    // Wording softened on review — header evidence can't distinguish
    // compromised-account from third-party impersonation.
    expect(a.replyTo.note).not.toContain("compromised")
  })

  it("different local-part and different domain → mismatch, danger", async () => {
    const a = await check(
      replyToEml({
        from: "Vendor <hello@vendor-a.example>",
        fromDomain: "vendor-a.example",
        replyTo: "ops@vendor-b-payments.example",
      }),
      { tier: "danger", reason: "replyto-mismatch" },
    )
    expect(a.replyTo.assessment).toBe("mismatch")
  })
})

describe("MX-based brand impersonation", () => {
  // The triggering scenario: a domain (longisland.com) with inbound MX at
  // Google was forged via SendGrid. The MX/delivery split is the
  // discriminator. Auth gating is what makes the signal trustworthy — a
  // legitimately-authorized split-inbound/outbound setup looks identical in
  // every other way.
  const sendgridDelivery = {
    receivedSpf:
      "Pass (mx.recipient.org: domain of bounces@sendgrid.net designates 167.89.10.20 as permitted sender) client-ip=167.89.10.20",
    received: [
      "from mx.recipient.org (mx.recipient.org [203.0.113.10]) by inbox.recipient.org with ESMTPS; Mon, 01 Jan 2024 12:00:00 -0500",
      "from o1.email.attacker.example (o1.email.attacker.example [167.89.10.20]) by mx.recipient.org with ESMTPS; Mon, 01 Jan 2024 11:59:55 -0500",
    ],
  } as const

  it("Google MX + SendGrid delivery + no auth → danger, brand-impersonation-confirmed", async () => {
    mockFetchMxAnswer([
      mxAnswer(1, "aspmx.l.google.com"),
      mxAnswer(5, "alt1.aspmx.l.google.com"),
    ])
    const a = await check(
      buildEml({
        from: "Andrew Campbell <andrew@longisland.com>",
        returnPath: "bounces@sendgrid.net",
        ...sendgridDelivery,
        authResults:
          "mx.recipient.org; spf=pass smtp.mailfrom=sendgrid.net; dkim=none; dmarc=fail header.from=longisland.com",
      }),
      { tier: "danger", reason: "brand-impersonation-confirmed" },
    )
    expect(a.mx?.provider).toBe("Google")
    expect(a.parser.sendingService.toLowerCase()).toContain("sendgrid")
  })

  it("auth gate: SPF pass aligned with sender domain → NO impersonation reason", async () => {
    // Same shape as the confirmed case but the From domain authorizes the
    // ESP via aligned SPF. That's a normal split-inbound/outbound setup and
    // must NOT fire either of the new reasons.
    mockFetchMxAnswer([mxAnswer(1, "aspmx.l.google.com")])
    const a = await check(
      buildEml({
        from: "Andrew Campbell <andrew@longisland.com>",
        returnPath: "bounces@longisland.com",
        ...sendgridDelivery,
        authResults: authResults({
          domain: "longisland.com",
          spf: "pass",
          mailfrom: "longisland.com",
          dkim: "pass",
          dmarc: "pass",
        }),
      }),
      { notReason: "brand-impersonation-confirmed" },
    )
    expect(a.verdict.reasons.map((r) => r.signal)).not.toContain(
      "brand-impersonation-likely",
    )
  })

  it("MX unavailable + strong Reply-To + ESP + no auth → caution, brand-impersonation-likely", async () => {
    // fetch resolves to an error; lookupMx returns status:'error'.
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("upstream", { status: 502 })),
    )
    const a = await check(
      buildEml({
        from: "Andrew Campbell <andrew@longisland.com>",
        replyTo: "andrew@ceocoach-int.com",
        returnPath: "bounces@sendgrid.net",
        ...sendgridDelivery,
        authResults:
          "mx.recipient.org; spf=pass smtp.mailfrom=sendgrid.net; dkim=none; dmarc=fail header.from=longisland.com",
      }),
      { reason: "brand-impersonation-likely" },
    )
    expect(a.mx?.status).toBe("error")
    expect(a.verdict.tier).not.toBe("safe")
  })

  it("public webmail sender skips the MX lookup entirely", async () => {
    const fetchSpy = vi.fn().mockResolvedValue(mockDnsResponse([]))
    vi.stubGlobal("fetch", fetchSpy)
    const a = await analyze(
      buildEml({
        from: "Some Person <person@gmail.com>",
        authResults: authResults({ domain: "gmail.com" }),
      }),
    )
    expect(a.mx).toBeNull()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it("MX provider matches the ESP (Google MX, gmail.com sender) → no impersonation reason", async () => {
    // Defensive: even if a lookup happens, matching provider/service must
    // not fire the confirmed reason. Use a non-webmail domain so the lookup
    // actually runs.
    mockFetchMxAnswer([mxAnswer(1, "aspmx.l.google.com")])
    const a = await check(
      buildEml({
        from: "Acme Newsletter <hello@news.acme.com>",
        returnPath: "bounces@news.acme.com",
        received: [
          "from mx.recipient.org (mx.recipient.org [203.0.113.10]) by inbox.recipient.org with ESMTPS; Mon, 01 Jan 2024 12:00:00 -0500",
          "from mail-yw1-f178.google.com (mail-yw1-f178.google.com [209.85.128.178]) by mx.recipient.org with ESMTPS; Mon, 01 Jan 2024 11:59:55 -0500",
        ],
        authResults: authResults({
          domain: "news.acme.com",
          spf: "pass",
          mailfrom: "news.acme.com",
          dkim: "pass",
          dmarc: "pass",
        }),
      }),
      { notReason: "brand-impersonation-confirmed" },
    )
    expect(a.verdict.reasons.map((r) => r.signal)).not.toContain(
      "brand-impersonation-likely",
    )
  })
})

describe("input validation", () => {
  it("empty source throws", async () => {
    await expect(analyze("")).rejects.toThrow()
    await expect(analyze("   \n\n   ")).rejects.toThrow()
  })
})
