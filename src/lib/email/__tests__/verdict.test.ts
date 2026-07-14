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
import { readFileSync } from "node:fs"
import { resolve } from "node:path"

import { analyze } from "../index"
import { __resetMxCacheForTests } from "../mx-lookup"
import { __resetRdapCacheForTests } from "../rdap-lookup"
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
function mockRdapBootstrapResponse(): Response {
  return new Response(
    JSON.stringify({
      services: [
        [["com", "org", "uk", "in", "de"], ["https://rdap.registry.test/"]],
      ],
    }),
    { status: 200, headers: { "Content-Type": "application/json" } },
  )
}
function mockFetchMxAnswer(answers: MockDnsAnswer[]): void {
  vi.stubGlobal(
    "fetch",
    vi.fn((input: RequestInfo | URL) => {
      const url = String(input)
      if (url === "https://data.iana.org/rdap/dns.json") {
        return Promise.resolve(mockRdapBootstrapResponse())
      }
      if (url.startsWith("https://rdap.registry.test/domain/")) {
        return Promise.resolve(
          new Response(JSON.stringify({ events: [] }), {
            status: 200,
            headers: { "Content-Type": "application/rdap+json" },
          }),
        )
      }
      return Promise.resolve(mockDnsResponse(answers))
    }),
  )
}
const mxAnswer = (priority: number, host: string): MockDnsAnswer => ({
  type: 15,
  data: `${priority} ${host}.`,
})
function mockDomainLookups({
  mx = [],
  rdapEvents = [],
}: {
  mx?: MockDnsAnswer[]
  rdapEvents?: Array<{ eventAction: string; eventDate: string }>
}): ReturnType<typeof vi.fn> {
  const fetchMock = vi.fn((input: RequestInfo | URL) => {
    const url = String(input)
    if (url === "https://data.iana.org/rdap/dns.json") {
      return Promise.resolve(mockRdapBootstrapResponse())
    }
    if (url.startsWith("https://rdap.registry.test/domain/")) {
      return Promise.resolve(
        new Response(JSON.stringify({ events: rdapEvents }), {
          status: 200,
          headers: { "Content-Type": "application/rdap+json" },
        }),
      )
    }
    return Promise.resolve(mockDnsResponse(mx))
  })
  vi.stubGlobal(
    "fetch",
    fetchMock,
  )
  return fetchMock
}
function rdapRegisteredDaysAgo(days: number): Array<{ eventAction: string; eventDate: string }> {
  return [
    {
      eventAction: "registration",
      eventDate: new Date(Date.now() - days * 86_400_000).toISOString(),
    },
  ]
}

function knownVendorAttachedInvoice({
  subject,
  bodyLine,
  filename,
}: {
  subject: string
  bodyLine: string
  filename: string
}): string {
  return cleanEsp({
    from: "Known Vendor <billing@news.vendor.example>",
    subject,
    body: [
      bodyLine,
      "",
      `Content-Type: application/pdf; name="${filename}"`,
      `Content-Disposition: attachment; filename="${filename}"`,
      "",
      "JVBERi0xLjQK",
    ].join("\r\n"),
  })
}

function microsoftEopAnonymousAuthEml({
  authBelowBoundary = false,
  fakeBoundaryBelowAuth = false,
}: {
  authBelowBoundary?: boolean
  fakeBoundaryBelowAuth?: boolean
} = {}): string {
  const topMicrosoftHops = [
    "Received: from EA3PR20MB994800.namprd20.prod.outlook.com (2603:10b6:303:2c3::11) by BL1PR20MB4561.namprd20.prod.outlook.com with HTTPS; Tue, 9 Jun 2026 19:31:14 +0000",
    "Received: from BN9PR03CA0236.namprd03.prod.outlook.com (2603:10b6:408:f8::31) by EA3PR20MB994800.namprd20.prod.outlook.com with Microsoft SMTP Server id 15.21.113.11; Tue, 9 Jun 2026 19:31:12 +0000",
    "Received: from BL6PEPF0001AB74.namprd02.prod.outlook.com (2603:10b6:408:f8:cafe::3a) by BN9PR03CA0236.outlook.office365.com with Microsoft SMTP Server id 15.21.92.15 via Frontend Transport; Tue, 9 Jun 2026 19:31:12 +0000",
  ]
  const authResults =
    "Authentication-Results: spf=pass (sender IP is 205.220.183.230) smtp.mailfrom=fortmcclellancu.org; dkim=pass (signature was verified) header.d=fortmcclellancu.org;dmarc=pass action=none header.from=fortmcclellancu.org;compauth=pass reason=100"
  const receivedSpf =
    "Received-SPF: Pass (protection.outlook.com: domain of fortmcclellancu.org designates 205.220.183.230 as permitted sender) receiver=protection.outlook.com; client-ip=205.220.183.230; helo=mx0b-0090d002.pphosted.com; pr=C"
  const boundaryHop =
    "Received: from mx0b-0090d002.pphosted.com (205.220.183.230) by BL6PEPF0001AB74.mail.protection.outlook.com (10.167.242.167) with Microsoft SMTP Server id 15.21.113.7 via Frontend Transport; Tue, 9 Jun 2026 19:31:10 +0000"
  const fakeSenderBoundaryHop =
    "Received: from attacker.example (attacker.example [198.51.100.22]) by FAKEPEPF00000001.mail.protection.outlook.com (10.0.0.1) with Microsoft SMTP Server id 15.21.113.7 via Frontend Transport; Tue, 9 Jun 2026 19:31:08 +0000"
  const messageHeaders = [
    "X-MS-Exchange-Organization-AuthSource: BL6PEPF0001AB74.namprd02.prod.outlook.com",
    "X-MS-Exchange-Organization-AuthSource: FAKEPEPF00000001.namprd02.prod.outlook.com",
    "X-MS-Exchange-CrossTenant-AuthSource: BL6PEPF0001AB74.namprd02.prod.outlook.com",
    "X-Forefront-Antispam-Report: CIP:205.220.183.230;H:mx0b-0090d002.pphosted.com;SCL:1;SFV:NSPM;",
    "DKIM-Signature: v=1; a=rsa-sha256; d=fortmcclellancu.org; s=fiservser1; h=From:To:Subject; b=sig",
    "Return-Path: <creditunion@fortmcclellancu.org>",
    "From: FORT MCCLELLAN CU <creditunion@fortmcclellancu.org>",
    "To: NICKOLSON STEPHANIE <admin@swaccountingstudio.com>",
    "Subject: New Message Alert",
    "Message-ID: <fixture-microsoft-eop@example.com>",
    "Date: Tue, 9 Jun 2026 19:31:09 GMT",
    "",
    "A new secure message is available.",
  ]

  const authBlock = [authResults, receivedSpf]
  return [
    ...topMicrosoftHops,
    ...(authBelowBoundary
      ? [boundaryHop, ...authBlock, ...(fakeBoundaryBelowAuth ? [fakeSenderBoundaryHop] : [])]
      : [...authBlock, boundaryHop]),
    ...messageHeaders,
  ].join("\r\n")
}

function microsoftInternalWithSenderForgedBoundaryEml({
  fakeBoundaryLabel = "FAKEPEPF00000001",
  copiedByBeforeFakeBoundary = false,
}: {
  fakeBoundaryLabel?: string
  copiedByBeforeFakeBoundary?: boolean
} = {}): string {
  const fakeBoundaryBy = copiedByBeforeFakeBoundary
    ? `BN9PR03CA0236.mail.protection.outlook.com (10.0.0.2) with Microsoft SMTP Server id 15.21.113.7; by ${fakeBoundaryLabel}.mail.protection.outlook.com`
    : `${fakeBoundaryLabel}.mail.protection.outlook.com`

  return [
    "Received: from EA3PR20MB994800.namprd20.prod.outlook.com (2603:10b6:303:2c3::11) by BL1PR20MB4561.namprd20.prod.outlook.com with HTTPS; Tue, 9 Jun 2026 19:31:14 +0000",
    "Received: from BN9PR03CA0236.namprd03.prod.outlook.com (2603:10b6:408:f8::31) by EA3PR20MB994800.namprd20.prod.outlook.com with Microsoft SMTP Server id 15.21.113.11; Tue, 9 Jun 2026 19:31:12 +0000",
    "Authentication-Results: spf=pass (sender IP is 198.51.100.22) smtp.mailfrom=attacker.example; dkim=pass (signature was verified) header.d=attacker.example;dmarc=pass action=none header.from=attacker.example;compauth=pass reason=100",
    "Received-SPF: Pass (protection.outlook.com: domain of attacker.example designates 198.51.100.22 as permitted sender) receiver=protection.outlook.com; client-ip=198.51.100.22; helo=attacker.example; pr=C",
    `Received: from attacker.example (attacker.example [198.51.100.22]) by ${fakeBoundaryBy} (10.0.0.1) with Microsoft SMTP Server id 15.21.113.7 via Frontend Transport; Tue, 9 Jun 2026 19:31:10 +0000`,
    `X-MS-Exchange-Organization-AuthSource: ${fakeBoundaryLabel}.namprd02.prod.outlook.com`,
    "From: Sender <sender@example.com>",
    "To: Recipient <recipient@example.org>",
    "Subject: Internal Microsoft message",
    "Message-ID: <fixture-microsoft-internal-forged-boundary@example.com>",
    "Date: Tue, 9 Jun 2026 19:31:09 GMT",
    "",
    "Hello.",
  ].join("\r\n")
}

beforeEach(() => {
  __resetMxCacheForTests()
  __resetRdapCacheForTests()
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

  it("SPF-only custom-domain auth → caution", async () => {
    await check(
      buildEml({
        from: "Derek Baker <dbaker@purduefedcu.com>",
        authResults:
          "mx.example.org; spf=pass smtp.mailfrom=purduefedcu.com; dkim=none; dmarc=none header.from=purduefedcu.com",
      }),
      { tier: "caution", reason: "spf-only-auth" },
    )
  })

  it("sender-supplied Authentication-Results are ignored", async () => {
    await check(
      buildEml({
        from: "Trusted Sender <sender@example.com>",
        authResults:
          "mail.attacker.test; spf=pass smtp.mailfrom=example.com; dkim=pass header.i=@example.com; dmarc=pass header.from=example.com",
      }),
      { tier: "caution", reason: "untrusted-auth-results" },
    )
  })

  it("forged upstream Received host does not make forged Authentication-Results trusted", async () => {
    await check(
      buildEml({
        from: "Trusted Sender <sender@example.com>",
        received: [
          "from mx.example.org (mx.example.org [203.0.113.10]) by inbox.example.org with ESMTPS; Mon, 01 Jan 2024 12:00:00 -0500",
          "from attacker.example (attacker.example [198.51.100.22]) by mail.attacker.test with ESMTPS; Mon, 01 Jan 2024 11:59:55 -0500",
        ],
        authResults:
          "mail.attacker.test; spf=pass smtp.mailfrom=example.com; dkim=pass header.i=@example.com; dmarc=pass header.from=example.com",
      }),
      { tier: "caution", reason: "untrusted-auth-results" },
    )
  })

  it("recipient-domain authserv is ignored when top Received host is unrelated", async () => {
    await check(
      buildEml({
        from: "Trusted Sender <sender@example.com>",
        received: [
          "from mail.other-provider.test (mail.other-provider.test [203.0.113.10]) by inbox.other-provider.test with ESMTPS; Mon, 01 Jan 2024 12:00:00 -0500",
          "from sender.example.com (sender.example.com [203.0.113.45]) by mail.other-provider.test with ESMTPS; Mon, 01 Jan 2024 11:59:55 -0500",
        ],
        authResults:
          "mx.example.org; spf=pass smtp.mailfrom=example.com; dkim=pass header.i=@example.com; dmarc=pass header.from=example.com",
      }),
      { tier: "caution", reason: "untrusted-auth-results" },
    )
  })

  it("Microsoft EOP anonymous Authentication-Results are recognized with boundary evidence", async () => {
    const analysis = await check(microsoftEopAnonymousAuthEml(), {
      notReason: "untrusted-auth-results",
    })

    expect(analysis.parser.authResultsTrusted).toBe(false)
    expect(analysis.parser.ignoredAuthResultsCount).toBe(0)
    expect(analysis.parser.spfResult).toBe("pass")
    expect(analysis.parser.dkimResult).toBe("present")
    expect(analysis.parser.dmarcResult).toBeNull()
  })

  it("sender-supplied Microsoft-shaped Authentication-Results below the boundary are ignored", async () => {
    const analysis = await check(microsoftEopAnonymousAuthEml({ authBelowBoundary: true }), {
      reason: "untrusted-auth-results",
    })

    expect(analysis.parser.authResultsTrusted).toBe(false)
  })

  it("sender-supplied fake Microsoft boundary does not make lower auth results trusted", async () => {
    const analysis = await check(
      microsoftEopAnonymousAuthEml({ authBelowBoundary: true, fakeBoundaryBelowAuth: true }),
      { reason: "untrusted-auth-results" },
    )

    expect(analysis.parser.authResultsTrusted).toBe(false)
  })

  it("sender-supplied Microsoft boundary in an internal M365 chain is ignored", async () => {
    const analysis = await check(microsoftInternalWithSenderForgedBoundaryEml(), {
      reason: "untrusted-auth-results",
    })

    expect(analysis.parser.authResultsTrusted).toBe(false)
  })

  it("sender-supplied copied-label Microsoft boundary is ignored", async () => {
    const analysis = await check(
      microsoftInternalWithSenderForgedBoundaryEml({ fakeBoundaryLabel: "BN9PR03CA0236" }),
      { reason: "untrusted-auth-results" },
    )

    expect(analysis.parser.authResultsTrusted).toBe(false)
  })

  it("sender-supplied multi-by Microsoft boundary is ignored", async () => {
    const analysis = await check(
      microsoftInternalWithSenderForgedBoundaryEml({ copiedByBeforeFakeBoundary: true }),
      { reason: "untrusted-auth-results" },
    )

    expect(analysis.parser.authResultsTrusted).toBe(false)
  })

  it("recognized anonymous Microsoft shape is not used as auth-pass proof", async () => {
    const analysis = await check(
      microsoftInternalWithSenderForgedBoundaryEml({
        fakeBoundaryLabel: "BL6PEPF0001AB74",
        copiedByBeforeFakeBoundary: true,
      }),
      { notReason: "dmarc-fail" },
    )

    expect(analysis.parser.authResultsTrusted).toBe(false)
    expect(analysis.parser.dkimResult).not.toBe("pass")
    expect(analysis.parser.dmarcResult).not.toBe("pass")
  })

  it("duplicate critical headers → danger", async () => {
    const eml = buildEml({
      from: "Billing <billing@example.com>",
      subject: "Invoice",
      authResults: authResults({ domain: "example.com" }),
    }).replace(
      "From: Billing <billing@example.com>",
      "From: Billing <billing@example.com>\r\nFrom: Trusted CEO <ceo@example.com>",
    )

    await check(eml, { tier: "danger", reason: "duplicate-critical-headers" })
  })
})

describe("display-name impersonation", () => {
  it.each([
    [
      "PayPal display from random domain",
      {
        from: "PayPal Service <service@random-payments.com>",
        authResults: authResults({ domain: "random-payments.com" }),
      },
    ],
    [
      "PayPal mixed with echoed sender address in display name",
      {
        from: '"PayPal noreply@random.example" <noreply@random.example>',
        authResults: authResults({ domain: "random.example" }),
        body: "Please review your account security notice.",
      },
    ],
    [
      "Brooks Running display from Gmail",
      {
        from: "Brooks Running <br.brooksrunning@gmail.com>",
        authResults: authResults({ domain: "gmail.com" }),
        body: "On behalf of Brooks Running, we would like to extend a partnership opportunity.",
      },
    ],
    [
      "Rocket Mortgage display from unrelated domain",
      {
        from: "Rocket Mortgage <office@frgwillhelp.com>",
        authResults: authResults({ domain: "frgwillhelp.com" }),
        body: "This message is from Rocket Mortgage.",
      },
    ],
    [
      "Southern Company display from lookalike domain",
      {
        from: "Southern Company <contact@southernscompany.com>",
        authResults: authResults({ domain: "southernscompany.com" }),
        body: "We are excited to offer you a modeling role for an upcoming shoot.",
      },
    ],
    [
      "ADP address shown as display name from unrelated domain",
      {
        from: '"noreply@adp.com" <postmaster@unrelated-marketing.example>',
        authResults: authResults({ domain: "unrelated-marketing.example" }),
        body: "Action required: review the change made to your compensation.",
      },
    ],
    [
      "ADP display address with same local part from unrelated domain",
      {
        from: '"noreply@adp.com" <noreply@unrelated-marketing.example>',
        authResults: authResults({ domain: "unrelated-marketing.example" }),
        body: "Action required: review the change made to your compensation.",
      },
    ],
  ])("brand-impersonation: %s → danger", async (_name, emlOptions) => {
    await check(buildEml(emlOptions), { tier: "danger", reason: "brand-impersonation" })
  })

  it.each([
    [
      "single encoded word",
      "=?UTF-8?B?UGF5UGFs?= <security@random-sender.example>",
    ],
    [
      "split encoded words",
      "=?UTF-8?B?UGF5?= =?UTF-8?B?UGFs?= <security@random-sender.example>",
    ],
  ])("brand-impersonation decodes RFC 2047 display names: %s", async (_name, from) => {
    await check(
      buildEml({
        from,
        authResults: authResults({ domain: "random-sender.example" }),
        body: "Please review your account security notice.",
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

  it.each([
    [
      "anchor/href mismatch",
      '<p>Click <a href="http://attacker.example/login">https://your-bank.com/secure</a> to verify.</p>',
    ],
    [
      "domain-shaped anchor text mismatch",
      '<p>Click <a href="https://attacker.example/login">paypal.com/secure</a> to verify.</p>',
    ],
    [
      "bare-domain anchor text mismatch",
      '<p>Click <a href="https://attacker.example/login">paypal.com</a> to verify.</p>',
    ],
    [
      "wrapped redirect URL is unwrapped before link verdict",
      '<p>Click <a href="https://www.google.com/url?q=https%3A%2F%2Fattacker.example%2Flogin">paypal.com/secure</a> to verify.</p>',
    ],
  ])("%s → danger", async (_name, htmlBody) => {
    await check(
      buildEml({
        authResults: exampleAuth,
        body: "Click the link to verify.",
        htmlBody,
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

  it("dotted product-name anchor text is not treated as a display URL", async () => {
    await check(
      buildEml({
        authResults: exampleAuth,
        body: "Read the docs.",
        htmlBody: '<p><a href="https://nextjs.org/docs">Next.js docs</a></p>',
      }),
      { notReason: "suspicious-links" },
    )
  })

  it("Google search URLs are not unwrapped as redirects", async () => {
    await check(
      buildEml({
        authResults: exampleAuth,
        body: "Search result.",
        htmlBody:
          '<p><a href="https://www.google.com/search?q=http%3A%2F%2F203.0.113.45">Google search</a></p>',
      }),
      { notReason: "suspicious-links" },
    )
  })

  it.each([
    ["legacy shortener", "https://bit.ly/3xyz123"],
    ["refreshed shortener", "https://t.ly/abc123"],
  ])("%s alone → caution", async (_name, url) => {
    await check(
      buildEml({
        authResults: exampleAuth,
        body: `Read more at ${url} - thanks!`,
      }),
      { tier: "caution", reason: "shortener-link" },
    )
  })

  it("non-web anchors are ignored without throwing", async () => {
    await check(
      buildEml({
        authResults: exampleAuth,
        body: "Contact support if needed.",
        htmlBody:
          '<p><a href="mailto:support@example.com">support@example.com</a><a href="#unsubscribe">unsubscribe</a></p>',
      }),
      { notReason: "suspicious-links" },
    )
  })
})

describe("attachment type risk", () => {
  const attachedFileBody = (filename: string, contentType: string): string =>
    [
      "Please review the attached file.",
      "",
      `Content-Type: ${contentType}; name="${filename}"`,
      `Content-Disposition: attachment; filename="${filename}"`,
      "",
      "placeholder",
    ].join("\r\n")

  it.each([
    ["HTML attachment", "invoice.html", "text/html"],
    ["SVG attachment", "chart.svg", "image/svg+xml"],
    ["disk image", "statement.iso", "application/octet-stream"],
    ["shortcut", "invoice.lnk", "application/octet-stream"],
    ["double extension", "invoice.pdf.exe", "application/octet-stream"],
  ])("%s escalates on its own → danger", async (_name, filename, contentType) => {
    await check(
      buildEml({
        from: "Known Vendor <billing@example.com>",
        authResults: authResults({ domain: "example.com" }),
        body: attachedFileBody(filename, contentType),
      }),
      { tier: "danger", reason: "dangerous-attachment-type" },
    )
  })
})

describe("content classification cap", () => {
  it("standalone bank-information request cannot return safe", async () => {
    const analysis = await check(
      cleanEsp({
        from: "Account Setup <accounts@news.acme.com>",
        body: "Please provide your bank information to complete account setup.",
      }),
      {
        tier: "caution",
        capped: true,
        reason: "financial-action-content",
        notReason: "document-request-content",
      },
    )

    expect(analysis.content.hasBankingDetailsRequest).toBe(true)
    expect(analysis.content.hasMoney).toBe(false)
    expect(analysis.verdict.explanation).toMatch(/bank|financial/i)
    expect(analysis.verdict.explanation).not.toMatch(/documents|signed forms/i)
  })

  it("treats updated bank details as financial content, not a personal-document request", async () => {
    const analysis = await check(
      cleanEsp({
        from: "Known Vendor <billing@news.vendor.example>",
        body: "Please use our updated bank details for the next invoice payment.",
      }),
      {
        tier: "caution",
        capped: true,
        reason: "financial-action-content",
        notReason: "document-request-content",
      },
    )

    expect(analysis.content.hasBankingChangeRequest).toBe(true)
    expect(analysis.content.hasDocumentRequest).toBe(false)
    expect(analysis.content.hasIdentityDocumentRequest).toBe(false)
    expect(analysis.verdict.reasons.map((reason) => reason.detail).join(" ")).not.toMatch(
      /passport|personal documents/i,
    )
  })

  it("describes a signed-form request without claiming identity documents were requested", async () => {
    const analysis = await check(
      cleanEsp({
        from: "Operations <operations@news.acme.com>",
        body: "Please sign and send back the attached acknowledgement form.",
      }),
      { tier: "caution", reason: "document-request-content" },
    )

    expect(analysis.content.hasSignedFormRequest).toBe(true)
    expect(analysis.content.hasIdentityDocumentRequest).toBe(false)
    expect(analysis.verdict.reasons.map((reason) => reason.detail).join(" ")).toMatch(
      /signed form/i,
    )
    expect(analysis.verdict.reasons.map((reason) => reason.detail).join(" ")).not.toMatch(
      /passport|personal documents/i,
    )
  })

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
    const analysis = await check(
      cleanEsp({
        body: "Please verify your account by clicking the link to reset your password.",
      }),
      { tier: "caution", capped: true },
    )

    expect(analysis.verdict.explanation).toMatch(/open the service/i)
    expect(analysis.verdict.explanation).not.toMatch(/verified by phone/i)
  })

  it("HTML-only money language → caution (capped)", async () => {
    await check(
      cleanEsp({
        body: "",
        htmlBody:
          "<p>Your invoice is ready. Please wire payment to the updated bank account.</p>",
      }),
      { tier: "caution", capped: true },
    )
  })

  it("tag-split HTML keywords still classify as money content", async () => {
    await check(
      cleanEsp({
        body: "",
        htmlBody: "<p>Please review this in<i></i>voice before approval.</p>",
      }),
      { tier: "caution", reason: "financial-action-content" },
    )
  })

  it("zero-width keyword evasion still classifies as money content", async () => {
    await check(
      cleanEsp({
        body: "Please review this in\u200bvoice before approval.",
      }),
      { tier: "caution", reason: "financial-action-content" },
    )
  })

  it("image-only body never returns safe", async () => {
    await check(
      cleanEsp({
        body: "",
        htmlBody: '<html><body><img src="cid:qr-code"></body></html>',
      }),
      { tier: "caution", reason: "low-readable-content" },
    )
  })

  it("public webmail + banking information update → danger", async () => {
    await check(
      cleanEsp({
        from: "Holly Straub <holly@gmail.com>",
        body:
          "I would like to request an update to my banking information before the next payroll is processed.",
      }),
      { tier: "danger", reason: "public-webmail-banking-change" },
    )
  })

  it.each([
    ["direct deposit status", "My direct deposit posted today. Thanks for confirming."],
    [
      "newsletter bank-account tips",
      "The newsletter includes bank account reconciliation tips for small businesses.",
    ],
    ["new report bank-account tips", "New report: bank account reconciliation tips for small businesses."],
  ])("public webmail %s does not trigger banking-change danger", async (_name, body) => {
    await check(
      cleanEsp({
        from: "Finance Tips <tips@gmail.com>",
        body,
      }),
      { tier: "caution", notReason: "public-webmail-banking-change" },
    )
  })

  it("executive display name + AR report request → danger", async () => {
    await check(
      cleanEsp({
        from: "Senior Executive <office.execs@seniorexecutivehost.com>",
        body:
          "Please send the most recent AR report and include customer payable contact emails.",
      }),
      { tier: "danger", reason: "executive-impersonation-with-money" },
    )
  })

  it("executive assistant display name without money does not trigger executive-money danger", async () => {
    await check(
      cleanEsp({
        from: "Executive Assistant <assistant@example.com>",
        body: "Please confirm whether tomorrow afternoon works for the planning meeting.",
      }),
      { notReason: "executive-impersonation-with-money" },
    )
  })

  it("authenticated president with ordinary dues language does not trigger executive-money danger", async () => {
    await check(
      buildEml({
        from: "Club President <president@club.example>",
        authResults: authResults({ domain: "club.example" }),
        body: "Annual membership dues are due this month. Please use the normal club portal.",
      }),
      { tier: "caution", notReason: "executive-impersonation-with-money" },
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

  it("job offer + payroll bank-details request → danger", async () => {
    const analysis = await check(
      cleanEsp({
        from: "Acme Recruiting <careers@news.acme.com>",
        subject: "Remote position onboarding",
        body:
          "We are pleased to offer you a remote position. To set up payroll, please provide your bank details and routing number.",
      }),
      { tier: "danger", reason: "job-offer-with-document-request" },
    )

    expect(analysis.content.hasBankingDetailsRequest).toBe(true)
    expect(analysis.content.hasDocumentRequest).toBe(false)
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

  it("brand ambassador partnership outreach → caution", async () => {
    await check(
      cleanEsp({
        from: "Creator Team <creator@agency.example>",
        body:
          "We would like to offer you a brand ambassador program with gifted products and commission on sales.",
      }),
      { tier: "caution", reason: "job-offer-content" },
    )
  })

  it("brand claimed in body from unrelated sender → danger", async () => {
    await check(
      cleanEsp({
        from: "Jos Bloemen <josbloemen@telenet.be>",
        subject: "Lace Up and Shine with Brooks!",
        body:
          "I'm Jos Bloemen, Influencer Manager at Credo Consulting & Content, working with Brooks Running, a premier athleisure brand from Seattle. You are an excellent candidate for our 2025 Brand Ambassador Program.",
      }),
      { tier: "danger", reason: "body-brand-claim-impersonation" },
    )
  })

  it("brand claimed in body from legitimate brand domain does not trigger body-brand danger", async () => {
    await check(
      buildEml({
        from: "Brooks Running Team <partnerships@brooksrunning.com>",
        authResults: authResults({ domain: "brooksrunning.com" }),
        subject: "Brand ambassador program",
        body:
          "We are working with Brooks Running on the 2025 Brand Ambassador Program.",
      }),
      { notReason: "body-brand-claim-impersonation" },
    )
  })

  it("word-boundary brand mention does not treat misrepresenting as representing", async () => {
    await check(
      cleanEsp({
        from: "Creator Team <creator@agency.example>",
        body:
          "This note discusses a creator misrepresenting Brooks Running in a brand ambassador pitch.",
      }),
      { notReason: "body-brand-claim-impersonation" },
    )
  })

  it("contract letter that must be signed and sent back → danger", async () => {
    await check(
      buildEml({
        from: "Gaskin Larry <gaskinlarry@polarispartnersjobs.com>",
        authResults: authResults({ domain: "polarispartnersjobs.com" }),
        body:
          "Attached above is your contract letter of agreement. You are required to fill, sign and send back for validation.",
      }),
      { tier: "danger", reason: "job-offer-with-document-request" },
    )
  })

  it("job offer signed as Polaris Partners from unrelated sender → danger", async () => {
    await check(
      cleanEsp({
        from: "Beth Fletcher <beth@example-sports.test>",
        subject: "Resume approval work from home",
        body:
          "We are pleased to approve your remote position. Please review the offer letter and reply to continue onboarding.\n\nRegards,\nPolaris Partners",
      }),
      { tier: "danger", reason: "job-brand-signature-impersonation" },
    )
  })

  it("Polaris Partners signature claim preserves line breaks for brand detection", async () => {
    await check(
      cleanEsp({
        from: "Beth Fletcher <beth@example-sports.test>",
        subject: "Remote role",
        body:
          "We are pleased to offer you a remote position.\n\nRegards,\nPolaris Partners",
      }),
      { tier: "danger", reason: "body-brand-claim-impersonation" },
    )
  })

  it("third-party recruiter mentioning Polaris Partners stays caution", async () => {
    await check(
      cleanEsp({
        from: "Recruiter <recruiter@search-firm.example>",
        subject: "Interview invitation",
        body:
          "I am a third-party recruiter coordinating an interview invitation for a possible role at Polaris Partners.",
      }),
      { tier: "caution", reason: "job-offer-content", notReason: "job-brand-signature-impersonation" },
    )
  })
})

describe("BEC openers and document lures", () => {
  it.each([
    [
      "quick-chat small-situation opener",
      {
        from: "Frank Sands <fsands@sandscapitalv.com>",
        authResults: authResults({ domain: "sandscapitalv.com" }),
        body:
          "Do you have a minute for a quick chat? We would like you to look into a small situation for us. Kindly write back and let me know.",
      },
      { tier: "caution" as const, reason: "bec-opener" },
    ],
    [
      "BEC opener with wire/payment language",
      {
        from: "Robert Nelsen <rtn@archventurep.com>",
        authResults: authResults({ domain: "archventurep.com" }),
        body:
          "Thanks for writing back. A situation was raised by my team. We need to remit a balance of $864,000 and I need you to instruct finance to wire said amount.",
      },
      { tier: "danger" as const, reason: "bec-opener-with-money" },
    ],
  ])("%s", async (_name, emlOptions, expectations) => {
    await check(buildEml(emlOptions), expectations)
  })

  it("consumer mailbox name mismatch + BEC opener → danger", async () => {
    await check(
      buildEml({
        from: "Lorenzo Larini <jeromo1@telefonica.net>",
        authResults: authResults({ domain: "telefonica.net" }),
        body:
          "Do you have a minute for a quick chat? Kindly write back and let me know.",
      }),
      { tier: "danger", reason: "consumer-mailbox-person-mismatch" },
    )
  })

  it("consumer mailbox matching display name + BEC opener stays caution", async () => {
    await check(
      buildEml({
        from: "Andrew Campbell <andrew.campbell@gmail.com>",
        authResults: authResults({ domain: "gmail.com" }),
        body:
          "Do you have a minute for a quick chat? Kindly write back and let me know.",
      }),
      { tier: "caution", reason: "bec-opener", notReason: "consumer-mailbox-person-mismatch" },
    )
  })

  it("secure document portal with unrelated link → danger", async () => {
    await check(
      buildEml({
        from: "Sam North <s.north@exeter.ac.uk>",
        authResults: authResults({ domain: "exeter.ac.uk" }),
        htmlBody:
          '<p>Rocket Mortgage</p><p>New Document(s) CD Posted to the portal for loan ending in 7027.</p><p><a href="https://rocket-fileshare-mgt.lovable.app/">View Closing Document(s)</a></p>',
      }),
      { tier: "danger", reason: "off-brand-document-link" },
    )
  })
})

describe("wire-transfer and invoice-redirection lures", () => {
  const attachmentBody = (message: string, filename: string): string =>
    [
      message,
      "",
      `Content-Type: application/pdf; name="${filename}"`,
      `Content-Disposition: attachment; filename="${filename}"`,
      "",
      "JVBERi0xLjQK",
    ].join("\r\n")

  it.each([
    [
      "weak DMARC and attachment",
      {
        from: "Roberta Edwards <redwards@vendor-team.example>",
        subject: "Request for Payment; Invoice",
        authResults:
          "mx.example.org; spf=neutral smtp.mailfrom=vendor-team.example; dkim=none; dmarc=none header.from=vendor-team.example",
        body: attachmentBody(
          "Please process this payment request for the attached invoice.",
          "leadership-bill.pdf",
        ),
      },
    ],
    [
      "RFC 2047 subject",
      {
        from: "Roberta Edwards <redwards@vendor-team.example>",
        subject: "=?UTF-8?Q?Request_for_Payment=3B_Invoice?=",
        authResults:
          "mx.example.org; spf=neutral smtp.mailfrom=vendor-team.example; dkim=none; dmarc=none header.from=vendor-team.example",
        body: attachmentBody("Please see the attached file.", "request.pdf"),
      },
    ],
  ])("invoice payment request with %s → danger", async (_name, emlOptions) => {
    await check(buildEml(emlOptions), { tier: "danger", reason: "invoice-payment-request" })
  })

  it("aligned SPF/DKIM invoice with no DMARC stays caution", async () => {
    await check(
      buildEml({
        from: "Known Vendor <billing@vendor.example>",
        subject: "Request for Payment; Invoice",
        authResults:
          "mx.example.org; spf=pass smtp.mailfrom=vendor.example; dkim=pass header.i=@vendor.example; dmarc=none header.from=vendor.example",
        body: [
          "Please process this payment request for the attached invoice.",
          "",
          "Content-Type: application/pdf; name=\"invoice.pdf\"",
          "Content-Disposition: attachment; filename=\"invoice.pdf\"",
          "",
          "JVBERi0xLjQK",
        ].join("\r\n"),
      }),
      { tier: "caution", reason: "financial-action-content", notReason: "invoice-payment-request" },
    )
  })

  it("SPF neutral with aligned DKIM and DMARC pass does not trigger fake-invoice danger", async () => {
    await check(
      buildEml({
        from: "Known Vendor <billing@vendor.example>",
        subject: "Request for Payment; Invoice",
        authResults:
          "mx.example.org; spf=neutral smtp.mailfrom=vendor.example; dkim=pass header.i=@vendor.example; dmarc=pass header.from=vendor.example",
        body: [
          "Please process this payment request for the attached invoice.",
          "",
          "Content-Type: application/pdf; name=\"invoice.pdf\"",
          "Content-Disposition: attachment; filename=\"invoice.pdf\"",
          "",
          "JVBERi0xLjQK",
        ].join("\r\n"),
      }),
      { tier: "caution", reason: "financial-action-content", notReason: "invoice-payment-request" },
    )
  })

  it("wire payment request with an attachment → danger", async () => {
    await check(
      cleanEsp({
        from: "Vendor Billing <billing@news.vendor.example>",
        subject: "Request for Payment; Invoice",
        body: [
          "Please process this invoice by ACH transfer using the routing number in the attached remittance instructions.",
          "",
          "Content-Type: application/pdf; name=\"leadership-bill.pdf\"",
          "Content-Disposition: attachment; filename=\"leadership-bill.pdf\"",
          "",
          "JVBERi0xLjQK",
        ].join("\r\n"),
      }),
      { tier: "danger", reason: "wire-transfer-lure" },
    )
  })

  it("final notice with wire routing language and an unrelated payment link → danger", async () => {
    await check(
      cleanEsp({
        from: "ASLC Group <clearing@aslc-group.example>",
        subject: "FINAL NOTICE - payment transfer required",
        htmlBody:
          '<p>Please remit the invoice by wire transfer using the routing instructions in the portal.</p><p><a href="https://settlement-upload.example.net/notice">Review payment notice</a></p>',
      }),
      { tier: "danger", reason: "wire-transfer-lure" },
    )
  })

  it("coercive final notice with exposure threat → danger", async () => {
    await check(
      cleanEsp({
        from: "ASLC Group <clearing@aslc-group.example>",
        subject: "FINAL NOTICE",
        body:
          "Final notice: payment is required for this invoice. Failure to resolve this may result in legal action and exposure of damaging facts about the recipient.",
      }),
      { tier: "danger", reason: "coercive-payment-threat" },
    )
  })

  it("ordinary invoice language without wire/routing details stays capped caution", async () => {
    await check(
      cleanEsp({
        from: "Known Vendor <billing@news.vendor.example>",
        subject: "Invoice available",
        body: "Your invoice balance is due this week. Please use your normal payment process.",
      }),
      { tier: "caution", reason: "financial-action-content", notReason: "wire-transfer-lure" },
    )
  })

  it("attached invoice with remit language but no bank details stays caution", async () => {
    await check(
      knownVendorAttachedInvoice({
        subject: "Monthly invoice",
        bodyLine: "Please remit payment by the due date listed on the attached invoice.",
        filename: "monthly-invoice.pdf",
      }),
      { tier: "caution", reason: "financial-action-content", notReason: "wire-transfer-lure" },
    )
  })

  it("attached invoice with a customer account number stays caution", async () => {
    await check(
      knownVendorAttachedInvoice({
        subject: "Monthly statement",
        bodyLine: "Customer account number: 123456. Your invoice balance is due this week.",
        filename: "monthly-statement.pdf",
      }),
      { tier: "caution", reason: "financial-action-content", notReason: "wire-transfer-lure" },
    )
  })

  it("fraud-report discussion with quoted wire details does not fire wire-lure danger", async () => {
    await check(
      cleanEsp({
        from: "Helpful Recipient <recipient.example@example.com>",
        subject: "RE: Fraudulent email",
        body: [
          "I received a fraudulent email impersonating your company and wanted to help.",
          "The fake message included ACH transfer and routing number details, but I did not act on it.",
          "",
          "Content-Type: application/pdf; name=\"fraud-evidence.pdf\"",
          "Content-Disposition: attachment; filename=\"fraud-evidence.pdf\"",
          "",
          "JVBERi0xLjQK",
        ].join("\r\n"),
      }),
      { tier: "caution", notReason: "wire-transfer-lure" },
    )
  })

  it("fake Re thread with money language → danger", async () => {
    await check(
      cleanEsp({
        from: "Vendor Billing <billing@news.vendor.example>",
        subject: "Re: Updated payment instructions",
        body:
          "Please use the updated bank account details and routing number for this invoice payment.",
      }),
      { tier: "danger", reason: "fake-reply-thread" },
    )
  })

  it("real Re thread with References does not trigger fake-thread danger", async () => {
    await check(
      cleanEsp({
        from: "Vendor Billing <billing@news.vendor.example>",
        subject: "Re: Updated payment instructions",
        extraHeaders: {
          References: "<prior-message@example.com>",
        },
        body:
          "Please use the updated bank account details and routing number for this invoice payment.",
      }),
      { notReason: "fake-reply-thread" },
    )
  })
})

describe("text-only fake invoice and refund scams", () => {
  const m365Received = [
    "from CH2PR17MB1234.namprd17.prod.outlook.com (2603:10b6:610:1::20) by DM6PR17MB5678.namprd17.prod.outlook.com with HTTPS; Mon, 01 Jan 2024 12:00:00 +0000",
    "from sender.example.com (sender.example.com [203.0.113.45]) by CH2PR17MB1234.namprd17.prod.outlook.com with ESMTPS; Mon, 01 Jan 2024 11:59:55 +0000",
  ]

  it("PGP-opaque transaction notice from public webmail → danger", async () => {
    await check(
      buildEml({
        from: "Transaction Notice <notice1234@hotmail.com>",
        subject: "Updated transaction breakdown issued TXN/ABC/1A",
        authResults:
          "mx.example.org; spf=pass smtp.mailfrom=hotmail.com; dkim=pass header.i=@hotmail.com; dmarc=pass header.from=hotmail.com",
        body:
          "-----BEGIN PGP MESSAGE-----\nVersion: OpenPGP\n\nopaque encrypted invoice body\n-----END PGP MESSAGE-----",
      }),
      { tier: "danger", reason: "encrypted-transaction-lure" },
    )
  })

  it("PGP-opaque transaction notice from a private domain stays caution", async () => {
    await check(
      buildEml({
        from: "Known Billing <billing@example.com>",
        subject: "Updated transaction breakdown issued",
        authResults: authResults({ domain: "example.com" }),
        body:
          "-----BEGIN PGP MESSAGE-----\nVersion: OpenPGP\n\nopaque encrypted invoice body\n-----END PGP MESSAGE-----",
      }),
      { tier: "caution", reason: "opaque-encrypted-body", notReason: "encrypted-transaction-lure" },
    )
  })

  it("PGP-opaque business message without transaction lure stays caution", async () => {
    await check(
      buildEml({
        from: "Known Contact <contact@example.com>",
        subject: "Encrypted note",
        authResults: authResults({ domain: "example.com" }),
        body:
          "-----BEGIN PGP MESSAGE-----\nVersion: OpenPGP\n\nopaque personal body\n-----END PGP MESSAGE-----",
      }),
      { tier: "caution", reason: "opaque-encrypted-body", notReason: "encrypted-transaction-lure" },
    )
  })

  it("PGP-opaque public-webmail project breakdown stays caution", async () => {
    await check(
      buildEml({
        from: "Personal Contact <contact@hotmail.com>",
        subject: "Project breakdown",
        authResults:
          "mx.example.org; spf=pass smtp.mailfrom=hotmail.com; dkim=pass header.i=@hotmail.com; dmarc=pass header.from=hotmail.com",
        body:
          "-----BEGIN PGP MESSAGE-----\nVersion: OpenPGP\n\nopaque project body\n-----END PGP MESSAGE-----",
      }),
      { tier: "caution", reason: "opaque-encrypted-body", notReason: "encrypted-transaction-lure" },
    )
  })

  it("recipient-side spam verdict prevents header-only sample from looking safe", async () => {
    const analysis = await check(
      buildEml({
        from: "Alex Example <notice@sender.example.test>",
        returnPath: "notice@sender.example.test",
        replyTo: "Alex Example <notice@sender.example.test>",
        subject: "your order was placed successfully",
        authResults:
          "mx.recipient.example.test; dkim=pass header.d=mail.example.test header.a=rsa-sha256",
        received: [
          "from outbound.example.test (outbound.example.test [203.0.113.73]) by mx.recipient.example.test with ESMTPS; Wed, 20 May 2026 15:07:20 +0000",
        ],
        extraHeaders: {
          "X-Spam": "Yes",
          "X-Spamd-Result":
            "default: False [6.25 / 25.00]; BAYES_SPAM(4.10)[99.00%]; MISSING_TO(1.00)[]",
          "X-Rspamd-Server": "mx1.recipient.example.test",
        },
        body: "-----BEGIN PGP MESSAGE-----\nopaque recipient-side encrypted body\n-----END PGP MESSAGE-----",
      }),
      { tier: "danger", reason: "recipient-spam-verdict" },
    )

    expect(analysis.parser.recipientSpamScore).toBe(6.25)
  })

  it("Microsoft SCL spam verdict prevents a message from looking safe", async () => {
    await check(
      buildEml({
        from: "Alex Example <notice@sender.example.test>",
        received: m365Received,
        authResults: authResults({ domain: "sender.example.test" }),
        extraHeaders: {
          "X-MS-Exchange-Organization-SCL": "6",
        },
      }),
      { tier: "danger", reason: "recipient-spam-verdict" },
    )
  })

  it("sender-supplied Microsoft SCL without Microsoft receiving context is ignored", async () => {
    await check(
      buildEml({
        from: "Alex Example <notice@sender.example.test>",
        authResults: authResults({ domain: "sender.example.test" }),
        extraHeaders: {
          "X-MS-Exchange-Organization-SCL": "6",
        },
      }),
      { notReason: "recipient-spam-verdict" },
    )
  })

  it("Microsoft Forefront phish verdict prevents a message from looking safe", async () => {
    await check(
      buildEml({
        from: "Alex Example <notice@sender.example.test>",
        received: m365Received,
        authResults: authResults({ domain: "sender.example.test" }),
        extraHeaders: {
          "X-Forefront-Antispam-Report": "CIP:203.0.113.10;CTRY:US;SFV:PHSH;",
        },
      }),
      { tier: "danger", reason: "recipient-spam-verdict" },
    )
  })

  it("SpamAssassin spam flag prevents a message from looking safe", async () => {
    await check(
      buildEml({
        from: "Alex Example <notice@sender.example.test>",
        authResults: authResults({ domain: "sender.example.test" }),
        extraHeaders: {
          "X-Spam-Flag": "YES",
          "X-Spam-Status": "Yes, score=7.2 required=5.0 tests=BAYES_99",
          "X-Spam-Checker-Version": "SpamAssassin 4.0.0 on recv.example.org",
        },
      }),
      { tier: "danger", reason: "recipient-spam-verdict" },
    )
  })

  it("standalone sender-supplied SpamAssassin flag is ignored", async () => {
    await check(
      buildEml({
        from: "Alex Example <notice@sender.example.test>",
        authResults: authResults({ domain: "sender.example.test" }),
        extraHeaders: {
          "X-Spam-Flag": "YES",
        },
      }),
      { notReason: "recipient-spam-verdict" },
    )
  })

  it("forged SpamAssassin trio without recipient checker host is ignored", async () => {
    await check(
      buildEml({
        from: "Alex Example <notice@sender.example.test>",
        authResults: authResults({ domain: "sender.example.test" }),
        extraHeaders: {
          "X-Spam-Flag": "YES",
          "X-Spam-Status": "Yes, score=7.2 required=5.0 tests=BAYES_99",
          "X-Spam-Checker-Version": "SpamAssassin 4.0.0 on attacker.example",
        },
      }),
      { notReason: "recipient-spam-verdict" },
    )
  })

  it("fake antivirus renewal phone scam → danger", async () => {
    await check(
      cleanEsp({
        from: "Billing Notice <notice@sender.example.test>",
        subject: "your order was placed successfully",
        body:
          "Renewal Date: 2026-05-20. We are pleased to confirm the renewal of your McAfee Plan for 60 Months. A charge of $499.00 has been made. Client Service Contact: 1.555.010.0199. For any adjustments to your subscription or to cancel, please contact our support.",
      }),
      { tier: "danger", reason: "subscription-refund-scam" },
    )
  })

  it("subscription invoice with separate footer phone stays caution", async () => {
    await check(
      cleanEsp({
        from: "Norton Billing <billing@norton.example>",
        subject: "Subscription invoice",
        body:
          "Your Norton subscription invoice is available. Visit your account portal for support options and normal account management resources.\n\nCompany directory: 1.555.010.0199",
      }),
      { tier: "caution", notReason: "subscription-refund-scam" },
    )
  })

  it("subscription refund scam catches a later nearby contact number", async () => {
    await check(
      cleanEsp({
        from: "McAfee Billing <billing@sender.example.test>",
        subject: "your order was placed successfully",
        body:
          "Your McAfee subscription renewal has been processed for $499. Visit support options online for account resources. To cancel this membership, contact 1.555.010.0199.",
      }),
      { tier: "danger", reason: "subscription-refund-scam" },
    )
  })

  it("bank notice for account opening with weak auth → danger", async () => {
    await check(
      buildEml({
        from: "Client Service <clientservice@bank.example>",
        subject: "A notice is available to view",
        authResults:
          "mx.example.org; spf=none smtp.mailfrom=bank.example; dkim=none; dmarc=none header.from=bank.example",
        body:
          "A notice is available to view from your bank. The notice concerns a new account opening and ACH activity.",
      }),
      { tier: "danger", reason: "bank-notice-lure" },
    )
  })
})

describe("forwarded-message guard", () => {
  const exampleAuth = authResults({ domain: "example.com" })

  it("subject prefix Fwd: without original header structure → forwarded tier", async () => {
    await check(buildEml({ subject: "Fwd: Suspicious email", received: [] }), {
      tier: "forwarded",
    })
  })

  it("body separator without original header structure → forwarded tier", async () => {
    await check(
      buildEml({
        received: [],
        body: "FYI:\n\n---------- Forwarded message ----------\nFrom: stranger@phish.example\nSubject: Urgent",
      }),
      { tier: "forwarded" },
    )
  })

  it("normal user forward with top-level auth still returns forwarded", async () => {
    await check(
      buildEml({
        subject: "Fwd: Suspicious email",
        authResults: exampleAuth,
        body: "FYI:\n\n---------- Forwarded message ----------\nFrom: stranger@phish.example\nSubject: Urgent",
      }),
      { tier: "forwarded" },
    )
  })

  it("subject prefix Fwd: with original headers still gets normal verdict", async () => {
    await check(
      buildEml({
        subject: "Fwd: urgent wire request",
        authResults: exampleAuth,
        body:
          "Do you have a minute for a quick chat? I need you to wire payment for this invoice today.",
      }),
      { tier: "danger", reason: "bec-opener-with-money" },
    )
  })
})

describe("clean ESP-routed mail", () => {
  it("fully-aligned SendGrid-routed newsletter → safe", async () => {
    const analysis = await check(cleanEsp(), { tier: "safe", reasonsEmpty: true })

    expect(analysis.verdict.headline).toBe("No obvious warning signs")
    expect(analysis.verdict.explanation).toMatch(/does not prove/i)
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
          authservId: "inbox.recipient.org",
        }),
      }),
      { notReason: "brand-impersonation-confirmed" },
    )
    expect(a.verdict.reasons.map((r) => r.signal)).not.toContain(
      "brand-impersonation-likely",
    )
  })

  it("private HELO plus public GCP source spoofing Proofpoint-protected domain → danger", async () => {
    mockFetchMxAnswer([mxAnswer(10, "mxa-0006eb01.gslb.pphosted.com")])
    const a = await check(
      buildEml({
        from: "ADP HR <team.roll@adp.com>",
        to: "team.roll@adp.com",
        subject: "Review Now Ref:625948.!",
        received: [
          "from [10.88.0.4] (118.194.74.34.bc.googleusercontent.com [34.74.194.118]) by mx0b-0006eb01.pphosted.com (PPS) with ESMTP id fixture for <team.roll@adp.com>; Wed, 24 Jun 2026 13:59:47 +0000 (GMT)",
        ],
        authResults: "ppops.net; spf=none smtp.mailfrom=",
        body: "Salary increase official notification. Review now.",
      }),
      { tier: "danger", reason: "brand-impersonation-confirmed" },
    )

    expect(a.forward.isForwarded).toBe(false)
    expect(a.parser.sourceIp).toBe("34.74.194.118")
    expect(a.parser.heloIdentity).toBeNull()
    expect(a.parser.sourceHostname).toBe("118.194.74.34.bc.googleusercontent.com")
    expect(a.parser.sendingService).toBe("Google Cloud Platform (GCP Compute Engine)")
    expect(a.mx?.provider).toBe("Proofpoint")
  })

  it("receiver-side public IP is not treated as the sender source", async () => {
    const a = await analyze(
      buildEml({
        from: "ADP HR <team.roll@adp.com>",
        to: "team.roll@adp.com",
        received: [
          "from [10.0.0.5] by mx.recipient.example (8.8.8.8) with ESMTP id fixture; Wed, 24 Jun 2026 13:59:47 +0000 (GMT)",
        ],
        authResults: "ppops.net; spf=none smtp.mailfrom=",
        body: "Review now.",
      }),
    )

    expect(a.parser.sourceIp).toBeNull()
    expect(a.forward.isForwarded).toBe(true)
    expect(a.parser.sendingService).toBe("No clear email service identified")
  })
})

describe("RDAP domain-age lookup", () => {
  it("new sender domain + weak auth + financial action → danger", async () => {
    mockDomainLookups({ rdapEvents: rdapRegisteredDaysAgo(7) })
    const a = await check(
      buildEml({
        from: "Vendor Billing <billing@fresh-payments-example.com>",
        subject: "Updated wire instructions",
        authResults:
          "mx.recipient.org; spf=none smtp.mailfrom=fresh-payments-example.com; dkim=none; dmarc=none header.from=fresh-payments-example.com",
        body:
          "Please use the updated routing number and wire transfer details for this invoice payment.",
      }),
      { tier: "danger", reason: "new-sender-domain-high-risk" },
    )

    expect(a.rdap?.domain).toBe("fresh-payments-example.com")
    expect(a.rdap?.ageDays).toBeLessThanOrEqual(7)
  })

  it("new sender domain alone stays caution", async () => {
    mockDomainLookups({ rdapEvents: rdapRegisteredDaysAgo(20) })
    await check(
      buildEml({
        from: "New Company <hello@brand-new-example.com>",
        authResults: authResults({ domain: "brand-new-example.com" }),
        body: "Thanks for connecting. Here is our new company announcement.",
      }),
      { tier: "caution", reason: "new-sender-domain" },
    )
  })

  it("public webmail sender skips MX and RDAP lookups", async () => {
    const fetchSpy = vi.fn().mockResolvedValue(mockDnsResponse([]))
    vi.stubGlobal("fetch", fetchSpy)
    const a = await analyze(
      buildEml({
        from: "Some Person <person@gmail.com>",
        authResults: authResults({ domain: "gmail.com" }),
      }),
    )

    expect(a.mx).toBeNull()
    expect(a.rdap).toBeNull()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it.each([
    ["known multi-label suffix", "sub.example.co.uk", "example.co.uk"],
    ["unlisted multi-label country-code suffix", "sub.newvendor.co.in", "newvendor.co.in"],
    ["ordinary second-level country-code domain", "mail.co.de", "co.de"],
  ])("RDAP sends only the registrable sender domain for %s", async (_name, senderDomain, expectedDomain) => {
    const fetchMock = mockDomainLookups({ rdapEvents: rdapRegisteredDaysAgo(40) })
    await analyze(
      buildEml({
        from: `Billing <billing@${senderDomain}>`,
        authResults: authResults({ domain: senderDomain }),
      }),
    )

    const rdapUrls = fetchMock.mock.calls
      .map(([input]) => String(input))
      .filter((url) => url.startsWith("https://rdap.registry.test/domain/"))
    expect(rdapUrls).toEqual([`https://rdap.registry.test/domain/${expectedDomain}`])
    expect(rdapUrls[0]).not.toContain("billing")
    expect(rdapUrls[0]).not.toContain(senderDomain)
  })
})

describe("input validation", () => {
  it("empty source throws", async () => {
    await expect(analyze("")).rejects.toThrow()
    await expect(analyze("   \n\n   ")).rejects.toThrow()
  })

  it("headers-only input is tracked as having no body", async () => {
    const a = await analyze(
      [
        "Received: from sender.example.com (sender.example.com [203.0.113.45]) by mx.example.com with ESMTPS; Mon, 01 Jan 2024 11:59:55 -0500",
        `Authentication-Results: ${authResults({ domain: "example.com" })}`,
        "From: Test Sender <sender@example.com>",
        "To: recipient@example.org",
        "Subject: Headers only",
      ].join("\r\n"),
    )
    expect(a.parser.hasBodyContent).toBe(false)
    expect(a.parser.bodyText).toBe("")
  })

  it("multipart attachment-only input is not treated as headers-only", async () => {
    const a = await analyze(
      [
        "Received: from sender.example.com (sender.example.com [203.0.113.45]) by mx.example.com with ESMTPS; Mon, 01 Jan 2024 11:59:55 -0500",
        `Authentication-Results: ${authResults({ domain: "example.com" })}`,
        "From: Test Sender <sender@example.com>",
        "To: recipient@example.org",
        "Subject: Attachment only",
        "Content-Type: multipart/mixed; boundary=\"attachment-boundary\"",
        "",
        "--attachment-boundary",
        "Content-Type: application/pdf; name=\"invoice.pdf\"",
        "Content-Disposition: attachment; filename=\"invoice.pdf\"",
        "Content-Transfer-Encoding: base64",
        "",
        "JVBERi0xLjQK",
        "--attachment-boundary--",
      ].join("\r\n"),
    )

    expect(a.parser.hasBodyContent).toBe(true)
    expect(a.parser.bodyText).toBe("")
    expect(a.attachments.map((attachment) => attachment.filename)).toContain("invoice.pdf")
  })

  it("Proton X-Attached image invoice from mismatched Outlook mailbox → danger", async () => {
    const a = await check(
      buildEml({
        from: "Alfonso Flores <najebo.motuhu@outlook.com>",
        subject: "Condition of these invoices",
        authResults: authResults({ domain: "outlook.com" }),
        extraHeaders: { "X-Attached": "0000631693.png" },
        body: "",
      }),
      { tier: "danger", reason: "image-invoice-from-mismatched-webmail" },
    )
    expect(a.attachments).toContainEqual({
      filename: "0000631693.png",
      contentType: "image/png",
    })
  })

  it("invoice image filename supplies the financial clue for a generic message → danger", async () => {
    await check(
      buildEml({
        from: "Alfonso Flores <najebo.motuhu@outlook.com>",
        subject: "Please review",
        authResults: authResults({ domain: "outlook.com" }),
        extraHeaders: { "X-Attached": "invoice.png" },
        body: "",
      }),
      { tier: "danger", reason: "image-invoice-from-mismatched-webmail" },
    )
  })

  it("folded encoded X-Attached image invoice → danger", async () => {
    const a = await check(
      buildEml({
        from: "Alfonso Flores <najebo.motuhu@outlook.com>",
        subject: "Please review",
        authResults: authResults({ domain: "outlook.com" }),
        extraHeaders: {
          "X-Attached": "=?UTF-8?Q?invoice?=\r\n =?UTF-8?Q?.png?=",
        },
        body: "",
      }),
      { tier: "danger", reason: "image-invoice-from-mismatched-webmail" },
    )
    expect(a.attachments).toContainEqual({
      filename: "invoice.png",
      contentType: "image/png",
    })
  })

  it("matching personal Outlook address with an image invoice stays caution", async () => {
    await check(
      buildEml({
        from: "Alfonso Flores <alfonso.flores@outlook.com>",
        subject: "Invoice for the landscaping work",
        authResults: authResults({ domain: "outlook.com" }),
        extraHeaders: { "X-Attached": "invoice.png" },
        body: "",
      }),
      {
        tier: "caution",
        reason: "low-readable-content",
        notReason: "image-invoice-from-mismatched-webmail",
      },
    )
  })
})

// Real-eml regression fixtures live in __tests__/fixtures/. Each is a
// case the analyzer should catch but didn't at the time it was added.
describe("real-eml regression cases", () => {
  it("raleighcountyfcu RMS self-send (compromised M365 mailbox) → danger", async () => {
    const eml = readFileSync(
      resolve(__dirname, "fixtures/raleighcountyfcu-rms-self-send.eml"),
      "utf8",
    )
    const a = await analyze(eml)
    expect(a.verdict.tier).toBe("danger")
    expect(a.verdict.reasons.map((r) => r.signal)).toContain("rms-self-send")
  })
})

describe("encrypted self-send (RMS) compromise pattern", () => {
  const selfMailbox = "epowers@example-fcu.com"
  const selfAuth = authResults({
    domain: "example-fcu.com",
    dkim: "none",
    dmarc: "none",
  })

  it("From == To AND Content-Class: rpmsg.message → danger, rms-self-send", async () => {
    await check(
      buildEml({
        from: `Emily Powers <${selfMailbox}>`,
        to: `Emily Powers <${selfMailbox}>`,
        authResults: selfAuth,
        contentClass: "rpmsg.message",
      }),
      { tier: "danger", reason: "rms-self-send" },
    )
  })

  it("self-send alone (no RMS) does NOT fire rms-self-send", async () => {
    await check(
      buildEml({
        from: `Emily Powers <${selfMailbox}>`,
        to: `Emily Powers <${selfMailbox}>`,
        authResults: selfAuth,
      }),
      { notReason: "rms-self-send" },
    )
  })

  it("RMS alone (different recipient) does NOT fire rms-self-send", async () => {
    await check(
      buildEml({
        from: `Emily Powers <${selfMailbox}>`,
        to: "Other Person <other@example-fcu.com>",
        authResults: selfAuth,
        contentClass: "rpmsg.message",
      }),
      { notReason: "rms-self-send" },
    )
  })

  it("self-send + RMS but different case → still fires (case-insensitive match)", async () => {
    await check(
      buildEml({
        from: `Emily Powers <${selfMailbox.toUpperCase()}>`,
        to: `Emily Powers <${selfMailbox}>`,
        authResults: selfAuth,
        contentClass: "rpmsg.message",
      }),
      { tier: "danger", reason: "rms-self-send" },
    )
  })
})
