// Regression tests for the verdict rule engine.
//
// Each test exercises one rule path with a synthetic .eml fixture and
// asserts the tier + the presence of the reason signal that should fire.
// The point is to catch behavior drift when the rules in verdict.ts move:
// if a refactor accidentally stops emitting "dmarc-fail" or stops escalating
// to danger on a brand-impersonation match, these will fail loudly.

import { describe, expect, it } from "vitest"

import { analyze } from "../index"
import type { VerdictTier } from "../types"
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
function check(eml: string, e: Expectations): ReturnType<typeof analyze> {
  const a = analyze(eml)
  const signals = a.verdict.reasons.map((r) => r.signal)
  if (e.tier !== undefined) expect(a.verdict.tier).toBe(e.tier)
  if (e.reason !== undefined) expect(signals).toContain(e.reason)
  if (e.notReason !== undefined) expect(signals).not.toContain(e.notReason)
  if (e.capped !== undefined) expect(a.verdict.capped).toBe(e.capped)
  if (e.reasonsEmpty) expect(a.verdict.reasons).toEqual([])
  return a
}

describe("authentication failures", () => {
  it("DMARC fail → danger", () => {
    check(
      buildEml({
        from: "Bank Alerts <alerts@bank.example>",
        authResults: authResults({ domain: "bank.example", dmarc: "fail" }),
      }),
      { tier: "danger", reason: "dmarc-fail" },
    )
  })

  it("SPF fail → danger", () => {
    check(
      buildEml({
        from: "Sender <user@example.com>",
        authResults: authResults({ domain: "example.com", spf: "fail", dmarc: "none" }),
      }),
      { tier: "danger", reason: "spf-fail" },
    )
  })

  it("SPF softfail → caution", () => {
    check(
      buildEml({ authResults: authResults({ domain: "example.com", spf: "softfail" }) }),
      { tier: "caution", reason: "spf-softfail" },
    )
  })

  it("DKIM fail with SPF pass → caution", () => {
    check(
      buildEml({ authResults: authResults({ domain: "example.com", dkim: "fail" }) }),
      { tier: "caution", reason: "dkim-fail" },
    )
  })

  it("no auth results at all → caution with no-auth", () => {
    check(buildEml({}), { tier: "caution", reason: "no-auth" })
  })
})

describe("display-name impersonation", () => {
  it("brand-impersonation: PayPal display from random domain → danger", () => {
    check(
      buildEml({
        from: "PayPal Service <service@random-payments.com>",
        authResults: authResults({ domain: "random-payments.com" }),
      }),
      { tier: "danger", reason: "brand-impersonation" },
    )
  })

  it("brand-impersonation suppressed when domain is on the legit list", () => {
    check(
      buildEml({
        from: "PayPal <service@paypal.com>",
        authResults: authResults({ domain: "paypal.com" }),
      }),
      { notReason: "brand-impersonation" },
    )
  })

  it("role-impersonation from a public webmail → danger", () => {
    check(
      buildEml({
        from: "Human Resources <hr.notice@gmail.com>",
        authResults: authResults({ domain: "gmail.com" }),
      }),
      { tier: "danger", reason: "role-impersonation-webmail" },
    )
  })

  it("role-impersonation from a typosquat-shape domain → danger", () => {
    check(
      buildEml({
        from: "IT Support <support@h3lp-desk-corp-77.com>",
        authResults: authResults({ domain: "h3lp-desk-corp-77.com" }),
      }),
      { tier: "danger", reason: "role-impersonation-sketchy-domain" },
    )
  })

  it("typosquat-shape domain alone (no role/brand match) → caution", () => {
    check(
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

  it("anchor/href mismatch → danger", () => {
    check(
      buildEml({
        authResults: exampleAuth,
        body: "Click the link to verify.",
        htmlBody:
          '<p>Click <a href="http://attacker.example/login">https://your-bank.com/secure</a> to verify.</p>',
      }),
      { tier: "danger", reason: "suspicious-links" },
    )
  })

  it("raw-IP host link → danger", () => {
    check(
      buildEml({
        authResults: exampleAuth,
        body: "Visit http://203.0.113.45/login to access your account.",
      }),
      { tier: "danger", reason: "suspicious-links" },
    )
  })

  it("shortener link alone → caution", () => {
    check(
      buildEml({
        authResults: exampleAuth,
        body: "Read more at https://bit.ly/3xyz123 — thanks!",
      }),
      { tier: "caution", reason: "shortener-link" },
    )
  })
})

describe("content classification cap", () => {
  it("clean auth + money language → caution (capped)", () => {
    check(
      cleanEsp({
        from: "Acme Billing <billing@news.acme.com>",
        body: "Your invoice balance due is $1,250. Please wire payment to the account on file.",
      }),
      { tier: "caution", capped: true },
    )
  })

  it("clean auth + credentials language → caution (capped)", () => {
    check(
      cleanEsp({
        body: "Please verify your account by clicking the link to reset your password.",
      }),
      { tier: "caution", capped: true },
    )
  })
})

describe("job-offer scams", () => {
  it("job offer + document request → danger", () => {
    check(
      buildEml({
        from: "Talent Team <careers@new-opportunities-inc.com>",
        authResults: authResults({ domain: "new-opportunities-inc.com" }),
        body: "We are pleased to offer you a remote position. Please email a scan of your passport and a copy of your driver's license to begin onboarding.",
      }),
      { tier: "danger", reason: "job-offer-with-document-request" },
    )
  })

  it("job offer alone → caution", () => {
    check(
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

  it("subject prefix Fwd: → forwarded tier, no verdict issued", () => {
    check(buildEml({ subject: "Fwd: Suspicious email", authResults: exampleAuth }), {
      tier: "forwarded",
    })
  })

  it("body separator '----- Forwarded message -----' → forwarded tier", () => {
    check(
      buildEml({
        authResults: exampleAuth,
        body: "FYI:\n\n---------- Forwarded message ----------\nFrom: stranger@phish.example\nSubject: Urgent",
      }),
      { tier: "forwarded" },
    )
  })
})

describe("clean ESP-routed mail", () => {
  it("fully-aligned SendGrid-routed newsletter → safe", () => {
    check(cleanEsp(), { tier: "safe", reasonsEmpty: true })
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

  it.each(NO_FLAG_CASES)("$name → no flag", ({ eml }) => {
    const a = analyze(eml())
    const signals = a.verdict.reasons.map((r) => r.signal)
    expect(a.replyTo.assessment).toBeNull()
    expect(signals).not.toContain("replyto-mismatch")
    expect(signals).not.toContain("replyto-strong-mismatch")
  })

  it("same local-part, different domain → strong, danger", () => {
    const a = check(
      replyToEml({
        from: "Andrew Campbell <andrew@longisland.com>",
        fromDomain: "longisland.com",
        replyTo: "andrew@ceocoach-int.com",
      }),
      { tier: "danger", reason: "replyto-strong-mismatch" },
    )
    expect(a.replyTo.assessment).toBe("strong")
    expect(a.replyTo.domain).toBe("ceocoach-int.com")
  })

  it("different local-part and different domain → mismatch, danger", () => {
    const a = check(
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

describe("input validation", () => {
  it("empty source throws", () => {
    expect(() => analyze("")).toThrow()
    expect(() => analyze("   \n\n   ")).toThrow()
  })
})
