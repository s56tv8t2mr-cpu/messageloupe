// Regression tests for the verdict rule engine.
//
// Each test exercises one rule path with a synthetic .eml fixture and
// asserts the tier + the presence of the reason signal that should fire.
// The point is to catch behavior drift when the rules in verdict.ts move:
// if a refactor accidentally stops emitting "dmarc-fail" or stops escalating
// to danger on a brand-impersonation match, these will fail loudly.

import { describe, expect, it } from "vitest"

import { analyze } from "../index"
import { authResults, buildEml, cleanEsp } from "./fixtures"

const reasonSignals = (a: ReturnType<typeof analyze>) =>
  a.verdict.reasons.map((r) => r.signal)

describe("authentication failures", () => {
  it("DMARC fail → danger", () => {
    const eml = buildEml({
      from: "Bank Alerts <alerts@bank.example>",
      authResults: authResults({ domain: "bank.example", dmarc: "fail" }),
    })
    const a = analyze(eml)
    expect(a.verdict.tier).toBe("danger")
    expect(reasonSignals(a)).toContain("dmarc-fail")
  })

  it("SPF fail → danger", () => {
    const eml = buildEml({
      from: "Sender <user@example.com>",
      authResults: authResults({ domain: "example.com", spf: "fail", dmarc: "none" }),
    })
    const a = analyze(eml)
    expect(a.verdict.tier).toBe("danger")
    expect(reasonSignals(a)).toContain("spf-fail")
  })

  it("SPF softfail → caution", () => {
    const eml = buildEml({
      authResults: authResults({ domain: "example.com", spf: "softfail" }),
    })
    const a = analyze(eml)
    expect(a.verdict.tier).toBe("caution")
    expect(reasonSignals(a)).toContain("spf-softfail")
  })

  it("DKIM fail with SPF pass → caution", () => {
    const eml = buildEml({
      authResults: authResults({ domain: "example.com", dkim: "fail" }),
    })
    const a = analyze(eml)
    expect(a.verdict.tier).toBe("caution")
    expect(reasonSignals(a)).toContain("dkim-fail")
  })

  it("no auth results at all → caution with no-auth", () => {
    const eml = buildEml({})
    const a = analyze(eml)
    expect(a.verdict.tier).toBe("caution")
    expect(reasonSignals(a)).toContain("no-auth")
  })
})

describe("display-name impersonation", () => {
  it("brand-impersonation: PayPal display from random domain → danger", () => {
    const eml = buildEml({
      from: "PayPal Service <service@random-payments.com>",
      authResults: authResults({ domain: "random-payments.com" }),
    })
    const a = analyze(eml)
    expect(a.verdict.tier).toBe("danger")
    expect(reasonSignals(a)).toContain("brand-impersonation")
  })

  it("brand-impersonation suppressed when domain is on the legit list", () => {
    const eml = buildEml({
      from: "PayPal <service@paypal.com>",
      authResults: authResults({ domain: "paypal.com" }),
    })
    const a = analyze(eml)
    expect(reasonSignals(a)).not.toContain("brand-impersonation")
  })

  it("role-impersonation from a public webmail → danger", () => {
    const eml = buildEml({
      from: "Human Resources <hr.notice@gmail.com>",
      authResults: authResults({ domain: "gmail.com" }),
    })
    const a = analyze(eml)
    expect(a.verdict.tier).toBe("danger")
    expect(reasonSignals(a)).toContain("role-impersonation-webmail")
  })

  it("role-impersonation from a typosquat-shape domain → danger", () => {
    const eml = buildEml({
      from: "IT Support <support@h3lp-desk-corp-77.com>",
      authResults: authResults({ domain: "h3lp-desk-corp-77.com" }),
    })
    const a = analyze(eml)
    expect(a.verdict.tier).toBe("danger")
    expect(reasonSignals(a)).toContain("role-impersonation-sketchy-domain")
  })

  it("typosquat-shape domain alone (no role/brand match) → caution", () => {
    const eml = buildEml({
      from: "John Smith <john@7secure-mail.com>",
      authResults: authResults({ domain: "7secure-mail.com" }),
    })
    const a = analyze(eml)
    expect(a.verdict.tier).toBe("caution")
    expect(reasonSignals(a)).toContain("domain-typosquat-shape")
  })
})

describe("link flags", () => {
  const exampleAuth = authResults({ domain: "example.com" })

  it("anchor/href mismatch → danger", () => {
    const eml = buildEml({
      authResults: exampleAuth,
      body: "Click the link to verify.",
      htmlBody:
        '<p>Click <a href="http://attacker.example/login">https://your-bank.com/secure</a> to verify.</p>',
    })
    const a = analyze(eml)
    expect(a.verdict.tier).toBe("danger")
    expect(reasonSignals(a)).toContain("suspicious-links")
  })

  it("raw-IP host link → danger", () => {
    const eml = buildEml({
      authResults: exampleAuth,
      body: "Visit http://203.0.113.45/login to access your account.",
    })
    const a = analyze(eml)
    expect(a.verdict.tier).toBe("danger")
    expect(reasonSignals(a)).toContain("suspicious-links")
  })

  it("shortener link alone → caution", () => {
    const eml = buildEml({
      authResults: exampleAuth,
      body: "Read more at https://bit.ly/3xyz123 — thanks!",
    })
    const a = analyze(eml)
    expect(a.verdict.tier).toBe("caution")
    expect(reasonSignals(a)).toContain("shortener-link")
  })
})

describe("content classification cap", () => {
  it("clean auth + money language → caution (capped)", () => {
    const eml = cleanEsp({
      from: "Acme Billing <billing@news.acme.com>",
      body: "Your invoice balance due is $1,250. Please wire payment to the account on file.",
    })
    const a = analyze(eml)
    expect(a.verdict.tier).toBe("caution")
    expect(a.verdict.capped).toBe(true)
  })

  it("clean auth + credentials language → caution (capped)", () => {
    const eml = cleanEsp({
      body: "Please verify your account by clicking the link to reset your password.",
    })
    const a = analyze(eml)
    expect(a.verdict.tier).toBe("caution")
    expect(a.verdict.capped).toBe(true)
  })
})

describe("job-offer scams", () => {
  it("job offer + document request → danger", () => {
    const eml = buildEml({
      from: "Talent Team <careers@new-opportunities-inc.com>",
      authResults: authResults({ domain: "new-opportunities-inc.com" }),
      body: "We are pleased to offer you a remote position. Please email a scan of your passport and a copy of your driver's license to begin onboarding.",
    })
    const a = analyze(eml)
    expect(a.verdict.tier).toBe("danger")
    expect(reasonSignals(a)).toContain("job-offer-with-document-request")
  })

  it("job offer alone → caution", () => {
    const eml = cleanEsp({
      from: "Acme Recruiting <careers@news.acme.com>",
      body: "Welcome to the team! Your offer letter is attached. Looking forward to your start date.",
    })
    const a = analyze(eml)
    // pure offer language without document request stays at caution.
    expect(a.verdict.tier).toBe("caution")
    expect(reasonSignals(a)).toContain("job-offer-content")
  })
})

describe("forwarded-message guard", () => {
  const exampleAuth = authResults({ domain: "example.com" })

  it("subject prefix Fwd: → forwarded tier, no verdict issued", () => {
    const eml = buildEml({
      subject: "Fwd: Suspicious email",
      authResults: exampleAuth,
    })
    const a = analyze(eml)
    expect(a.verdict.tier).toBe("forwarded")
  })

  it("body separator '----- Forwarded message -----' → forwarded tier", () => {
    const eml = buildEml({
      authResults: exampleAuth,
      body: "FYI:\n\n---------- Forwarded message ----------\nFrom: stranger@phish.example\nSubject: Urgent",
    })
    const a = analyze(eml)
    expect(a.verdict.tier).toBe("forwarded")
  })
})

describe("clean ESP-routed mail", () => {
  it("fully-aligned SendGrid-routed newsletter → safe", () => {
    const a = analyze(cleanEsp())
    expect(a.verdict.tier).toBe("safe")
    expect(a.verdict.reasons).toEqual([])
  })
})

describe("Reply-To routing", () => {
  const vendorAuth = authResults({ domain: "vendor-a.example" })

  it("Reply-To on a different registrable domain (no List-Id) → caution", () => {
    const eml = buildEml({
      from: "Vendor <hello@vendor-a.example>",
      replyTo: "ops@vendor-b-payments.example",
      authResults: vendorAuth,
    })
    const a = analyze(eml)
    expect(a.verdict.tier).toBe("caution")
    expect(reasonSignals(a)).toContain("replyto-cross-domain")
  })

  it("Reply-To cross-domain suppressed when List-Id is present (mailing list)", () => {
    const eml = buildEml({
      from: "Vendor <hello@vendor-a.example>",
      replyTo: "ops@vendor-b.example",
      listId: "<announce.vendor-a.example>",
      authResults: vendorAuth,
    })
    const a = analyze(eml)
    expect(reasonSignals(a)).not.toContain("replyto-cross-domain")
  })
})

describe("input validation", () => {
  it("empty source throws", () => {
    expect(() => analyze("")).toThrow()
    expect(() => analyze("   \n\n   ")).toThrow()
  })
})
