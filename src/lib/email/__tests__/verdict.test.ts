// Regression tests for the verdict rule engine.
//
// Each test exercises one rule path with a synthetic .eml fixture and
// asserts the tier + the presence of the reason signal that should fire.
// The point is to catch behavior drift when the rules in verdict.ts move:
// if a refactor accidentally stops emitting "dmarc-fail" or stops escalating
// to danger on a brand-impersonation match, these will fail loudly.

import { describe, expect, it } from "vitest"

import { analyze } from "../index"
import { buildEml, cleanEsp } from "./fixtures"

const reasonSignals = (a: ReturnType<typeof analyze>) =>
  a.verdict.reasons.map((r) => r.signal)

describe("authentication failures", () => {
  it("DMARC fail → danger", () => {
    const eml = buildEml({
      from: "Bank Alerts <alerts@bank.example>",
      authResults: "mx.recipient.org; spf=pass smtp.mailfrom=bank.example; dkim=pass header.i=@bank.example; dmarc=fail header.from=bank.example",
    })
    const a = analyze(eml)
    expect(a.verdict.tier).toBe("danger")
    expect(reasonSignals(a)).toContain("dmarc-fail")
  })

  it("SPF fail → danger", () => {
    const eml = buildEml({
      from: "Sender <user@example.com>",
      authResults: "mx.recipient.org; spf=fail smtp.mailfrom=example.com; dmarc=none",
    })
    const a = analyze(eml)
    expect(a.verdict.tier).toBe("danger")
    expect(reasonSignals(a)).toContain("spf-fail")
  })

  it("SPF softfail → caution", () => {
    const eml = buildEml({
      authResults: "mx.recipient.org; spf=softfail smtp.mailfrom=example.com; dkim=pass header.i=@example.com; dmarc=pass",
    })
    const a = analyze(eml)
    expect(a.verdict.tier).toBe("caution")
    expect(reasonSignals(a)).toContain("spf-softfail")
  })

  it("DKIM fail with SPF pass → caution", () => {
    const eml = buildEml({
      authResults: "mx.recipient.org; spf=pass smtp.mailfrom=example.com; dkim=fail header.i=@example.com; dmarc=pass",
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
      authResults: "mx.recipient.org; spf=pass smtp.mailfrom=random-payments.com; dkim=pass header.i=@random-payments.com; dmarc=pass",
    })
    const a = analyze(eml)
    expect(a.verdict.tier).toBe("danger")
    expect(reasonSignals(a)).toContain("brand-impersonation")
  })

  it("brand-impersonation suppressed when domain is on the legit list", () => {
    const eml = buildEml({
      from: "PayPal <service@paypal.com>",
      authResults: "mx.recipient.org; spf=pass smtp.mailfrom=paypal.com; dkim=pass header.i=@paypal.com; dmarc=pass",
    })
    const a = analyze(eml)
    expect(reasonSignals(a)).not.toContain("brand-impersonation")
  })

  it("role-impersonation from a public webmail → danger", () => {
    const eml = buildEml({
      from: "Human Resources <hr.notice@gmail.com>",
      authResults: "mx.recipient.org; spf=pass smtp.mailfrom=gmail.com; dkim=pass header.i=@gmail.com; dmarc=pass",
    })
    const a = analyze(eml)
    expect(a.verdict.tier).toBe("danger")
    expect(reasonSignals(a)).toContain("role-impersonation-webmail")
  })

  it("role-impersonation from a typosquat-shape domain → danger", () => {
    const eml = buildEml({
      from: "IT Support <support@h3lp-desk-corp-77.com>",
      authResults: "mx.recipient.org; spf=pass smtp.mailfrom=h3lp-desk-corp-77.com; dkim=pass header.i=@h3lp-desk-corp-77.com; dmarc=pass",
    })
    const a = analyze(eml)
    expect(a.verdict.tier).toBe("danger")
    expect(reasonSignals(a)).toContain("role-impersonation-sketchy-domain")
  })

  it("typosquat-shape domain alone (no role/brand match) → caution", () => {
    const eml = buildEml({
      from: "John Smith <john@7secure-mail.com>",
      authResults: "mx.recipient.org; spf=pass smtp.mailfrom=7secure-mail.com; dkim=pass header.i=@7secure-mail.com; dmarc=pass",
    })
    const a = analyze(eml)
    expect(a.verdict.tier).toBe("caution")
    expect(reasonSignals(a)).toContain("domain-typosquat-shape")
  })
})

describe("link flags", () => {
  it("anchor/href mismatch → danger", () => {
    const eml = buildEml({
      authResults: "mx.recipient.org; spf=pass smtp.mailfrom=example.com; dkim=pass header.i=@example.com; dmarc=pass",
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
      authResults: "mx.recipient.org; spf=pass smtp.mailfrom=example.com; dkim=pass header.i=@example.com; dmarc=pass",
      body: 'Visit http://203.0.113.45/login to access your account.',
    })
    const a = analyze(eml)
    expect(a.verdict.tier).toBe("danger")
    expect(reasonSignals(a)).toContain("suspicious-links")
  })

  it("shortener link alone → caution", () => {
    const eml = buildEml({
      authResults: "mx.recipient.org; spf=pass smtp.mailfrom=example.com; dkim=pass header.i=@example.com; dmarc=pass",
      body: 'Read more at https://bit.ly/3xyz123 — thanks!',
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
      authResults: "mx.recipient.org; spf=pass smtp.mailfrom=new-opportunities-inc.com; dkim=pass header.i=@new-opportunities-inc.com; dmarc=pass",
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
    // job-offer + attachment-with-suspicious-content scenarios not used here;
    // pure offer language without document request stays at caution.
    expect(a.verdict.tier).toBe("caution")
    expect(reasonSignals(a)).toContain("job-offer-content")
  })
})

describe("forwarded-message guard", () => {
  it("subject prefix Fwd: → forwarded tier, no verdict issued", () => {
    const eml = buildEml({
      subject: "Fwd: Suspicious email",
      authResults: "mx.recipient.org; spf=pass smtp.mailfrom=example.com; dkim=pass header.i=@example.com; dmarc=pass",
    })
    const a = analyze(eml)
    expect(a.verdict.tier).toBe("forwarded")
  })

  it("body separator '----- Forwarded message -----' → forwarded tier", () => {
    const eml = buildEml({
      authResults: "mx.recipient.org; spf=pass smtp.mailfrom=example.com; dkim=pass header.i=@example.com; dmarc=pass",
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
  it("Reply-To on a different registrable domain (no List-Id) → caution", () => {
    const eml = buildEml({
      from: "Vendor <hello@vendor-a.example>",
      replyTo: "ops@vendor-b-payments.example",
      authResults: "mx.recipient.org; spf=pass smtp.mailfrom=vendor-a.example; dkim=pass header.i=@vendor-a.example; dmarc=pass",
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
      authResults: "mx.recipient.org; spf=pass smtp.mailfrom=vendor-a.example; dkim=pass header.i=@vendor-a.example; dmarc=pass",
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
