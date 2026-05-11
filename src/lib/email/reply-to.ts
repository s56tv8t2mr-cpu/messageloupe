// Reply-To mismatch assessment.
//
// Phishing campaigns commonly send through one infrastructure (often a
// hijacked/lookalike sending domain) while routing victim replies to a
// separate attacker-controlled address. The two-tier signal:
//
//   strong   — From and Reply-To share the same local-part but differ in
//              domain (e.g. andrew@longisland.com vs andrew@ceocoach-int.com).
//              Hallmark of brand-impersonation abuse — replies are redirected
//              to an attacker-controlled mailbox.
//   mismatch — Domains differ, local-parts don't match. Lower confidence,
//              still worth surfacing.
//
// The skip list suppresses legitimate routing patterns: ESP relays (SendGrid,
// Mailgun, etc.) and notification subdomains (notify., noreply., etc.) where
// a different Reply-To is normal and expected.
//
// Tuned against ~250 real phishing samples in a sibling project. Expected
// precision after skip list: 100% on 'strong', ~89% on 'mismatch'.

import { sameRegistrable } from "./domain"
import type { ParserResult } from "./types"

export type ReplyToAssessment = "strong" | "mismatch" | null

export interface ReplyToCheck {
  email: string | null
  domain: string | null
  assessment: ReplyToAssessment
  note: string | null
}

const SKIP_EXACT_DOMAINS = new Set([
  "surveymonkeyuser.com",
  "sendgrid.net",
  "mailgun.org",
  "mailgun.com",
  "amazonses.com",
  "sparkpostmail.com",
  "mcsv.net",
  "mandrillapp.com",
  "postmarkapp.com",
  "mailjet.com",
  "brevo.com",
  "sendinblue.com",
  "hubspotemail.net",
  "createsend.com",
  "klaviyomail.com",
  "rsgsv.net",
  "mailerlite.com",
])

const SKIP_PREFIXES = ["notify.", "noreply.", "no-reply.", "donotreply."]

function localPart(email: string | null): string | null {
  if (!email) return null
  const at = email.lastIndexOf("@")
  if (at <= 0) return null
  return email.slice(0, at).toLowerCase()
}

function onSkipList(domain: string | null): boolean {
  if (!domain) return false
  const d = domain.toLowerCase()
  if (SKIP_EXACT_DOMAINS.has(d)) return true
  return SKIP_PREFIXES.some((p) => d.startsWith(p))
}

export function assessReplyTo(parser: ParserResult): ReplyToCheck {
  const email = parser.replyTo
  const domain = parser.replyToDomain
  const fromEmail = parser.sendingEmail
  const fromDomain = parser.sendingDomain

  if (!email || !domain || !fromDomain) {
    return { email, domain, assessment: null, note: null }
  }

  // Same registrable domain (including subdomain → parent like
  // hello@news.acme.com / support@acme.com) is normal organizational
  // routing, not phishing.
  if (sameRegistrable(domain, fromDomain)) {
    return { email, domain, assessment: null, note: null }
  }

  // Mailing lists legitimately set Reply-To to the list address on a
  // different domain. List-Id presence is the canonical signal that this
  // is bulk/list traffic and not a phishing campaign.
  if (parser.listId) {
    return { email, domain, assessment: null, note: null }
  }

  if (onSkipList(fromDomain) || onSkipList(domain)) {
    return { email, domain, assessment: null, note: null }
  }

  const fromLocal = localPart(fromEmail)
  const replyLocal = localPart(email)

  if (fromLocal && replyLocal && fromLocal === replyLocal) {
    return {
      email,
      domain,
      assessment: "strong",
      note: `Reply-To uses a different domain (${domain}) but the same name as the visible sender — a common pattern in brand-impersonation attacks designed to make redirected replies look natural.`,
    }
  }

  return {
    email,
    domain,
    assessment: "mismatch",
    note: `Reply-To (${domain}) differs from the visible sender domain (${fromDomain}). Replies will go to a different party, treat with caution.`,
  }
}
