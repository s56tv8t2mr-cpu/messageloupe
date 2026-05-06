// Content classifier for the verdict-cap rule.
//
// If a message mentions money/credentials/urgency, the verdict cannot rise
// above "Caution — verify by phone," even when every technical signal looks
// clean. This is a deliberate safety floor: header analysis is structurally
// blind to BEC sent from a compromised real account, where every auth check
// passes but the message is still hostile. The cap forces honest UX in that
// blind spot.
//
// Keyword-based v1 — no ML, no network. Fast, predictable, easy to audit.

import type { ContentClassification } from "./types"

const MONEY_PATTERNS: RegExp[] = [
  /\bwire(?:\s+(?:transfer|instructions?|details?|info))?\b/i,
  /\bach\s+(?:transfer|payment|debit)\b/i,
  /\b(?:routing|account)\s+number\b/i,
  /\b(?:swift|iban|bic)\b/i,
  /\bbank\s+(?:account|change|details|info)\b/i,
  /\bchange(?:\s+of|\s+in)?\s+(?:bank|payment|banking)\b/i,
  /\bgift\s+cards?\b/i,
  /\bvanilla\s+(?:gift|prepaid)\b/i,
  /\b(?:bitcoin|btc|crypto(?:currency)?|ethereum|usdt|wallet\s+address)\b/i,
  /\binvoice\b/i,
  /\bbalance\s+due\b/i,
  /\bpast\s+due\b/i,
  /\bpayment\s+(?:due|required|overdue|info|details)\b/i,
  /\bdirect\s+deposit\b/i,
  /\bpayroll\s+(?:change|update)\b/i,
  /\b(?:remit|remittance)\b/i,
  /\bw-?9\b/i,
  /\bach\s+form\b/i,
  /\bsend\s+(?:money|funds|payment)\b/i,
  /\$\s?\d/,
]

const CREDENTIAL_PATTERNS: RegExp[] = [
  /\bpasswords?\b/i,
  /\bpasscode\b/i,
  /\bverify\s+(?:your\s+)?(?:account|identity|email|password|payment)/i,
  /\b(?:re-?)?confirm\s+your\s+(?:account|password|identity|email)/i,
  /\bvalidate\s+your\b/i,
  /\bupdate\s+your\s+(?:account|password|payment|billing|info)/i,
  /\bsecure\s+your\s+account\b/i,
  /\b(?:log|sign)\s*-?\s*in\s+(?:to|here|now|required)/i,
  /\b(?:one[\s-]?time|2fa|mfa|two[\s-]?factor|authentication)\s+code/i,
  /\bsecurity\s+(?:question|code)/i,
  /\baccess\s+code\b/i,
  /\bunlock\s+your\s+account\b/i,
  /\breset\s+(?:your\s+)?password/i,
]

const URGENCY_PATTERNS: RegExp[] = [
  /\burgent(?:ly)?\b/i,
  /\bimmediately\b/i,
  /\bright\s+away\b/i,
  /\bwithin\s+(?:24|12|48|72)\s+hours?\b/i,
  /\bwithin\s+the\s+next\s+\d+\s+(?:hours?|minutes?)/i,
  /\b(?:account|access|mailbox|membership)\s+(?:has\s+been\s+|will\s+be\s+)?(?:locked|suspended|terminated|closed|disabled|deactivated)/i,
  /\bact\s+now\b/i,
  /\bact\s+today\b/i,
  /\bexpires?\s+(?:today|tomorrow|in\s+\d+|soon)/i,
  /\b(?:final|last)\s+(?:notice|warning|chance|reminder)/i,
  /\btoday\s+only\b/i,
  /\bdo\s+not\s+(?:delay|ignore)/i,
  /\btime[\s-]?sensitive\b/i,
]

const matchAny = (text: string, patterns: RegExp[]): boolean =>
  patterns.some((p) => p.test(text))

export function classifyContent(text: string): ContentClassification {
  const target = text || ""
  return {
    hasMoney: matchAny(target, MONEY_PATTERNS),
    hasCredentials: matchAny(target, CREDENTIAL_PATTERNS),
    hasUrgency: matchAny(target, URGENCY_PATTERNS),
  }
}

export function shouldCapVerdict(c: ContentClassification): boolean {
  return c.hasMoney || c.hasCredentials
}
