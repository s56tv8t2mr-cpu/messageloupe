// Sender-trust heuristics — go beyond authentication-result checking.
//
// The original toolkit assumed the analyst already had a strong prior that
// the input was a phish; their job was to route it. In Message Loupe the
// user is judging cold, so the engine has to do more of the suspicion
// lifting on the user's behalf.
//
// Three classes of signal that authentication alone misses:
//   1. Display-name *role* impersonation — "Human Resources" / "IT Support"
//      / "Office of the CEO" sent from a domain that doesn't look like any
//      real employer. The actual email is From a throwaway domain that
//      authenticates fine *for itself* — but no one's HR is at
//      random-letters-and-digits dot com.
//   2. Display-name *brand* impersonation — the display name claims a
//      well-known brand (Microsoft, PayPal, ADP, etc.), but the From:
//      domain isn't on that brand's known sender list.
//   3. Typosquat-shape sending domains — domains with shapes commonly used
//      for throwaway phishing infrastructure: digits-and-letters mixed,
//      leading digit, punycode, very long hyphenated labels.

import type { ParserResult } from "./types"

// Department / role display names commonly used in phishing.
// These match against the *display name* only, not the email body.
const ROLE_IMPERSONATION_PATTERNS: RegExp[] = [
  /\bhuman\s+resources?\b/i,
  /^h\.?r\.?$/i,
  /^h\.?r\.?\s+(department|team|notice|admin)/i,
  /\bhr\s+(department|team|admin|notice|update)\b/i,
  /\baccounts?\s+(payable|receivable)\b/i,
  /\baccounting\s+(department|team)?\b/i,
  /\bpayroll(\s+(department|team|notice))?\b/i,
  /\bbilling\s+(department|team|notice)\b/i,
  /\b(it|tech)\s+(support|help|department|team|admin|services?)\b/i,
  /\bhelp\s*desk\b/i,
  /\bcustomer\s+(service|support|care|relations)\b/i,
  /\b(security|infosec|cyber\s*security)\s+(team|department|alert|notice|update)\b/i,
  /\bsecurity\s+alert\b/i,
  /\boffice\s+of\s+the\s+(ceo|president|cfo|cio|director)/i,
  /\bsystem\s+admin(istrator)?\b/i,
  /\bmail\s+(admin|administrator|delivery|server|system)\b/i,
  /\bnotifications?\s+(team|center|service)\b/i,
  /\binternal\s+(communications?|memo|update)\b/i,
  /\bmanagement\s+(team|notice)\b/i,
  /\bemployee\s+(relations|benefits|services)\b/i,
  /\bbenefits\s+(team|admin|department)\b/i,
  /\bcareers?\b/i,
  /\brecruit(ing|ment|er)?\b/i,
  /\btalent\s+(team|acquisition|department)\b/i,
  /\bhiring\s+(team|manager|department)?\b/i,
  /\bhr\s+(?:and\s+)?recruit(ing|ment)?\b/i,
]

const EXECUTIVE_IMPERSONATION_PATTERNS: RegExp[] = [
  /\b(?:ceo|cfo|coo|cio|cto|chief\s+(?:executive|financial|operating|information|technology)\s+officer)\b/i,
  /\bpresident\b/i,
  /\b(?:senior\s+)?executive\b(?!\s+assistant)/i,
  /\bmanaging\s+partner\b/i,
  /\bfounding\s+partner\b/i,
  /\bgeneral\s+partner\b/i,
  /\bmanaging\s+director\b/i,
]

// Well-known brands frequently impersonated, with their known legitimate
// sender domains. If a display name matches the brand but the From: domain
// isn't on the legitimate list, that's a high-confidence phish signal.
//
// `legitimate` is a list of regexes the registrable domain must match.
// Keep these tight — false negatives (brand exists but isn't in our list
// and we miss the impersonation) are recoverable; false positives (real
// vendor domain we don't know about and we wrongly flag) erode trust.
interface BrandRule {
  brand: string
  display: RegExp
  legitimate: RegExp[]
}

const IMPERSONATED_BRANDS: BrandRule[] = [
  {
    brand: "Microsoft",
    display: /\bmicrosoft(\s+(account|365|office|teams|outlook|support))?\b/i,
    legitimate: [/(^|\.)microsoft\.com$/i, /(^|\.)office365\.com$/i, /(^|\.)onmicrosoft\.com$/i, /(^|\.)outlook\.com$/i, /(^|\.)microsoftonline\.com$/i],
  },
  {
    brand: "Apple",
    display: /\bapple(\s+(id|support|account))?\b/i,
    legitimate: [/(^|\.)apple\.com$/i, /(^|\.)icloud\.com$/i, /(^|\.)me\.com$/i],
  },
  {
    brand: "Google",
    display: /\bgoogle(\s+(workspace|drive|account|support))?\b/i,
    legitimate: [/(^|\.)google\.com$/i, /(^|\.)gmail\.com$/i, /(^|\.)googlemail\.com$/i, /(^|\.)youtube\.com$/i],
  },
  {
    brand: "Amazon",
    display: /\bamazon(\s+(prime|aws|web\s*services|customer\s*service))?\b/i,
    legitimate: [/(^|\.)amazon\.[a-z.]+$/i, /(^|\.)amazonses\.com$/i, /(^|\.)amazon\.aws$/i, /(^|\.)aws\.amazon\.com$/i],
  },
  {
    brand: "PayPal",
    display: /\bpaypal\b/i,
    legitimate: [/(^|\.)paypal\.com$/i, /(^|\.)paypal-(business|merchant|community)\.com$/i],
  },
  {
    brand: "Netflix",
    display: /\bnetflix\b/i,
    legitimate: [/(^|\.)netflix\.com$/i],
  },
  {
    brand: "Chase",
    display: /\bchase(\s+(bank|card))?\b/i,
    legitimate: [/(^|\.)chase\.com$/i, /(^|\.)jpmorganchase\.com$/i],
  },
  {
    brand: "Bank of America",
    display: /\bbank\s+of\s+america\b/i,
    legitimate: [/(^|\.)bankofamerica\.com$/i, /(^|\.)bofa\.com$/i],
  },
  {
    brand: "Wells Fargo",
    display: /\bwells\s+fargo\b/i,
    legitimate: [/(^|\.)wellsfargo\.com$/i],
  },
  {
    brand: "USPS",
    display: /\busps(\s+(delivery|notification))?\b/i,
    legitimate: [/(^|\.)usps\.com$/i, /(^|\.)usps\.gov$/i],
  },
  {
    brand: "FedEx",
    display: /\bfedex\b/i,
    legitimate: [/(^|\.)fedex\.com$/i],
  },
  {
    brand: "UPS",
    display: /\b(ups|united\s+parcel\s+service)\b/i,
    legitimate: [/(^|\.)ups\.com$/i],
  },
  {
    brand: "DHL",
    display: /\bdhl\b/i,
    legitimate: [/(^|\.)dhl\.[a-z]+$/i],
  },
  {
    brand: "ADP",
    display: /\b(adp(\s+payroll)?|automatic\s+data\s+processing)\b/i,
    legitimate: [/(^|\.)adp\.com$/i, /(^|\.)adpemail\.com$/i, /(^|\.)adpinfo\.com$/i],
  },
  {
    brand: "DocuSign",
    display: /\bdocu\s*sign\b/i,
    legitimate: [/(^|\.)docusign\.(com|net)$/i],
  },
  {
    brand: "Dropbox",
    display: /\bdropbox\b/i,
    legitimate: [/(^|\.)dropbox\.com$/i, /(^|\.)dropboxmail\.com$/i],
  },
  {
    brand: "Zoom",
    display: /\bzoom(\s+(meeting|video))?\b/i,
    legitimate: [/(^|\.)zoom\.us$/i, /(^|\.)zoom\.com$/i],
  },
  {
    brand: "Slack",
    display: /\bslack\b/i,
    legitimate: [/(^|\.)slack\.com$/i],
  },
  {
    brand: "LinkedIn",
    display: /\blinked\s*in\b/i,
    legitimate: [/(^|\.)linkedin\.com$/i, /(^|\.)e\.linkedin\.com$/i],
  },
  {
    brand: "Meta / Facebook / Instagram",
    display: /\b(meta|facebook|instagram)\b/i,
    legitimate: [/(^|\.)(facebook|instagram|meta)\.com$/i, /(^|\.)fb\.com$/i, /(^|\.)facebookmail\.com$/i],
  },
  {
    brand: "IRS",
    display: /\b(irs|internal\s+revenue\s+service)\b/i,
    legitimate: [/(^|\.)irs\.gov$/i],
  },
  {
    brand: "Venmo",
    display: /\bvenmo\b/i,
    legitimate: [/(^|\.)venmo\.com$/i],
  },
  {
    brand: "Zelle",
    display: /\bzelle\b/i,
    legitimate: [/(^|\.)zellepay\.com$/i, /(^|\.)zelle\.com$/i],
  },
  {
    brand: "Rocket Mortgage",
    display: /\brocket\s+mortgage\b/i,
    legitimate: [/(^|\.)rocketmortgage\.com$/i, /(^|\.)rocketcompanies\.com$/i],
  },
  {
    brand: "Brooks Running",
    display: /\bbrooks\s+running\b/i,
    legitimate: [/(^|\.)brooksrunning\.com$/i],
  },
  {
    brand: "Southern Company",
    display: /\bsouthern\s+company\b/i,
    legitimate: [/(^|\.)southerncompany\.com$/i],
  },
]

// Public webmail domains. By itself, not suspicious — billions of real
// people use these. Combined with role/brand impersonation, very strong.
const PUBLIC_WEBMAIL = new Set([
  "gmail.com",
  "googlemail.com",
  "outlook.com",
  "hotmail.com",
  "live.com",
  "msn.com",
  "icloud.com",
  "me.com",
  "mac.com",
  "yahoo.com",
  "ymail.com",
  "aol.com",
  "protonmail.com",
  "proton.me",
  "zoho.com",
  "gmx.com",
  "mail.com",
  "yandex.com",
  "tutanota.com",
  "fastmail.com",
])

const CONSUMER_MAILBOX_DOMAINS = new Set([
  ...PUBLIC_WEBMAIL,
  "telenet.be",
  "telefonica.net",
  "comcast.net",
  "att.net",
  "sbcglobal.net",
  "btinternet.com",
  "orange.fr",
  "gmx.de",
  "web.de",
  "libero.it",
  "wanadoo.fr",
  "verizon.net",
  "cox.net",
  "earthlink.net",
])

function hasTyposquatShape(domain: string | null): boolean {
  if (!domain) return false
  const label = domain.toLowerCase().split(".")[0] ?? ""
  if (!label) return false
  if (/^[0-9]/.test(label)) return true // starts with digit
  if (/[a-z]/.test(label) && /\d/.test(label)) return true // mixes letters + digits
  if (label.startsWith("xn--")) return true // punycode / IDN homograph
  if (label.length >= 25 && label.includes("-")) return true // very long hyphenated
  return false
}

function isPublicWebmail(domain: string | null): boolean {
  return Boolean(domain && PUBLIC_WEBMAIL.has(domain.toLowerCase()))
}

function isConsumerMailbox(domain: string | null): boolean {
  return Boolean(domain && CONSUMER_MAILBOX_DOMAINS.has(domain.toLowerCase()))
}

// Decide whether the visible "name" portion of the From: header is actually
// a meaningful display name (not just the email address echoed back).
function looksLikeDisplayName(name: string, email: string | null): boolean {
  if (!name) return false
  if (name === email) return false
  if (name.includes("@") && isEchoedEmailDisplayName(name, email)) return false
  if (name.toLowerCase() === "unknown") return false
  return true
}

function isEchoedEmailDisplayName(name: string, email: string | null): boolean {
  const displayAddress = normalizedPlainEmailAddress(name)
  return displayAddress !== "" && displayAddress === normalizedPlainEmailAddress(email)
}

function normalizedPlainEmailAddress(value: string | null): string {
  const source = value?.trim().toLowerCase() ?? ""
  const unquoted =
    source.length >= 2 && source.startsWith('"') && source.endsWith('"')
      ? source.slice(1, -1).trim()
      : source
  const at = unquoted.indexOf("@")
  if (at <= 0) return ""
  if (unquoted.slice(at + 1).includes("@")) return ""

  const local = unquoted.slice(0, at)
  const domain = unquoted.slice(at + 1)
  if (!local || !domain) return ""
  if (!allCharsAllowed(local, "abcdefghijklmnopqrstuvwxyz0123456789._%+-")) return ""
  if (!allCharsAllowed(domain, "abcdefghijklmnopqrstuvwxyz0123456789.-")) return ""

  const dot = domain.lastIndexOf(".")
  if (dot <= 0 || dot > domain.length - 3) return ""
  return unquoted
}

function allCharsAllowed(value: string, allowed: string): boolean {
  for (const char of value) {
    if (!allowed.includes(char)) return false
  }
  return true
}

function emailLocalPart(email: string | null): string {
  return email?.split("@")[0]?.toLowerCase().replace(/[^a-z0-9]/g, "") ?? ""
}

function personNameMailboxMismatch(displayName: string, email: string | null, domain: string | null): boolean {
  if (!isConsumerMailbox(domain)) return false
  const nameTokens = displayName
    .toLowerCase()
    .split(/[^a-z]+/)
    .filter((token) => token.length >= 3)
  if (nameTokens.length < 2 || nameTokens.length > 4) return false

  const local = emailLocalPart(email)
  if (!local) return false
  return !nameTokens.some((token) => local.includes(token))
}

export interface SenderTrustSignals {
  /** Display name claims a generic role/department (HR, IT, etc.). */
  roleImpersonation: boolean
  /** Display name claims an executive role commonly used in BEC. */
  executiveImpersonation: boolean
  /** Display name claims a known brand and the From: domain isn't on that brand's known list. */
  brandImpersonation: { brand: string } | null
  /** Sending domain has a shape associated with throwaway / typosquat infrastructure. */
  domainHasTyposquatShape: boolean
  /** From: domain is a public webmail provider (gmail, outlook, etc.). */
  fromPublicWebmail: boolean
  /** From: domain is a consumer mailbox/ISP provider. */
  fromConsumerMailbox: boolean
  /** Personal display name does not match the consumer mailbox local-part. */
  personNameMailboxMismatch: boolean
  /** A meaningful display name was extracted (not just the email echoed back). */
  hasDisplayName: boolean
}

export function evaluateSenderTrust(parser: ParserResult): SenderTrustSignals {
  const displayName = (parser.sendingName ?? "").trim()
  const fromDomain = (parser.sendingDomain ?? "").trim().toLowerCase()
  const fromEmail = parser.sendingEmail

  const hasDisplayName = looksLikeDisplayName(displayName, fromEmail)

  const executiveImpersonation =
    hasDisplayName && EXECUTIVE_IMPERSONATION_PATTERNS.some((p) => p.test(displayName))
  const roleImpersonation =
    hasDisplayName && (
      executiveImpersonation ||
      ROLE_IMPERSONATION_PATTERNS.some((p) => p.test(displayName))
    )
  const fromConsumerMailbox = isConsumerMailbox(parser.sendingDomain)

  let brandImpersonation: { brand: string } | null = null
  if (hasDisplayName) {
    for (const rule of IMPERSONATED_BRANDS) {
      if (rule.display.test(displayName)) {
        const matches = rule.legitimate.some((re) => re.test(fromDomain))
        if (!matches) {
          brandImpersonation = { brand: rule.brand }
          break
        }
      }
    }
  }

  return {
    roleImpersonation,
    executiveImpersonation,
    brandImpersonation,
    domainHasTyposquatShape: hasTyposquatShape(parser.sendingDomain),
    fromPublicWebmail: isPublicWebmail(parser.sendingDomain),
    fromConsumerMailbox,
    personNameMailboxMismatch: hasDisplayName
      ? personNameMailboxMismatch(displayName, fromEmail, parser.sendingDomain)
      : false,
    hasDisplayName,
  }
}
