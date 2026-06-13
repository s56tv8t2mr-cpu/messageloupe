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
  /\bbanking\s+(?:details|information|info)\b/i,
  /\bchange(?:\s+of|\s+in)?\s+(?:bank|payment|banking)\b/i,
  /\bgift\s+cards?\b/i,
  /\bvanilla\s+(?:gift|prepaid)\b/i,
  /\b(?:bitcoin|btc|crypto(?:currency)?|ethereum|usdt|wallet\s+address)\b/i,
  /\binvoice\b/i,
  /\bbalance\s+due\b/i,
  /\bpast\s+due\b/i,
  /\bpayment\s+(?:due|required|overdue|info|details)\b/i,
  /\bdirect\s+deposit\b/i,
  /\bpayroll\s+(?:change|update|processed)\b/i,
  /\b(?:update|change)\s+(?:to\s+)?(?:my\s+|your\s+)?banking\s+information\b/i,
  /\b(?:remit|remittance)\b/i,
  /\baging\s+report\b/i,
  /\bar\s+report\b/i,
  /\baccounts?\s+receivable\b/i,
  /\bamounts?\s+due\b/i,
  /\bpayable\s+contact\s+emails?\b/i,
  /\bloan\s+(?:payments?|modification|payoff|ending)\b/i,
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
  /\bwithin\s+(?:five|5|seven|7|three|3|ten|10)\s+(?:working|business)?\s*days?\b/i,
  /\bwithin\s+the\s+next\s+\d+\s+(?:hours?|minutes?|days?)/i,
  /\b(?:account|access|mailbox|membership)\s+(?:has\s+been\s+|will\s+be\s+)?(?:locked|suspended|terminated|closed|disabled|deactivated)/i,
  /\bact\s+now\b/i,
  /\bact\s+today\b/i,
  /\bexpires?\s+(?:today|tomorrow|in\s+\d+|soon)/i,
  /\b(?:final|last)\s+(?:notice|warning|chance|reminder)/i,
  /\btoday\s+only\b/i,
  /\bdo\s+not\s+(?:delay|ignore)/i,
  /\btime[\s-]?sensitive\b/i,
]

// Job-offer / hiring scams — a distinct family from money/credential phish.
// The threat model: an attacker offers a fake remote job, then weaponizes
// the "onboarding" process to harvest personal documents (passport, ID,
// bank info) or as a stepping-stone to mule recruitment / advance-fee
// schemes. Patterns lifted from real samples.
const JOB_OFFER_PATTERNS: RegExp[] = [
  /\boffer\s+letter\b/i,
  /\bjob\s+offer\b/i,
  /\bofficial\s+(acceptance|offer|appointment)/i,
  /\bappointment\s+letter\b/i,
  /\bwelcome\s+to\s+(the\s+team|our\s+(team|company|family))/i,
  /\bjoin(ing)?\s+(our|the)\s+(team|company|organization)/i,
  /\bselection\s+(stage|stages|process|panel|committee)/i,
  /\b(pre[\s-]?screening|pre[\s-]?interview)\b/i,
  /\bats\s+(screening|review|filter)/i,
  /\b(online|virtual|video|zoom|skype)\s+interview\b/i,
  /\binterview\s+sched(?:u(?:e)?led|ule|uling)\b/i,
  /\bsched(?:u(?:e)?led|uling)\s+(?:your\s+|an?\s+)?interview\b/i,
  /\binterview\s+invitation\b/i,
  /\binvitation\s+to\s+(?:an?\s+)?interview/i,
  /\b(?:your|an?)\s+interview\s+(?:has\s+been\s+|is\s+)?(scheduled|confirmed|set|arranged)\b/i,
  /\binterview\s+(date|time|details|invite|panel|round)\b/i,
  /\b(?:we'?ve|we\s+have)\s+(?:shortlisted|selected)\s+you\b/i,
  /\bhq\s+(application|review|approval|interview)/i,
  /\binduction\s+(meeting|session|programme|program)/i,
  /\bonboarding\s+(details|kit|process|programme|program|materials)/i,
  /\bemployee\s+(badge|id|number|file)\b/i,
  /\bemployment\s+(agreement|contract|offer)/i,
  /\bofficial\s+contract\b/i,
  /\b(your\s+)?application\s+(has\s+been\s+)?(successful|approved|accepted)/i,
  /\bwe\s+are\s+pleased\s+to\s+(offer|confirm|inform)/i,
  /\bsuccessfully\s+completed\s+(?:all\s+)?(?:our|the)\s+(selection|interview|hiring)/i,
  /\bcustomer\s+service\s+(advisor|representative|agent)\s+(role|position|job)?/i,
  /\bremote\s+(?:position|role|job|opportunity)\b/i,
  /\bwork[\s-]?from[\s-]?home\s+(role|position|opportunity)/i,
  /\bpartnership\s+opportunit(?:y|ies)\b/i,
  /\bbrand\s+ambassador\s+program\b/i,
  /\bmodeling\s+role\b/i,
  /\bcontract\s+letter\s+of\s+agreement\b/i,
  /\bletter\s+of\s+agreement\b/i,
  /\brate\s+per\s+post\b/i,
  /\bgifted\s+products?\b/i,
  /\bcommission\s+on\s+sales\b/i,
]

// Document / PII requests — combined with offer/onboarding language, a
// strong scam signal. Real businesses use secure portals (DocuSign, Lever,
// BambooHR) for this; they do not ask candidates to email scans of their
// passport.
const DOCUMENT_REQUEST_PATTERNS: RegExp[] = [
  /\bpassport(\s+(copy|scan|number|details|page|valid|validity|size))?\b/i,
  /\b(?:visa|immigration)\s+(status|stamp|copy|details|valid)/i,
  /\b(driver'?s?|driving)\s+licen[sc]e/i,
  /\bnational\s+(id|identification|identity\s+card)/i,
  /\bemirates\s+id\b/i,
  /\bsocial\s+security\s+(number|card|details)/i,
  /\b(degree|academic|graduation)\s+(certificate|transcript|diploma)/i,
  /\b(?:high\s+school|university|college)\s+(transcript|diploma|certificate)/i,
  /\b(ccxp|cipd|pmp|prince2|cisa|cissp)\s+certificate/i,
  /\bbirth\s+certificate\b/i,
  /\bproof\s+of\s+(address|residence|identity|employment|income)/i,
  /\bbank\s+(statement|details|info|copy)/i,
  /\bcopy\s+of\s+(your\s+)?(id|passport|licen[sc]e|visa)/i,
  /\bphoto[\s-]?copy\s+of\s+(your\s+)?(passport|id|licen[sc]e)/i,
  /\bpassport[\s-]?size\s+(photo|photograph|picture)/i,
  /\bsend\s+(?:us\s+)?(?:a\s+)?(?:scan|photo|copy)\s+of\s+your\s+/i,
  /\bemail\s+(?:us\s+)?(?:a\s+)?(?:scan|photo|copy)\s+of\s+your\s+/i,
  /\bfill,\s*sign\s+and\s+send\s+back\b/i,
  /\bsign\s+and\s+send\s+back\b/i,
]

// Early-stage BEC often avoids links, attachments, and money words. It tries
// to start a private thread before asking for wire, payroll, gift-card, or
// data movement. These phrases are deliberately narrow because "can we talk?"
// alone would be too broad.
const BEC_OPENER_PATTERNS: RegExp[] = [
  /\bdo\s+you\s+have\s+a\s+minute\s+for\s+a\s+quick\s+(chat|call)\b/i,
  /\bwhen\s+is\s+a\s+good\s+time\s+to\s+reach\s+you\s+for\s+a\s+quick\s+call\b/i,
  /\bwhat\s+is\s+your\s+schedule\s+like\s+this\s+morning\b/i,
  /\bare\s+you\s+currently\s+in\s+the\s+office\b/i,
  /\bwe\s+would\s+like\s+you\s+to\s+look\s+into\s+a\s+small\s+situation\b/i,
  /\ba\s+situation\s+was\s+raised\b/i,
  /\bkindly\s+write\s+back\s+and\s+let\s+me\s+know\b/i,
]

const BANKING_CHANGE_VERBS = ["update", "change", "revise", "switch"]

const BANKING_CHANGE_TARGETS = buildPhrasePairs(
  ["banking", "bank", "payment", "payroll", "direct deposit"],
  ["information", "info", "details", "instructions", "account"],
)

const NEW_BANKING_TARGETS = [
  ...BANKING_CHANGE_TARGETS,
  ...buildPhrasePairs(["wire", "ach"], ["information", "info", "details", "instructions", "account"]),
]

const PAYROLL_CHANGE_PHRASES = buildPhrasePairs(
  ["payroll", "direct deposit"],
  ["change", "update", "revision"],
)

const BANKING_CHANGE_CONNECTORS = ["", "to", "to my", "to your", "to our", "my", "your", "our"]

const BANKING_CHANGE_REQUEST_PHRASES = BANKING_CHANGE_VERBS.flatMap((verb) =>
  BANKING_CHANGE_CONNECTORS.flatMap((connector) =>
    BANKING_CHANGE_TARGETS.map((target) => joinPhraseParts(verb, connector, target)),
  ),
)

const NEW_BANKING_REQUEST_PHRASES = ["new", "updated"].flatMap((prefix) =>
  NEW_BANKING_TARGETS.map((target) => `${prefix} ${target}`),
)

const POLARIS_SIGNATURE_SIGNOFFS = new Set(["regards", "sincerely", "best regards", "team"])

interface BodyBrandRule {
  brand: string
  legitimateDomains: string[]
  claim: (normalizedText: string, lineText: string) => boolean
}

const BODY_BRAND_RULES: BodyBrandRule[] = [
  {
    brand: "Brooks Running",
    legitimateDomains: ["brooksrunning.com"],
    claim: (text) =>
      hasAnyPhrase(text, [
        "working with brooks running",
        "on behalf of brooks running",
        "representing brooks running",
      ]) ||
      hasPhraseNear(text, "brooks running", "brand ambassador", 120),
  },
  {
    brand: "Polaris Partners",
    legitimateDomains: ["polarispartners.com"],
    claim: (_normalizedText, lineText) => hasPolarisSignatureClaim(lineText),
  },
  {
    brand: "Rocket Mortgage",
    legitimateDomains: ["rocketmortgage.com", "rocketcompanies.com"],
    claim: (text) =>
      hasAnyPhrase(text, [
        "from rocket mortgage",
        "on behalf of rocket mortgage",
        "for rocket mortgage",
      ]) ||
      ["document", "portal", "loan", "closing"].some((term) =>
        hasPhraseNear(text, "rocket mortgage", term, 120),
      ),
  },
  {
    brand: "Southern Company",
    legitimateDomains: ["southerncompany.com"],
    claim: (text) =>
      hasAnyPhrase(text, [
        "from southern company",
        "on behalf of southern company",
        "representing southern company",
      ]) ||
      ["modeling", "role", "partnership", "program"].some((term) =>
        hasPhraseNear(text, "southern company", term, 120),
      ),
  },
]

// Fake secure-message and document-portal lures frequently authenticate for
// a real but unrelated domain, then push the victim to a third-party app.
// The verdict engine only escalates this when a third-party link is present.
const SECURE_DOCUMENT_LURE_PATTERNS: RegExp[] = [
  /\bnew\s+document\(s\)\s+(?:cd\s+)?posted\s+to\s+the\s+portal\b/i,
  /\bdocuments?\s+posted\s+to\s+the\s+portal\b/i,
  /\bclosing\s+disclosure\s+package\b/i,
  /\bwiring\s+instructions\b/i,
  /\bview\s+(?:closing\s+)?document\(s\)\b/i,
  /\bview\s+message\b/i,
  /\bopen\s+message\b/i,
  /\bsecure\s+message\b/i,
  /\bpowered\s+by\s+zixcorp\b/i,
]

const matchAny = (text: string, patterns: RegExp[]): boolean =>
  patterns.some((p) => p.test(text))

const normalizePhraseText = (text: string): string =>
  text.toLowerCase().replace(/\s+/g, " ")

function buildPhrasePairs(prefixes: string[], suffixes: string[]): string[] {
  return prefixes.flatMap((prefix) =>
    suffixes.map((suffix) => joinPhraseParts(prefix, suffix)),
  )
}

function joinPhraseParts(...parts: string[]): string {
  return parts.filter(Boolean).join(" ")
}

function hasAnyPhrase(text: string, phrases: string[]): boolean {
  return phrases.some((phrase) => hasPhrase(text, phrase))
}

function hasPhraseNear(
  text: string,
  firstPhrase: string,
  secondPhrase: string,
  windowSize: number,
): boolean {
  let index = findPhraseIndex(text, firstPhrase)
  while (index !== -1) {
    const window = text.slice(index, index + firstPhrase.length + windowSize)
    if (hasPhrase(window, secondPhrase)) return true
    index = findPhraseIndex(text, firstPhrase, index + firstPhrase.length)
  }
  return false
}

function hasPhrase(text: string, phrase: string): boolean {
  return findPhraseIndex(text, phrase) !== -1
}

function findPhraseIndex(text: string, phrase: string, fromIndex = 0): number {
  let index = text.indexOf(phrase, fromIndex)
  while (index !== -1) {
    if (isPhraseBoundary(text, index, phrase.length)) return index
    index = text.indexOf(phrase, index + phrase.length)
  }
  return -1
}

function isPhraseBoundary(text: string, start: number, length: number): boolean {
  return !isWordChar(text[start - 1]) && !isWordChar(text[start + length])
}

function isWordChar(value: string | undefined): boolean {
  return value !== undefined && /[a-z0-9_]/.test(value)
}

function hasPolarisSignatureClaim(text: string): boolean {
  const lines = text
    .split("\n")
    .map((line) => line.trim().replace(/,$/, ""))
    .filter(Boolean)

  return lines.some((line, index) =>
    POLARIS_SIGNATURE_SIGNOFFS.has(line) &&
    lines[index + 1]?.startsWith("polaris partners") === true,
  )
}

const SECURITY_SUBSCRIPTION_BRANDS =
  /\b(mc\s*afee|mcafee|norton|lifelock|geek\s+squad|total\s+secure|total\s+security|antivirus|anti-virus)\b/i

const INVOICE_PAYMENT_REQUEST_PATTERNS: RegExp[] = [
  /\brequest\s+for\s+payment\b/i,
  /\bpayment\s+request\b/i,
  /\bpayment\s+(?:required|due|needed|overdue)\b/i,
  /\bplease\s+(?:process|send|make)\s+(?:the\s+)?payment\b/i,
  /\bpay\s+this\s+invoice\b/i,
]

const COERCIVE_PAYMENT_THREAT_PATTERNS: RegExp[] = [
  /\bfinal\s+notice\b/i,
  /\blegal\s+action\b/i,
  /\blawsuit\b/i,
  /\bexpos(?:e|ure)\b/i,
  /\bpublic\s+disclosure\b/i,
  /\brelease\s+(?:of\s+)?(?:facts|information|records)\b/i,
  /\bdamaging\s+(?:facts|information)\b/i,
  /\breputational\s+harm\b/i,
]

const SUPPORT_CONTACT_PATTERN =
  /\b(?:support|client\s+service|contact|helpline|customer\s+care|billing)\b/gi

const PHONE_NUMBER_PATTERN =
  /\b(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/i

function hasSupportPhoneProximity(text: string): boolean {
  SUPPORT_CONTACT_PATTERN.lastIndex = 0
  let match = SUPPORT_CONTACT_PATTERN.exec(text)
  while (match) {
    const termEnd = match.index + match[0].length
    const window = text.slice(termEnd, termEnd + 50)
    if (PHONE_NUMBER_PATTERN.test(window)) return true
    match = SUPPORT_CONTACT_PATTERN.exec(text)
  }
  return false
}

function hasInvoicePaymentRequest(text: string): boolean {
  const invoice = /\b(?:invoice|bill|statement|balance\s+due|amount\s+due)\b/i.test(text)
  return invoice && matchAny(text, INVOICE_PAYMENT_REQUEST_PATTERNS)
}

function hasCoercivePaymentThreat(text: string): boolean {
  const paymentOrInvoice = /\b(?:invoice|payment|wire|routing|balance\s+due|amount\s+due)\b/i.test(text)
  return paymentOrInvoice && matchAny(text, COERCIVE_PAYMENT_THREAT_PATTERNS)
}

function hasFraudReportContext(text: string): boolean {
  return (
    /\b(?:re:\s*)?fraudulent\s+email\b/i.test(text) ||
    /\b(?:received|got|forwarding|reporting|reported|notifying|alerting)\b.{0,80}\b(?:fraudulent|fake|impersonat(?:e|ed|ing|ion))\b/i.test(text) ||
    /\b(?:fraudulent|fake|impersonat(?:e|ed|ing|ion))\b.{0,80}\b(?:email|message|sender|domain)\b/i.test(text)
  )
}

function hasBankNoticeLure(text: string): boolean {
  const bankNotice =
    /\bnotice\s+is\s+available\s+to\s+view\b/i.test(text) ||
    /\b(?:bank|client\s+service)\b.{0,60}\bnotice\b/i.test(text)
  const accountOrTransfer =
    /\b(?:new\s+account|account\s+(?:opening|opened|created)|ach|bank\s+account|wire|routing)\b/i.test(text)
  return bankNotice && accountOrTransfer
}

function hasBankingChangeRequest(text: string): boolean {
  const normalized = normalizePhraseText(text)
  return (
    hasAnyPhrase(normalized, BANKING_CHANGE_REQUEST_PHRASES) ||
    hasAnyPhrase(normalized, NEW_BANKING_REQUEST_PHRASES) ||
    hasAnyPhrase(normalized, PAYROLL_CHANGE_PHRASES)
  )
}

function bodyBrandClaim(text: string): ContentClassification["bodyBrandClaim"] {
  const normalized = normalizePhraseText(text)
  const lineText = text.toLowerCase()
  return BODY_BRAND_RULES.find((rule) => rule.claim(normalized, lineText)) ?? null
}

function hasRiskyWorkFromHomeJobLure(text: string): boolean {
  return /\bresume\s+approval\b/i.test(text) ||
    /\bwork[\s-]?from[\s-]?home\b/i.test(text) ||
    /\byour\s+(?:resume|application)\s+(?:has\s+been\s+)?(?:approved|accepted)\b/i.test(text)
}

function hasOpaqueEncryptedBody(text: string): boolean {
  return /-----BEGIN\s+PGP\s+MESSAGE-----/i.test(text) ||
    /\brpmsg\.message\b/i.test(text)
}

function hasTransactionNoticeLure(text: string): boolean {
  return (
    /\b(?:txn|transaction|invoice|order|receipt|statement|billing|charge|amount)\b/i.test(text) &&
    /\b(?:issued|updated|available|posted|ready|processed|placed|confirmed|breakdown|notice)\b/i.test(text)
  )
}

function hasWireTransferLure(text: string): boolean {
  const bankAccountContext =
    /\bbank\s+account\s+(?:number|details?|info|information|instructions?)\b/i.test(text) ||
    /\baccount\s+number\b.{0,60}\b(?:routing|wire|ach|beneficiar(?:y|ies)|bank)\b/i.test(text) ||
    /\b(?:routing|wire|ach|beneficiar(?:y|ies)|bank)\b.{0,60}\baccount\s+number\b/i.test(text)
  const wireAction =
    /\bwire(?:\s+(?:transfer|instructions?|details?|info|payment))?\b/i.test(text) ||
    /\bach\s+(?:transfer|payment|debit|form|instructions?)\b/i.test(text) ||
    /\brouting\s+number\b/i.test(text) ||
    /\b(?:swift|iban|bic)\b/i.test(text) ||
    /\bbeneficiar(?:y|ies)\b/i.test(text) ||
    bankAccountContext
  const paymentContext =
    /\b(?:invoice|payment|money|funds?|transfer|bank|account|clearing|beneficiary|payee|due|quote)\b/i.test(text)
  return wireAction && paymentContext
}

function hasSubscriptionRefundScam(text: string): boolean {
  const subscriptionOrOrder =
    /\b(?:subscription|membership|renewal|auto[\s-]?renewal|order\s*#?|order\s+(?:id|number)|item\s+purchased)\b/i.test(text)
  const chargeOrAmount =
    /\b(?:amount\s+charged|charged|charge\s+of|payment\s+mode|transaction\s+details|invoice|tax)\b/i.test(text)
    || /\$\s?\d/.test(text)
  const phoneSupport = hasSupportPhoneProximity(text)
  return (
    SECURITY_SUBSCRIPTION_BRANDS.test(text) &&
    subscriptionOrOrder &&
    chargeOrAmount &&
    phoneSupport
  )
}

export function classifyContent(text: string): ContentClassification {
  const target = text || ""
  return {
    hasMoney: matchAny(target, MONEY_PATTERNS),
    hasCredentials: matchAny(target, CREDENTIAL_PATTERNS),
    hasUrgency: matchAny(target, URGENCY_PATTERNS),
    hasJobOffer: matchAny(target, JOB_OFFER_PATTERNS),
    hasDocumentRequest: matchAny(target, DOCUMENT_REQUEST_PATTERNS),
    hasBecOpener: matchAny(target, BEC_OPENER_PATTERNS),
    hasSecureDocumentLure: matchAny(target, SECURE_DOCUMENT_LURE_PATTERNS),
    hasSubscriptionRefundScam: hasSubscriptionRefundScam(target),
    hasWireTransferLure: hasWireTransferLure(target),
    hasInvoicePaymentRequest: hasInvoicePaymentRequest(target),
    hasCoercivePaymentThreat: hasCoercivePaymentThreat(target),
    hasFraudReportContext: hasFraudReportContext(target),
    hasBankNoticeLure: hasBankNoticeLure(target),
    hasBankingChangeRequest: hasBankingChangeRequest(target),
    mentionsPolarisPartners: /\bpolaris\s+partners\b/i.test(target),
    bodyBrandClaim: bodyBrandClaim(target),
    hasRiskyWorkFromHomeJobLure: hasRiskyWorkFromHomeJobLure(target),
    hasOpaqueEncryptedBody: hasOpaqueEncryptedBody(target),
    hasTransactionNoticeLure: hasTransactionNoticeLure(target),
  }
}

// The cap rule: any of these categories forces the verdict to never rise
// above "Caution — verify by phone." Money and credentials are the
// classic cap; document requests inherit the same logic (asking a stranger
// for their passport scan is high-stakes regardless of the apparent sender).
export function shouldCapVerdict(c: ContentClassification): boolean {
  return c.hasMoney || c.hasCredentials || c.hasDocumentRequest
}
