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
  }
}

// The cap rule: any of these categories forces the verdict to never rise
// above "Caution — verify by phone." Money and credentials are the
// classic cap; document requests inherit the same logic (asking a stranger
// for their passport scan is high-stakes regardless of the apparent sender).
export function shouldCapVerdict(c: ContentClassification): boolean {
  return c.hasMoney || c.hasCredentials || c.hasDocumentRequest
}
