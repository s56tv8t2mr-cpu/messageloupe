// Synthetic RFC-822 fixture builder.
//
// Each helper returns a string that the parser accepts as a real .eml input.
// Fixtures intentionally hold only the headers and body text needed to
// exercise a specific verdict-rule path — they aren't redacted real samples,
// they're constructed inputs for a constructed engine.
//
// The minimum needed to avoid the "from-self" forward-detection heuristic is
// either two Received hops OR a parseable source IP — most fixtures here use
// both, mirroring what real mail looks like.

interface BuildOpts {
  from?: string
  to?: string
  subject?: string
  returnPath?: string
  replyTo?: string
  listId?: string
  authResults?: string
  receivedSpf?: string
  received?: string[]
  dkimSignature?: string
  body?: string
  /** When provided, the body is wrapped in multipart/alternative with this as the text/html part. */
  htmlBody?: string
  /** When provided, emits a Content-Class header (used by Outlook RMS detection). */
  contentClass?: string
  extraHeaders?: Record<string, string>
}

const DEFAULT_RECEIVED = [
  "from mx.example.com (mx.example.com [203.0.113.10]) by recv.example.org with ESMTPS; Mon, 01 Jan 2024 12:00:00 -0500",
  "from sender.example.com (sender.example.com [203.0.113.45]) by mx.example.com with ESMTPS; Mon, 01 Jan 2024 11:59:55 -0500",
]

// Counter-based deterministic Message-IDs. Sonar S2245 flags Math.random
// even in test code; a counter is both deterministic (good for snapshots)
// and silences the rule.
let messageIdCounter = 0

// Compose an Authentication-Results header. Default values mirror a
// legitimate aligned message; pass overrides to exercise specific failure
// paths without rewriting the whole string in every test.
export function authResults(opts: {
  domain: string
  spf?: string
  dkim?: string
  dmarc?: string
  mailfrom?: string
  headerFrom?: string
  authservId?: string
}): string {
  const {
    domain,
    spf = "pass",
    dkim = "pass",
    dmarc = "pass",
    mailfrom = domain,
    headerFrom = domain,
    authservId = "mx.example.org",
  } = opts
  return `${authservId}; spf=${spf} smtp.mailfrom=${mailfrom}; dkim=${dkim} header.i=@${domain}; dmarc=${dmarc} header.from=${headerFrom}`
}

export function buildEml(opts: BuildOpts = {}): string {
  const {
    from = "Test Sender <sender@example.com>",
    to = "recipient@example.org",
    subject = "Test message",
    returnPath,
    replyTo,
    listId,
    authResults,
    receivedSpf,
    received = DEFAULT_RECEIVED,
    dkimSignature,
    body = "Hello, this is a test message body.",
    htmlBody,
    contentClass,
    extraHeaders = {},
  } = opts

  const lines: string[] = []
  for (const r of received) lines.push(`Received: ${r}`)
  if (authResults) lines.push(`Authentication-Results: ${authResults}`)
  if (receivedSpf) lines.push(`Received-SPF: ${receivedSpf}`)
  if (returnPath !== undefined) lines.push(`Return-Path: <${returnPath}>`)
  if (replyTo) lines.push(`Reply-To: ${replyTo}`)
  if (listId) lines.push(`List-Id: ${listId}`)
  if (contentClass) lines.push(`Content-Class: ${contentClass}`)
  if (dkimSignature) lines.push(`DKIM-Signature: ${dkimSignature}`)
  for (const [name, value] of Object.entries(extraHeaders)) lines.push(`${name}: ${value}`)
  lines.push(`From: ${from}`)
  lines.push(`To: ${to}`)
  lines.push(`Subject: ${subject}`)
  lines.push(`Message-ID: <fixture-${++messageIdCounter}@example.com>`)
  lines.push(`Date: Mon, 01 Jan 2024 12:00:00 -0500`)

  if (htmlBody) {
    const boundary = "---ml-fixture-boundary---"
    lines.push(`MIME-Version: 1.0`)
    lines.push(`Content-Type: multipart/alternative; boundary="${boundary}"`)
    lines.push("")
    lines.push(`--${boundary}`)
    lines.push(`Content-Type: text/plain; charset=UTF-8`)
    lines.push("")
    lines.push(body)
    lines.push(`--${boundary}`)
    lines.push(`Content-Type: text/html; charset=UTF-8`)
    lines.push("")
    lines.push(htmlBody)
    lines.push(`--${boundary}--`)
  } else {
    lines.push("")
    lines.push(body)
  }
  return lines.join("\r\n")
}

// Common shorthand: a fully clean ESP-routed message that should land on
// "safe" with no caution reasons. Sendgrid is in providers.js's known list.
export function cleanEsp(overrides: BuildOpts = {}): string {
  return buildEml({
    from: "Acme Newsletter <hello@news.acme.com>",
    returnPath: "bounces+abc@sendgrid.net",
    received: [
      "from mx.recipient.org (mx.recipient.org [203.0.113.10]) by inbox.recipient.org with ESMTPS; Mon, 01 Jan 2024 12:00:00 -0500",
      "from o1.email.acme.com (o1.email.acme.com [167.89.10.20]) by mx.recipient.org with ESMTPS; Mon, 01 Jan 2024 11:59:55 -0500",
    ],
    authResults:
      "mx.recipient.org; spf=pass smtp.mailfrom=sendgrid.net; dkim=pass header.i=@news.acme.com; dmarc=pass header.from=news.acme.com",
    receivedSpf: "Pass (mx.recipient.org: domain of bounces+abc@sendgrid.net designates 167.89.10.20 as permitted sender) client-ip=167.89.10.20",
    dkimSignature: "v=1; a=rsa-sha256; d=news.acme.com; s=s1; h=From:To:Subject; b=sig",
    ...overrides,
  })
}
