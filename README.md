# Message Loupe

Message Loupe is a free, browser-based email analyzer focused on business email compromise (BEC), invoice fraud, and wire-transfer scams. Drop in an original email (`.eml`) or paste its raw headers to get a three-tier verdict: **No warning signs**, **Caution** ("Be careful"), or **Likely fake**.

It provides a second opinion on text-only payment requests, executive impersonation, changed bank details, fake invoices, and payroll diversion, while warning that a compromised legitimate account may still look authentic.

Use it at [messageloupe.com](https://messageloupe.com), or read the [BEC and wire-fraud guide](https://messageloupe.com/business-email-compromise/).

## Why it exists

SPF, DKIM, and DMARC provide evidence that a message was authorized by and aligned with a domain. They cannot prove that the person controlling the mailbox is honest. A criminal using a compromised real account may send a fully authenticated payment request.

Message Loupe combines technical evidence with explicit content rules, then explains both what the evidence shows and what it cannot prove. Messages involving money, credentials, payroll, documents, or account changes are never treated as safe solely because authentication passes.

## What it checks

- **Authentication:** trusted recipient-side SPF, DKIM, and DMARC results.
- **Sender identity:** alignment among `From`, `Return-Path`, Reply-To, DKIM, and authenticated domains.
- **Delivery path:** `Received` headers, originating IP, mail providers, and known security gateways.
- **Domain context:** optional MX-provider and RDAP domain-age checks.
- **Links:** misleading visible destinations, raw-IP hosts, punycode, typo domains, unrelated hosts, and shorteners.
- **Attachments:** dangerous file types, double extensions, and risky attachment/content combinations.
- **BEC language:** wire, ACH, remittance, invoice, payroll, bank-change, executive-request, credential, and document lures.
- **Impersonation patterns:** lookalike domains, public-webmail role impersonation, body/signature brand claims, fake reply threads, and mismatched reply addresses.
- **Evasion clues:** image-only messages, opaque encrypted bodies, duplicate critical headers, and sender-supplied authentication claims.

Verdicts come from a reviewable set of explicit rules, not an opaque score or remote AI model. The full behavior is documented in the [methodology](https://messageloupe.com/methodology/) and implemented in [src/lib/email/verdict.ts](src/lib/email/verdict.ts).

## Privacy model

Email parsing and verdict logic run in the browser. Message Loupe has no account requirement, backend email processing, analytics, cookies, or application database. The email, headers, links, attachments, and verdict are not uploaded.

For non-webmail senders, the browser may make two domain-only requests:

- Google Public DNS to identify the sender domain's MX provider.
- A same-site Cloudflare endpoint that asks public RDAP services when the sender domain was registered.

Those lookups contain only the visible sender domain. Message Loupe does not send message content to reputation services, URL scanners, or hosted classification models.

## Important limitation

Message Loupe can find evidence of spoofing, impersonation, suspicious infrastructure, and known scam patterns. It cannot prove that a request is legitimate.

A compromised real mailbox can produce clean authentication and normal routing. Always verify payment, payroll, credential, and bank-detail changes through a phone number or contact method you already trusted before the email arrived.

## Supported input

- Original `.eml` files up to 25 MB
- Raw email source or full headers pasted as text
- Plain-text exports containing RFC 822 headers
- `.mbox` input when it contains a single message

Outlook `.msg`, `.pst`, and `.ost` files are not supported. Use Outlook's Internet headers view or save/export the original message as `.eml`. Regular forwarding is also unsuitable because it replaces the headers needed for analysis.

See [How to save an email](https://messageloupe.com/how-to-save-an-email/) for Gmail, Outlook, Apple Mail, and mobile instructions.

## Product direction

The public scanner is the foundation for a small-business email-fraud product. Planned surfaces include Gmail and Outlook add-ins, a shared suspicious-email review path, and a lightweight team history that stores verdict metadata rather than email contents.

The initial audience is people who regularly approve payments or handle sensitive requests without a dedicated security team: bookkeepers, agencies, realtors, law offices, family offices, executive assistants, and small finance teams.

## Local development

Requirements: a current Node.js LTS release and npm.

```bash
npm ci
npm run dev
```

Open <http://localhost:3000>. The project uses a Next.js static export; `npm run build` writes the deployable site to `out/`. Cloudflare Pages serves the static site and the domain-only RDAP function in [functions/api/rdap.js](functions/api/rdap.js).

Cloudflare-hosted builds relay domain-age lookups through the same-site function. Node tools and local development without the production CSP cache the IANA bootstrap and query authoritative public RDAP registries directly, still sending only the registrable sender domain. Other static deployments should provide a compatible same-origin `/api/rdap` endpoint; a restrictive host CSP may block the direct fallback.

## Verification

```bash
npm run lint
npm test
npm run build
```

The committed suite uses synthetic fixtures and selected representative regression messages. The full known-fake corpus remains private and is checked by a separate local runner:

```bash
npm run eval:private
```

The private gate fails if a known-fake message returns the internal `safe` tier, if a message cannot be analyzed, or if a configured corpus is empty.

## Stack

Next.js 16, React 19, TypeScript, Tailwind CSS v4, shadcn/ui, Lucide, Motion, and Vitest. The site is exported as static files and hosted on Cloudflare.

## Contributing a missed sample

Before sending an original `.eml` to **hello@messageloupe.com**, remove confidential, personal, or regulated information. Repository cases should be synthetic, sanitized, or explicitly approved for publication.
