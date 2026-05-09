# Message Loupe

A free, browser-based phishing checker. Drop a saved email (`.eml`) or paste raw headers, get a plain-English verdict — **Safe**, **Caution**, or **Likely Fake** — in under a second.

Live at [messageloupe.com](https://messageloupe.com).

## Privacy model

Everything runs in the browser. The site is a static export served from a CDN with no backend, no analytics, no cookies, no logs. Email content never leaves the device — there is no server to send it to.

Concrete consequences:

- No reputation lookups (VirusTotal, urlscan, abuse.ch, etc.). The benefit isn't worth leaking the user's mail.
- No content-meaning ML model. A model that classified message intent would have to phone home, breaking the privacy promise.
- No spam scoring. The product answers *"is this email pretending to be something it isn't?"* — not *"is this email welcome?"*

## What it actually checks

Roughly four categories, all derived from headers and body text:

1. **Authentication** — SPF, DKIM, DMARC results from the receiving server's `Authentication-Results`.
2. **Sender alignment** — visible `From:` vs. `Return-Path`, DKIM signing domain, and auth-results domain.
3. **Routing** — the `Received:` chain, walked backwards past known security gateways to the originating IP.
4. **Links** — anchor-text vs. href mismatch, raw-IP hosts, punycode lookalikes, `.cm` typosquats, known shorteners.

Verdict synthesis is a small set of explicit rules — not a score-and-threshold model. Read [src/app/methodology/page.tsx](src/app/methodology/page.tsx) or visit `/methodology` on the live site for the full rule set.

### Deliberate blind spot: the money/credential cap

Header analysis cannot detect a Business Email Compromise sent from a fully-compromised real account: every signal will pass, because the email *is* genuinely from that domain. To stay honest about that, any message mentioning money, banking changes, credentials, or document-request language is capped at **Caution — verify by phone**, regardless of how clean the technical signals look. See [src/lib/email/classify-content.ts](src/lib/email/classify-content.ts).

## Local development

```bash
sfw npm install
npm run dev
```

Then open <http://localhost:3000>.

The build is a fully static export (`output: 'export'` in [next.config.ts](next.config.ts)) — `npm run build` writes deployable HTML to `out/`.

## Tests

```bash
npm test
```

Regression fixtures live in [src/lib/email/__tests__/](src/lib/email/__tests__/). They cover the verdict-rule engine: SPF/DKIM/DMARC outcomes, alignment failures, link-flag combinations, the money/credential cap, the job-offer + document-request pair, the forwarded-message guard, and known-good ESP-routed mail.

The fixtures are synthetic (constructed RFC-822 strings exercising specific rules), not redacted real samples. They prove the engine still produces the documented verdict for each rule path.

## Stack

Next.js 16 (App Router, static export) · React 19 · TypeScript · Tailwind v4 · shadcn/ui · Lucide · Motion. Email parsing is a port of an internal triage tool kept in plain JS at [src/lib/email/parser.js](src/lib/email/parser.js); the orchestration around it (verdict, content classifier, sender trust, attachments) is TypeScript.

## Known limitations

- **Forwarded messages**: regular forwarding overwrites the headers we need. We detect forwards and refuse to verdict them rather than answer wrong. Save the original `.eml` or use "Show Original" instead.
- **`.eml` file size**: the file picker accepts up to 25 MB. Parsing happens in a Web Worker so the UI stays responsive on big files.
- **Outlook `.msg`**: not supported. Save as `.eml` first, or paste the raw headers from "View Source".

## Contributing a sample we get wrong

Email a saved `.eml` (never just the body — the headers are the evidence) to **hello@messageloupe.com**. Counterexamples become regression fixtures.
