# Message Loupe inbox add-ins — build brief

Instructions for a coding agent (Codex / Claude Opus) to build the Gmail (Google
Workspace) and Microsoft 365 (Outlook) add-ins promised at
https://messageloupe.com/business/#add-ins.

Three standardized scan modes (defined precisely in §1 and Q&A #1 — use
these exact terms everywhere):

1. **Scan on demand** — the user opens a message and asks for a verdict.
2. **Auto-scan on open** — every message the user opens/selects is scanned
   automatically (Gmail contextual card; Outlook pinned pane).
3. **Inbox autoscan** — messages are scanned as they arrive, before the user
   opens them, and visibly marked (Gmail G2 labels; Outlook M2 categories —
   M2 is spec-only).

Both platforms ship modes 1+2 in their first milestone; mode 3 is G2 (Gmail)
and M2 (Outlook, on go-ahead only).

This brief is self-contained. Work milestone-by-milestone; each milestone is an
independent branch + PR with its own verification gate (§10). Do not start a
milestone until the previous one is merged.

---

## 0. Context you must internalize first

- **Repo:** `s56tv8t2mr-cpu/messageloupe`, Next.js 16 static export, deployed
  on Cloudflare Pages at messageloupe.com. Read `AGENTS.md`: this Next.js
  version differs from training data — read `node_modules/next/dist/docs/`
  before touching site code.
- **The verdict engine** lives in `src/lib/email/`. Entry point:
  `analyze(source: string): Promise<Analysis>` in `src/lib/email/index.ts` —
  takes raw RFC-822 text (full .eml, headers+body, or headers-only), returns
  `{ parser, links, attachments, content, forward, trust, replyTo, mx, rdap, verdict }`.
  `verdict.tier` is `"safe" | "caution" | "danger" | "forwarded"`.
- **Core product promise: privacy.** Message content never leaves the user's
  mail environment. The only network calls are domain-name-only lookups
  (DoH MX via dns.google, RDAP domain age). The add-ins must preserve this.
  Any mode that cannot (M2 backend autoscan) is opt-in and disclosed.
- **Private corpora** (`Known Fake EMLs/`, `email-analysis-archive/`) are
  local-only and untracked. NEVER commit them or excerpts of them. Committed
  tests use synthetic fixtures only (`src/lib/email/__tests__/fixtures.ts`).
- **Existing gates:** `npm test`, `npm run lint`, `npm run build`,
  `npm run test:email-eval` (committed synthetic corpus gate). The repo owner
  additionally runs `npm run eval:private` locally; the standard is **zero
  "safe" verdicts on known fakes**. Your changes must not alter any committed
  corpus-eval verdict unless the change is the explicit point of the PR.
- **Tooling note for this machine:** prefix `npm install` and `npx` commands
  with `sfw` (owner's security wrapper), e.g. `sfw npx clasp push`.

---

## 1. Product requirements

Standardized mode names — use these exact terms in code, UI copy, and site
copy (see Q&A #1):

| Mode | Gmail | Outlook / M365 |
|---|---|---|
| **Scan on demand** | Contextual add-on card when a message is open | Ribbon button "Message Loupe" opens a task pane with the verdict |
| **Auto-scan on open** (no backend) | Same contextual card — it auto-renders on every message open, free | Pinned task pane (`SupportsPinning`) auto-rescans on every selection via `ItemChanged` |
| **Inbox autoscan** (arrival-time) | Time-driven Apps Script trigger polls the inbox and applies labels (G2) | Graph change-notification service — **spec only in M2, build only on explicit go-ahead** |

Verdict UI in every surface maps the tier exactly like the site's verdict card:

- `danger` → red, headline "Likely fake"
- `caution` → amber, "Be careful"
- `safe` → green, "No obvious warning signs"
- `forwarded` → neutral, "This looks like a forward" + instruction to open the
  original message instead

Always show the top reasons (`verdict.reasons[].detail`, high-weight first,
max ~4) and a link to https://messageloupe.com/ for the full-detail scanner.
Never transmit message content in that link — it's a plain link, no params.

---

## 2. Non-negotiables

1. Engine analysis runs **inside the user's mail runtime** (Apps Script
   executes in the user's Google account; Outlook task pane executes in the
   user's browser). No Message Loupe server sees message content in G1/G2/M1.
2. One engine, three runtimes. Do not fork detection logic per platform. All
   detection changes continue to happen in `src/lib/email/` and flow into the
   add-ins through the build (Milestone 0).
3. Minimal scopes. Gmail on-demand uses per-message scope
   (`gmail.addons.current.message.readonly`), never `gmail.readonly`. The
   restricted `gmail.modify` scope exists only in the G2 autoscan module.
4. The website keeps working identically. Milestone 0's refactor must be
   behavior-neutral for the site (worker, scanner, all tests).
5. Fail safe and honest: if the add-in cannot retrieve full headers, say
   "couldn't verify — use the website with the raw original" rather than
   rendering a verdict from partial data.

---

## 3. Repo layout (new)

```
addins/
  gmail/
    appsscript.json          # Apps Script manifest
    src/                     # handwritten .gs/.js (cards, triggers, adapters)
    dist/                    # bundled engine + copied src, pushed via clasp
    README.md                # setup: GCP project, clasp, test-deploy steps
  outlook/
    manifest.xml             # XML add-in manifest (classic + new Outlook + web + Mac)
    src/taskpane/            # HTML/TS for the pane
    src/commands/            # function-file stub
    README.md                # sideload + central-deployment steps
scripts/
  build-addins.mjs           # esbuild: engine bundles for both targets
docs/
  ADDIN_BUILD_BRIEF.md       # this file
```

No monorepo/workspaces tooling — plain esbuild scripts, matching the repo's
minimal-dependency style. Add `esbuild` and `@types/office-js` as
devDependencies; for Gmail also `@types/google-apps-script`.

---

## 4. Milestone 0 — make the engine portable (`codex/addin-engine-portability`)

The engine currently assumes browser globals. Exact dependencies:

| Global | Where | Notes |
|---|---|---|
| `atob` + `TextDecoder` | `src/lib/email/parser.js` (~line 298), `src/lib/email/encodedWords.js` (~lines 17–24) | base64 body + RFC 2047 decode |
| `fetch` | `src/lib/email/mx-lookup.ts` (~line 118) | DoH MX via dns.google |
| `fetch` | `src/lib/email/rdap-lookup.ts` (~lines 58, 85, 96) | IANA bootstrap, authoritative RDAP, and a **same-origin proxy `/api/rdap`** that only exists on messageloupe.com |
| Web Worker | `src/lib/email/analyze.worker.ts` | site-only; exclude from add-in bundles |

Work:

1. Create `src/lib/email/env.ts` — a tiny injectable environment:
   ```ts
   // Deliberately narrower than the DOM fetch type so a UrlFetchApp-backed
   // adapter satisfies it without faking a full Response. Engine call sites
   // may use ONLY ok/status/json()/text(), and must tolerate adapters that
   // ignore `signal` (UrlFetchApp cannot abort). Browser fetch is
   // structurally assignable as-is.
   interface EngineFetchResponse {
     ok: boolean
     status: number
     json(): Promise<unknown>
     text(): Promise<string>
   }
   type EngineFetch = (
     url: string,
     init?: {
       method?: string
       headers?: Record<string, string>
       body?: string
       signal?: AbortSignal
     },
   ) => Promise<EngineFetchResponse>

   interface EngineEnv {
     fetch: EngineFetch | null         // null = network lookups disabled
     base64Decode(s: string): string   // binary string out (atob semantics)
     utf8Decode(binary: string): string
     rdapProxyUrl: string | null       // null = go direct to authoritative RDAP only
   }
   export function setEngineEnv(partial: Partial<EngineEnv>): void
   export function getEngineEnv(): EngineEnv
   ```
   Defaults use the existing globals and `/api/rdap`, so the site needs zero
   call-site changes beyond importing through the env accessors.
2. Route every use listed in the table through `getEngineEnv()`. When
   `fetch` is null, `lookupMx`/`lookupRdapDomainAge` must resolve to their
   existing "unavailable" shapes (verdict already tolerates `mx: null` /
   `rdap: null` — grep `index.ts` for the public-webmail skip to confirm the
   shapes).
3. `scripts/build-addins.mjs` produces (entry-point wiring: Q&A #11):
   - Outlook: no intermediate engine artifact — the task pane TS imports
     `src/lib/email/entry.outlook.ts` directly and esbuild bundles pane +
     engine together into `public/outlook/` (Q&A #12).
   - `addins/gmail/dist/engine.js` — IIFE from `entry.gas.ts` exposing
     global `MessageLoupeEngine` with `{ analyze, setEngineEnv }`, target
     ES2019 (Apps Script V8: no `TextDecoder`, no `atob`, no `fetch` — the
     bundle must not reference them outside the env indirection).
4. Add an npm script `build:addins`.
5. Tests: a Node-based test that loads the IIFE bundle in a bare `vm` context
   (no browser globals), injects stub env, runs `analyze()` on a synthetic
   fixture, and asserts a verdict is produced. This proves Apps Script
   compatibility without Apps Script.

**Gate:** `npm test`, `npm run test:email-eval`, `npm run lint`,
`npm run build` all pass; committed corpus verdicts unchanged; site worker
still functions (`npm run dev`, scan a sample .eml manually).

---

## 5. Milestone G1 — Gmail add-on, on-demand / scan-on-open (`codex/gmail-addon`)

Google Workspace add-on built in Apps Script (V8), managed with `clasp`.

### Manifest (`addins/gmail/appsscript.json`)

```json
{
  "timeZone": "America/New_York",
  "runtimeVersion": "V8",
  "oauthScopes": [
    "https://www.googleapis.com/auth/gmail.addons.current.message.readonly",
    "https://www.googleapis.com/auth/gmail.addons.execute",
    "https://www.googleapis.com/auth/script.external_request"
  ],
  "addOns": {
    "common": {
      "name": "Message Loupe",
      "logoUrl": "https://messageloupe.com/addon-icon-128.png",
      "homepageTrigger": { "runFunction": "onHomepage" }
    },
    "gmail": {
      "contextualTriggers": [
        { "unconditional": {}, "onTriggerFunction": "onGmailMessageOpen" }
      ]
    }
  }
}
```

The unconditional contextual trigger means the verdict card renders
automatically every time the user opens a message — this satisfies both
"on demand" and "scan the message I'm looking at" in one surface.

### Flow (`onGmailMessageOpen`)

1. `GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken)`.
2. Fetch raw RFC-822:
   `GmailApp.getMessageById(e.gmail.messageId).getRawContent()`. Do **not**
   send `e.gmail.accessToken` as an `Authorization: Bearer` token to the
   Gmail REST API; it is the current-message token for `GmailApp`, not a
   general OAuth bearer. If a REST fallback is ever needed, use
   `ScriptApp.getOAuthToken()` as the bearer and pass the message token
   separately as `X-Goog-Gmail-Access-Token: ${e.gmail.accessToken}`. Do not
   add `gmail.readonly`.
3. Inject the Apps Script env once per execution:
   ```js
   MessageLoupeEngine.setEngineEnv({
     fetch: gasFetchAdapter,        // wraps UrlFetchApp.fetch → Response-like
     base64Decode: (s) => Utilities.newBlob(Utilities.base64Decode(s)).getDataAsString("ISO-8859-1"),
     utf8Decode: (bin) => /* bytes-of-binary-string → UTF-8 string via Utilities.newBlob */,
     rdapProxyUrl: null
   })
   ```
   `gasFetchAdapter` must implement `{ ok, status, json(), text() }` and honor
   a soft timeout (UrlFetchApp has no AbortSignal — ignore the signal arg,
   set `muteHttpExceptions: true`).
4. `const analysis = await MessageLoupeEngine.analyze(rawEml)` inside an
   async trigger function that returns the card. Because the only `await`
   boundaries are network lookups and the injected `UrlFetchApp` adapter is
   synchronous, the promise settles without real I/O parking. This is
   likely-working but unproven — implementation default, acceptance test,
   and pre-approved fallback are specified in **Q&A #2 (§11)**; follow that.
5. Build the card with `CardService`:
   - Header: tier color chip + headline (`Likely fake` / `Be careful` /
     `No obvious warning signs` / `This looks like a forward`).
   - Section "Why": top reasons (≤4), each as a `DecoratedText` with a
     severity icon.
   - Section "Details": SPF/DKIM/DMARC one-liner (`parser.authSummary`),
     sending service, source IP if present.
   - Footer: button linking to https://messageloupe.com/ ("Full report —
     paste the raw original there").
6. Errors → a card that says analysis failed and points to the website. Never
   a blank card.

### Notes

- Deployment for dev: `sfw npx clasp create/push`, then "Install add-on"
  (Deploy → Test deployments). Document in `addins/gmail/README.md`.
- A GCP project is required for Marketplace publishing later; dev testing
  works with the default Apps Script project. The repo owner will handle
  OAuth consent screen setup — document exactly what they must click.
- `gmail.addons.current.message.readonly` is a *sensitive* (not restricted)
  scope: standard verification, no CASA. Do not add any broader Gmail scope
  in this milestone.

**Gate:** Milestone 0 gates all still pass; the vm-bundle test extended with
the Apps Script adapter shims; manual checklist in README executed by the
owner (open 3 synthetic test emails sent to their own inbox: a clean one, one
with a Reply-To mismatch, one forwarded — expect green / red / forward card).

---

## 6. Milestone G2 — Gmail inbox autoscan (`codex/gmail-autoscan`)

Adds an opt-in autoscan module to the same Apps Script project. Everything
still runs inside the user's own Google account — privacy model unchanged.

- New scope: `https://www.googleapis.com/auth/gmail.modify` (**restricted** —
  see §9 before making the Marketplace listing public).
- Settings card (homepage): "Enable inbox autoscan" toggle →
  `ScriptApp.newTrigger("autoscanInbox").timeBased().everyMinutes(5).create()`;
  disable removes the trigger and offers to remove labels.
- `autoscanInbox()`:
  1. Search `in:inbox newer_than:2d -label:message-loupe-scanned`, cap 25
     messages/run (stay far inside quotas: 6 min/execution, UrlFetch daily
     caps).
  2. For each: fetch `format=raw` via the Gmail REST API with
     `ScriptApp.getOAuthToken()`, run the engine, then apply labels:
     - always: `Message Loupe/Scanned`
     - `danger` → `Message Loupe/Likely fake` (+ mark important: optional,
       default off)
     - `caution` → `Message Loupe/Be careful`
     - `forwarded`/`safe` → scanned label only
  3. Store per-run stats in `PropertiesService.getUserProperties()` (counts
     only — never message content) and show them on the homepage card.
- Idempotent, crash-tolerant: label first-thing after verdict; a re-run must
  not double-process (the `-label:` query guarantees it).
- Failure budget: if the engine throws on a message, label it
  `Message Loupe/Scan failed` and continue.

**Gate:** G1 gates; plus a dry-run mode (`autoscanInbox({ dryRun: true })`)
the owner can execute from the editor that logs verdicts without labeling;
owner runs it against their own inbox and spot-checks 10 results.

---

## 7. Milestone M1 — Outlook add-in, on-demand + pinned autoscan-on-open (`codex/outlook-addin`)

Static task-pane add-in. **Host it on messageloupe.com** (generated files under
`public/outlook/`, per Q12) so the engine can use the same-origin
`/api/rdap` Cloudflare Pages Function already used by the site. Cloudflare
Pages serves the static pane; no new infrastructure.

### Manifest (`addins/outlook/manifest.xml`)

Use the classic XML MailApp manifest (widest client coverage: Outlook on the
web, new Outlook for Windows, classic Windows, Mac). Key elements:

- `<Requirements><Sets><Set Name="Mailbox" MinVersion="1.8"/></Sets></Requirements>`
  (1.8 is required for `getAllInternetHeadersAsync`).
- `<Permissions>ReadItem</Permissions>` — nothing broader.
- VersionOverrides: `MessageReadCommandSurface` button "Scan with Message
  Loupe" opening the task pane, and on the task-pane control
  `<SupportsPinning>true</SupportsPinning>`.
- `AppDomains`: messageloupe.com.
- Icons: reuse site icon, provide 16/32/80 px PNGs under `public/outlook/`.

### Task pane flow

1. `Office.onReady` → if `!Office.context.requirements.isSetSupported("Mailbox", "1.8")`,
   render a fallback: "Your Outlook can't share full headers with add-ins —
   use messageloupe.com with the saved original."
2. Reconstruct a pseudo-EML from the Office.js item — this is the one
   genuinely fiddly piece; implement it as a pure, unit-tested function
   `buildPseudoEml(headers, textBody, htmlBody, attachments): string`:
   - `item.getAllInternetHeadersAsync()` → full original header block
     (Received chain, Authentication-Results, From, Reply-To, spam headers —
     everything the engine feeds on).
   - `item.body.getAsync(Office.CoercionType.Text)` and `(Office.CoercionType.Html)`.
   - `item.attachments` → metadata (name, contentType) only.
   - **Critical gotcha:** the original headers contain the original
     `Content-Type: multipart/...; boundary=...` — but you are not attaching
     the original MIME parts, so the parser would split on a boundary that
     never appears and read an empty body. The builder must:
     a. Remove original `Content-Type` and `Content-Transfer-Encoding`
        headers (only those two).
     b. Append its own `Content-Type: multipart/mixed; boundary="loupe-rebuild"`.
     c. Emit parts: `text/plain` (text body), `text/html` (html body), and
        for each attachment an empty-bodied part with
        `Content-Type: <contentType>; name="<filename>"` +
        `Content-Disposition: attachment; filename="<filename>"` so
        `extractAttachments` and the attachment-based verdict rules see them.
   - Preserve every other header byte-for-byte, `\r\n` line endings.
3. `import { analyze } from "@/lib/email/entry.outlook"` (bundled by
   `build:addins`; the entry pins `rdapProxyUrl` — Q&A #11). Browser fetch
   is picked up automatically. Run `analyze(pseudoEml)`.
4. Render the verdict banner (tier pill, headline, reasons, auth summary,
   link to the site). Match the site's tone; dark mode via
   `Office.context.officeTheme` with a sensible light default.
5. **Pinned autoscan-on-open:**
   `Office.context.mailbox.addHandlerAsync(Office.EventType.ItemChanged, rescan)` —
   when the pane is pinned, every message the user selects is scanned
   automatically. Handle `item == null` (no selection) by clearing the pane.
   Surface a hint in the UI: "Pin this pane to scan every message you open."
6. `forwarded` verdicts in this context deserve a tailored message: the user
   is looking at the *original* in their own inbox more often than on the
   website, so say "If this message itself arrived like this, the sender may
   be faking a forwarded thread" (the engine's website copy assumes the user
   uploaded a forward of their own — don't reuse it verbatim).

### CSP / hosting caveats

- Office.js loads from `https://appsforoffice.microsoft.com/lib/1/hosted/office.js`.
  The site ships a strict CSP via the Cloudflare `_headers` file — add a
  scoped rule for `/outlook/*` allowing that script origin. Keep
  `connect-src 'self' https://dns.google`; do not allow arbitrary public RDAP
  hosts from the pane.
- The pane runs same-origin with the site, so dns.google and `/api/rdap` work
  under that CSP. RDAP must go through the same-origin `/api/rdap` Pages
  Function; if that endpoint is unavailable in a local/static preview,
  domain-age checks should degrade to `rdap: null` rather than attempting
  direct public RDAP from the Outlook pane.

**Gate:** unit tests for `buildPseudoEml` (multipart original, plain
original, attachments, missing html body); all repo gates; sideload
checklist in `addins/outlook/README.md` executed on Outlook on the web + new
Outlook for Windows (client availability: see Q&A #8; document
`Add-ins → My add-ins → Add from file`); same 3-email manual matrix as G1, plus pin the pane and
arrow through 5 messages to verify ItemChanged rescans.

---

## 8. Milestone M2 — Outlook arrival-time autoscan (spec, build on go-ahead only)

There is no client-side path to scan on arrival in M365 (add-ins only run
with UI open; event-based activation is compose-side). Arrival-time autoscan
requires a service:

- Azure AD app (start single-tenant), delegated or application
  `Mail.ReadWrite`; Microsoft Graph **change notifications** subscription on
  `/me/mailFolders('Inbox')/messages` (`changeType: created`), webhook
  endpoint on a Cloudflare Worker; subscriptions expire (~3 days for
  messages) → scheduled renewal.
- On notification: `GET /messages/{id}/$value` (raw MIME) → run the engine
  (same bundle, Node/Worker env) → `PATCH` the message's `categories` with
  `Loupe: Likely fake` / `Loupe: Be careful`. Retain verdict metadata only —
  never store the MIME. This is the first mode where message content transits
  Message Loupe infrastructure: it must be opt-in, admin-consented, and
  disclosed in the privacy page before launch.
- Deliverable for this milestone as scoped **now**: a design doc
  `docs/outlook-autoscan-service.md` covering auth flow, subscription
  lifecycle, retention, failure handling, and cost — not code.

---

## 9. Distribution & compliance checklists

**Gmail / Workspace Marketplace**
- Dev/personal + same-domain installs need no review. Public listing needs:
  OAuth brand verification, sensitive-scope review (G1), and — once G2's
  `gmail.modify` is included — a **restricted-scope CASA Tier 2 assessment**
  (annual, third-party). Recommendation: publish G1 publicly; keep G2 as
  "advanced setup" (private/internal install) until demand justifies CASA.

**Outlook**
- Sideload + Microsoft 365 admin **central deployment** need no Microsoft
  review — that covers the pilot-customer motion on /business.
- AppSource later: requires manifest validation
  (`sfw npx office-addin-manifest validate addins/outlook/manifest.xml`),
  privacy policy + support URLs (exist on the site), and Microsoft's
  commercial marketplace review.

---

## 10. Verification protocol (every milestone)

1. `npm test` && `npm run test:email-eval` && `npm run lint` && `npm run build` — all green.
2. Committed corpus verdicts unchanged (corpus-eval is the tripwire).
3. The owner runs `npm run eval:private` locally — expected: 0 "safe", 0 errors.
4. Manual checklist in the milestone's README executed (sideload/test-deploy steps must be copy-paste runnable).
5. No private corpus material, tokens, or tenant IDs in the diff.
6. State results honestly in the PR body: what was run, what passed, what was not verified.

## 11. Q&A — decisions from pre-build review (2026-07-07)

These answers are binding; where they conflict with earlier sections, the Q&A
wins.

### Q1. Define "autoscan" per platform

**Decision: three standardized terms, used everywhere (code, UI, site copy):**

- **Scan on demand** — user explicitly asks for a verdict.
- **Auto-scan on open** — every message the user *opens/selects* is scanned
  automatically. Gmail G1's unconditional contextual card and Outlook M1's
  pinned pane both qualify. This is NOT "autoscan of the inbox" and product
  copy must never call it that.
- **Inbox autoscan** — arrival-time scanning of messages the user hasn't
  opened. Only G2 (Gmail polling) and M2 (Graph service) qualify.

So: Outlook M1 ships "scan on demand + auto-scan on open" and the /business
page may only claim inbox autoscan for Outlook once M2 exists. Gmail G1
counts as both on-demand *and* auto-scan on open; G2 is inbox autoscan.

### Q2. Gmail async feasibility (can the trigger await `analyze()`?)

**Default for Codex to implement: full lookups via the UrlFetchApp adapter,
async trigger function returning the card.** Rationale: Apps Script V8
supports async functions, and because `UrlFetchApp` is synchronous, every
`await` inside `analyze()` settles without real I/O parking. Treat it as
likely-working but unproven: G1's manual checklist MUST include an
acceptance test — a test message from a young/lookalike domain whose card
shows an MX- or RDAP-based reason.

**Pre-approved fallback (no need to re-ask):** if the card fails to render
or renders before resolution, ship G1 with `fetch: null` (MX/RDAP disabled),
add a card footer line "Domain-age and MX checks run on the website", and
file the async issue in the PR body. Do not block G1 on this.

### Q3. Privacy copy

**Domain-only lookups: yes, disclose.** Standard sentence for add-in listing
descriptions, add-in READMEs, and the site privacy page (add-ins section):

> "To evaluate the sender's domain, Message Loupe sends the domain name only
> — never message content — to public DNS (dns.google) and the public RDAP
> registry for that domain. When lookups are unavailable, the scan still
> runs; those two checks are simply skipped."

**M2 privacy-page draft (must be finalized and published before any M2 code
ships; include this draft in `docs/outlook-autoscan-service.md`):**

> "Inbox autoscan for Microsoft 365 is optional and off by default. When
> your organization's admin enables it, Microsoft sends each new message to
> Message Loupe's scanning service, which analyzes it in memory and writes a
> category (for example 'Loupe: Likely fake') back to your mailbox. We
> retain verdict metadata only: sender domain, authentication results,
> verdict tier, and reason codes. Message bodies, attachments, subjects, and
> full headers are never stored and are discarded immediately after
> analysis. Turning autoscan off stops all processing and deletes the
> service's stored metadata for your mailbox on request."

### Q4. Gmail autoscan scope (`gmail.modify` / CASA)

**G2 is excluded from the public Marketplace package entirely.** Two
deployments from one codebase: the public listing's manifest never requests
`gmail.modify`; the autoscan module ships only in a private/unlisted
deployment (personal install or Workspace domain-internal), documented as
"advanced setup" in the README. Revisit CASA only if a paying pilot demands
a public listing.

**Labels are fixed, not configurable, in v1:** `Message Loupe/Scanned`,
`Message Loupe/Likely fake`, `Message Loupe/Be careful`,
`Message Loupe/Scan failed`. Configurability is scope creep; add only if a
pilot customer asks.

### Q5. Outlook pseudo-EML confidence

**Yes — show a one-line provenance note** in the pane, non-alarming:
"Analyzed from Outlook's copy of this message (original headers; body
rebuilt from item data)." Expandable "About this scan" detail may explain
that header-based signals (authentication, routing, Reply-To) come from the
original headers verbatim, while body/attachment signals are reconstructed.

**Forwarded wording: UI-layer override only.** The engine stays
presentation-agnostic — do not add context flags or copy variants to
`src/lib/email/` for this. Each surface (site, Gmail card, Outlook pane)
maps `verdict.tier === "forwarded"` to its own copy.

### Q6. Engine portability defaults

**Auto-detect, fail closed.** `env.fetch` defaults to `globalThis.fetch` if
present, else `null` (lookups disabled). Consequences: the site and the
Outlook pane work with zero injection; Apps Script has no global `fetch`, so
the Gmail bundle is fail-closed until the adapter is injected. No bundle may
ever attempt network in a runtime that didn't provide a fetch.
`rdapProxyUrl` wiring is specified precisely in **Q&A #11** (which
supersedes this paragraph's earlier phrasing): the module default stays
`"/api/rdap"` so site and tests are behavior-neutral; the Gmail entry nulls
it; the Outlook entry sets it explicitly.

**Unavailable shape: resolve to `null`** — exactly what `analyze()` already
produces for the public-webmail skip (`mx: null`, `rdap: null`). No new
"disabled" status enum in v1; the verdict engine needs zero changes. UI
degradation rule: when `mx`/`rdap` are null for a non-webmail sender, the
add-in footer says "Domain checks unavailable here — full report at
messageloupe.com."

### Q7. Distribution intent & ownership

**Pilot-first.** Sideload + M365 central deployment + private/unlisted
Marketplace install are the launch motion (matches the /business pilot
tier). Public Marketplace listing for G1 is the first later candidate;
AppSource later still. Nothing in v1 may hard-depend on public-store review.

**Ownership split:** the owner personally executes everything attached to
his accounts — Google OAuth consent screen + brand verification, Workspace
Marketplace SDK config, M365 admin central deployment, DNS, and publishing
privacy-page updates. The building agent delivers: all manifests, icons
(exported to PNG from the existing `src/app/icon.svg`), draft listing/privacy
copy, support-URL page content, and copy-paste runnable instructions for
every owner step. Support contact: use the existing addresses on
messageloupe.com (hello@/security@) — do not invent new ones.

### Q8. Verification accounts & private eval

**Assume for planning (owner to correct in the PR if wrong):** Gmail
consumer account — available; Outlook on the web + new Outlook for Windows —
available; Google Workspace domain, classic Outlook, and Outlook for Mac —
NOT assumed. Milestone gates may only require the available set; the README
matrices list the untested clients explicitly as "declared-compatible via
requirement set, not manually verified."

**Private corpus eval stays owner-run only.** Agents without local access to
`Known Fake EMLs/` must run every committed gate and state in the PR body:
"private eval not run (no local corpus access) — owner gate pending." Never
fabricate or approximate that gate.

### Q9. Milestone boundaries

**M2 is documentation-only until the owner gives an explicit written
go-ahead in a session or PR comment.** Producing service code, Azure app
registrations, or infrastructure for M2 without that go-ahead is a review
failure.

**G2 is always its own PR**, even though G1 makes the toggle tempting — the
restricted-scope escalation must be reviewable in isolation. G1's manifest
and public packaging must not contain `gmail.modify` or dormant autoscan
code.

### Q10. Autoscan UX (labels/categories)

**Messages without warning signs are marked silently** — `Message Loupe/Scanned`
only, with no visible endorsement badge. Rationale: an ambient positive mark on thousands of
messages trains users to treat absence-of-warning as endorsement and makes
any future false negative a product failure. Danger/caution tiers get visible
labels.

**Tier-only marks; reasons live in the add-in UI.** Gmail labels and Outlook
categories are global named tags, not per-message metadata — encoding
reasons there is technically unsound (label-set explosion) and leaks verdict
detail into surfaces we don't control. The user opens the message; the
card/pane shows why.

---

### Round 2 (2026-07-07) — build-mechanics decisions

### Q11. Milestone 0 env wiring — exact entry points

One core, three entries, one rule.

- **Core:** `src/lib/email/env.ts` holds the state and the *module defaults*:
  `fetch: globalThis.fetch ?? null`, `base64Decode`/`utf8Decode` from globals
  (throwing a descriptive error only when actually called without a
  provider), `rdapProxyUrl: "/api/rdap"`. Keeping `"/api/rdap"` as the module
  default is deliberate: it is today's hardcoded value, so the site, the
  worker, and every existing test remain byte-for-byte behavior-neutral with
  **zero** site-side `setEngineEnv` calls.
- **Site/worker entry:** none. `src/lib/email/index.ts` + `analyze.worker.ts`
  keep working on defaults. Existing tests keep importing `../index`.
- **Outlook entry:** `src/lib/email/entry.outlook.ts` — re-exports
  `analyze`, `setEngineEnv`, and needed types; calls
  `setEngineEnv({ rdapProxyUrl: "/api/rdap" })` explicitly (self-documenting;
  survives any future default change; correct because the pane is served
  same-origin on messageloupe.com). esbuild → ESM
  `addins/outlook` output (see Q12).
- **Gmail entry:** `src/lib/email/entry.gas.ts` — calls
  `setEngineEnv({ fetch: null, rdapProxyUrl: null })` at module load
  (fail-closed until the Apps Script host injects the UrlFetchApp adapter
  and its own base64/utf8 providers); esbuild IIFE with
  `--global-name=MessageLoupeEngine` → `addins/gmail/dist/engine.js`.
- **The rule:** no module in `src/lib/email/` except `env.ts` may touch
  `globalThis`/`fetch`/`atob`/`TextDecoder` directly, and only entry files
  call `setEngineEnv` statically. Runtime hosts (the GAS card code) call it
  again with live adapters. Add an ESLint `no-restricted-globals` scoped to
  `src/lib/email/**` (excluding `env.ts` and `analyze.worker.ts`) to enforce
  it.

### Q12. Outlook deploy path — single source of truth

`addins/outlook/src/` is the **only** source. `public/outlook/` is **100%
generated and gitignored** — `build:addins` bundles the task pane
(HTML/TS/CSS), copies `addins/outlook/assets/` (icons), and copies
`manifest.xml` into it (hosting the manifest at
`https://messageloupe.com/outlook/manifest.xml` makes central deployment
easier). Because Cloudflare Pages runs `npm run build`, change the script to
`node scripts/build-addins.mjs --outlook && next build` so the deployed site
always carries the current pane. The Gmail bundle is *not* part of the site
build (it deploys via clasp, not Cloudflare). Never hand-edit anything in
`public/outlook/`.

### Q13. Gmail "scan on demand" UI

**Open message = scan is the entire G1 read-surface UX.** There is no Gmail
surface for scanning a message you haven't opened, so a separate "Scan this
message" button would be theater. Two additions, both required: a **Rescan**
action button on the card (re-runs analysis and replaces the card via
`Navigation.updateCard` — covers flaky lookups), and a **homepage card**
stating plainly: "Open any message and Message Loupe scans it automatically.
The verdict appears here." Product copy: opening the message *is* the
demand; G1 legitimately claims both "scan on demand" and "auto-scan on
open."

### Q14. Gmail async acceptance test — make it observable, not lucky

Do not depend on the owner possessing a young/lookalike domain to send from.
Instead G1's card must include a small **"Domain checks" diagnostic row**
rendered whenever `mx`/`rdap` resolve (e.g. "MX: Google · Domain age:
2,943 days") and "Domain checks: unavailable" when they are null. The
acceptance test then becomes deterministic and manual-only:

1. Open any real external message (any retailer/newsletter) → the row must
   show resolved MX/age values. That proves the async trigger awaited
   `analyze()` **and** the UrlFetchApp adapter worked — which is everything
   Q2 needs proven.
2. Verdict-level MX/RDAP escalation behavior stays covered by the existing
   committed unit tests; no manual danger-verdict reproduction is required.

Document both steps in `addins/gmail/README.md` as owner-run checklist
items. If step 1 shows "unavailable" on real external mail, that is the Q2
fallback trigger.

### Q15. Icons — committed static PNGs, generated once

Commit static PNGs; do not generate at build time (adds an image toolchain
to the site build for assets that change ~never). The agent generates them
once from `src/app/icon.svg` with a throwaway script (the script may be
committed under `scripts/` for regeneration, but is wired into no build):

- Gmail: `public/addon-icon-128.png` (the manifest `logoUrl` must be a
  public HTTPS URL — the site serves it).
- Outlook: `addins/outlook/assets/icon-16.png`, `icon-32.png`, `icon-80.png`
  (copied into `public/outlook/` by `build:addins`, per Q12).

The SVG stays the design source; PNGs are derived artifacts, regenerated
only when the logo changes.

### Q16. Outlook requirement set — classic Outlook is best effort

Launch requirement: **Outlook on the web + new Outlook for Windows** (the
Q8 verified set). Classic Outlook for Windows on a Microsoft 365
subscription (Current Channel) has Mailbox 1.8 and should simply work —
declare it "compatible, not manually verified." Perpetual-license classic
clients (2016/2019 MSI) cap below 1.8: the manifest's
`MinVersion="1.8"` means Outlook hides the add-in there, and that is
acceptable — those users are pointed at the website. Never lower the
MinVersion to chase classic coverage; `getAllInternetHeadersAsync` is the
product. Mac: declared-compatible via requirement set, not a gate.

### Q17. Website copy timing

**Site copy changes ship in the same PR as the milestone that makes them
true — never earlier.** Milestone 0 touches no site copy. G1's PR updates
/business (and the privacy page with Q3's disclosure sentence) to reflect a
real, installable Gmail add-on using the three standardized §1 terms; M1's
PR does the same for Outlook. Until then the existing forward-looking
"build toward" wording stays. Rationale: /business currently promises a
roadmap, which is honest; claiming a mode (especially "inbox autoscan")
before it is installable is exactly the kind of overclaim the product
exists to catch.

---

### Round 3 (2026-07-07) — final consistency decisions

### Q18. Intro/terminology conflict

Fixed inline: the document intro now uses the three standardized mode names;
the old two-mode framing ("autoscan = every message landing in the inbox")
is gone. If any stray two-mode phrasing survives elsewhere, Q&A #1's
definitions govern.

### Q19. Build script split

- `npm run build` → `node scripts/build-addins.mjs --outlook && next build`.
  Only the Outlook pane is coupled to the Cloudflare deploy.
- `npm run build:addins` → builds **both** targets (no flag = both;
  `--outlook` / `--gmail` scope it). Gmail's bundle is deployed by clasp,
  never by Cloudflare, so it needs no site-build coupling — but
  `build:addins` in full is the pre-clasp step and the "does everything
  still compile" dev command.
- Test-order independence: the Milestone 0 vm test must not depend on a
  prior build — it invokes the esbuild API programmatically to produce the
  GAS bundle into a temp dir, so `npm test` stays self-contained.

### Q20. Generated-output cleanup

Yes — `build-addins.mjs` deletes its output directories before regenerating:
`public/outlook/` (on `--outlook`) and `addins/gmail/dist/` (on `--gmail`).
No stale manifest, icon, or bundle may survive a rebuild. Corollary of Q12's
"never hand-edit generated output": deletion is always safe.

### Q21. Fetch adapter type

Fixed inline in §4: `EngineEnv.fetch` is now typed as `EngineFetch | null`,
a narrow structural interface (`ok`, `status`, `json()`, `text()`; optional
ignored `signal`) that browser `fetch` satisfies as-is and the UrlFetchApp
adapter can implement honestly. Engine call sites are restricted to that
surface.

### Q22. Gmail manifest icon URL

Fixed inline in §5: `logoUrl` is `https://messageloupe.com/addon-icon-128.png`,
matching Q15's committed asset path (`public/addon-icon-128.png`).

### Q23. Brief tracking

Commit `docs/ADDIN_BUILD_BRIEF.md` to `main` **before Milestone 0 starts**.
It is the spec every add-in branch builds against, contains nothing private
(no corpus material, tokens, or tenant identifiers), and agents working on
branches need it in-tree. Future decision rounds append to §11 in normal
PRs.

## 12. Out of scope

- Team dashboard / verdict-metadata reporting (separate track).
- Auto-moving or deleting mail in any mode — Message Loupe marks, humans decide.
- Attachment content scanning (engine analyzes attachment metadata only, by design).
- Engine detection changes — unless a milestone gate exposes an actual engine bug, in which case fix it in `src/lib/email/` with a synthetic regression fixture, in its own commit.
