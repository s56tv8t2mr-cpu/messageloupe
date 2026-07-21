# Agent Readiness Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish truthful, privacy-preserving agent discovery metadata through homepage Link headers, Content Signals, and one instruction-only Agent Skill.

**Architecture:** Keep every new surface static and compatible with the existing Next.js export and Cloudflare Pages deployment. Replace the typed robots generator only because Next.js cannot express `Content-Signal`, generate the Agent Skills index from the raw skill bytes, and enforce the complete contract with one focused Vitest file.

**Tech Stack:** Next.js 16 static export, TypeScript, Vitest, Node.js built-in `crypto` and `fs`, Cloudflare Pages `_headers`.

## Global Constraints

- Implement only the approved scope in `docs/superpowers/specs/2026-07-21-agent-readiness-design.md`.
- Preserve Message Loupe's promise that email contents, headers, links, and verdicts are not uploaded.
- Use `Content-Signal: search=yes, ai-input=yes, ai-train=no` exactly.
- Publish exactly one instruction-only skill named `review-suspicious-email`; add no scripts or archive.
- Do not publish DNS-AID, API Catalog, OAuth/OIDC, OAuth Protected Resource, `auth.md`, MCP Server Card, or WebMCP artifacts.
- Do not add runtime dependencies.
- Prefix any `npm install` or `npx` command with `sfw`; this plan requires neither command.
- Keep the existing security headers unchanged.
- Land through the protected pull-request and Cloudflare Pages deployment workflow.

## File Structure

- Create `src/app/__tests__/agent-discovery.test.ts` — source and artifact contract for all accepted discovery surfaces.
- Modify `public/_headers` — homepage Link response header plus MIME/CORS/cache headers for the skill index and skill document.
- Delete `src/app/robots.ts` — the typed metadata generator cannot emit `Content-Signal`.
- Create `src/app/robots.txt` — static crawl policy and Content Signals.
- Create `public/.well-known/agent-skills/review-suspicious-email/SKILL.md` — the published instruction-only skill.
- Create `scripts/generate-agent-skills-index.mjs` — dependency-free SHA-256 index generator.
- Create `public/.well-known/agent-skills/index.json` — generated and committed discovery index.
- Modify `package.json` — expose the generator and run it automatically before production builds.

---

### Task 1: Publish the homepage Link response header

**Files:**
- Create: `src/app/__tests__/agent-discovery.test.ts`
- Modify: `public/_headers`

**Interfaces:**
- Consumes: existing `public/llms.txt` and `/methodology/` route.
- Produces: a Cloudflare Pages homepage `Link` header containing registered `service-desc` and `service-doc` relations.

- [ ] **Step 1: Write the failing homepage-header contract**

Create `src/app/__tests__/agent-discovery.test.ts` with:

```ts
import { readFileSync } from "node:fs"
import { resolve } from "node:path"
import { describe, expect, it } from "vitest"

function readNormalized(path: string): string {
  return readFileSync(resolve(process.cwd(), path), "utf8").replace(/\r\n/g, "\n")
}

describe("agent discovery headers", () => {
  it("advertises existing description and documentation from the homepage", () => {
    const headers = readNormalized("public/_headers")

    expect(headers).toContain(
      [
        "/",
        '  Link: </llms.txt>; rel="service-desc"; type="text/plain", </methodology/>; rel="service-doc"; type="text/html"',
      ].join("\n"),
    )
    expect(headers).not.toContain('rel="api-catalog"')
  })
})
```

- [ ] **Step 2: Run the focused test and verify that it fails**

Run:

```powershell
npm test -- src/app/__tests__/agent-discovery.test.ts
```

Expected: FAIL because `public/_headers` does not yet contain the homepage `Link` rule.

- [ ] **Step 3: Add the exact homepage rule**

Append this block to `public/_headers` without changing any existing rule:

```text

# Agent discovery on the homepage.
/
  Link: </llms.txt>; rel="service-desc"; type="text/plain", </methodology/>; rel="service-doc"; type="text/html"
```

- [ ] **Step 4: Run the focused test and verify that it passes**

Run:

```powershell
npm test -- src/app/__tests__/agent-discovery.test.ts
```

Expected: one test passes.

- [ ] **Step 5: Commit the Link-header slice**

Run:

```powershell
git add public/_headers src/app/__tests__/agent-discovery.test.ts
git commit -m "Add agent discovery Link headers"
```

Expected: one commit containing only the header rule and its focused contract.

---

### Task 2: Declare Content Signals in a static robots file

**Files:**
- Modify: `src/app/__tests__/agent-discovery.test.ts`
- Delete: `src/app/robots.ts`
- Create: `src/app/robots.txt`

**Interfaces:**
- Consumes: the existing crawl policy, host, and sitemap values from `src/app/robots.ts`.
- Produces: an exported `/robots.txt` that adds Content Signals without changing crawler access.

- [ ] **Step 1: Add a failing robots contract**

Replace the first import in `src/app/__tests__/agent-discovery.test.ts` with:

```ts
import { existsSync, readFileSync } from "node:fs"
```

Append this complete test block:

```ts
describe("robots policy", () => {
  it("allows search and AI input while reserving content from training", () => {
    expect(existsSync(resolve(process.cwd(), "src/app/robots.ts"))).toBe(false)

    const robots = readNormalized("src/app/robots.txt").trimEnd()
    expect(robots).toBe(
      [
        "User-Agent: *",
        "Content-Signal: search=yes, ai-input=yes, ai-train=no",
        "Allow: /",
        "",
        "Host: https://messageloupe.com",
        "Sitemap: https://messageloupe.com/sitemap.xml",
      ].join("\n"),
    )
  })
})
```

- [ ] **Step 2: Run the focused test and verify that it fails**

Run:

```powershell
npm test -- src/app/__tests__/agent-discovery.test.ts
```

Expected: the Link-header test passes and the robots test fails because `src/app/robots.ts` still exists and `src/app/robots.txt` does not.

- [ ] **Step 3: Replace the generated robots route with the static file**

Delete `src/app/robots.ts` and create `src/app/robots.txt` with exactly:

```text
User-Agent: *
Content-Signal: search=yes, ai-input=yes, ai-train=no
Allow: /

Host: https://messageloupe.com
Sitemap: https://messageloupe.com/sitemap.xml
```

- [ ] **Step 4: Run the focused test and production build**

Run:

```powershell
npm test -- src/app/__tests__/agent-discovery.test.ts
npm run build
Get-Content out\robots.txt
```

Expected: both tests pass, the build succeeds, and `out/robots.txt` contains the exact six-line policy from Step 3.

- [ ] **Step 5: Commit the Content Signals slice**

Run:

```powershell
git add src/app/robots.ts src/app/robots.txt src/app/__tests__/agent-discovery.test.ts
git commit -m "Declare AI content usage preferences"
```

Expected: one commit replacing only the robots implementation and extending its contract.

---

### Task 3: Publish the privacy-preserving Agent Skill

**Files:**
- Modify: `src/app/__tests__/agent-discovery.test.ts`
- Modify: `public/_headers`
- Modify: `package.json`
- Create: `public/.well-known/agent-skills/review-suspicious-email/SKILL.md`
- Create: `scripts/generate-agent-skills-index.mjs`
- Create: `public/.well-known/agent-skills/index.json`

**Interfaces:**
- Consumes: the public Message Loupe workflow, save-email guide, methodology, privacy page, and the raw bytes of `SKILL.md`.
- Produces: `generate-agent-skills-index.mjs`, which writes a v0.2.0 index whose `digest` is the `sha256:` prefix followed by the exact skill bytes' 64-character lowercase hexadecimal hash.

- [ ] **Step 1: Replace the focused test with the complete final contract**

Replace `src/app/__tests__/agent-discovery.test.ts` with:

```ts
import { createHash } from "node:crypto"
import { existsSync, readFileSync } from "node:fs"
import { resolve } from "node:path"
import { describe, expect, it } from "vitest"

const skillDescription =
  "Guide a user to privately check a suspicious email with Message Loupe, preserve original headers, and interpret the result. Use when the user asks whether an email may be phishing, spoofed, or business email compromise."

function repoPath(path: string): string {
  return resolve(process.cwd(), path)
}

function readNormalized(path: string): string {
  return readFileSync(repoPath(path), "utf8").replace(/\r\n/g, "\n")
}

describe("agent discovery headers", () => {
  it("advertises existing description and documentation from the homepage", () => {
    const headers = readNormalized("public/_headers")

    expect(headers).toContain(
      [
        "/",
        '  Link: </llms.txt>; rel="service-desc"; type="text/plain", </methodology/>; rel="service-doc"; type="text/html"',
      ].join("\n"),
    )
    expect(headers).not.toContain('rel="api-catalog"')
  })

  it("serves the skills index and skill with explicit types and CORS", () => {
    const headers = readNormalized("public/_headers")

    expect(headers).toContain(
      [
        "/.well-known/agent-skills/index.json",
        "  Content-Type: application/json; charset=utf-8",
        "  Access-Control-Allow-Origin: *",
        "  Cache-Control: public, max-age=3600, must-revalidate",
      ].join("\n"),
    )
    expect(headers).toContain(
      [
        "/.well-known/agent-skills/review-suspicious-email/SKILL.md",
        "  Content-Type: text/markdown; charset=utf-8",
        "  Access-Control-Allow-Origin: *",
        "  Cache-Control: public, max-age=3600, must-revalidate",
      ].join("\n"),
    )
  })
})

describe("robots policy", () => {
  it("allows search and AI input while reserving content from training", () => {
    expect(existsSync(repoPath("src/app/robots.ts"))).toBe(false)

    const robots = readNormalized("src/app/robots.txt").trimEnd()
    expect(robots).toBe(
      [
        "User-Agent: *",
        "Content-Signal: search=yes, ai-input=yes, ai-train=no",
        "Allow: /",
        "",
        "Host: https://messageloupe.com",
        "Sitemap: https://messageloupe.com/sitemap.xml",
      ].join("\n"),
    )
  })
})

describe("Agent Skills discovery", () => {
  it("publishes one instruction-only skill with a matching SHA-256 digest", () => {
    const skillPath = "public/.well-known/agent-skills/review-suspicious-email/SKILL.md"
    const skillBytes = readFileSync(repoPath(skillPath))
    const skill = skillBytes.toString("utf8").replace(/\r\n/g, "\n")
    const digest = `sha256:${createHash("sha256").update(skillBytes).digest("hex")}`
    const index = JSON.parse(
      readFileSync(repoPath("public/.well-known/agent-skills/index.json"), "utf8"),
    )

    expect(index).toEqual({
      $schema: "https://schemas.agentskills.io/discovery/0.2.0/schema.json",
      skills: [
        {
          name: "review-suspicious-email",
          type: "skill-md",
          description: skillDescription,
          url: "/.well-known/agent-skills/review-suspicious-email/SKILL.md",
          digest,
        },
      ],
    })
    expect(skill.startsWith(`---\nname: review-suspicious-email\ndescription: ${skillDescription}\n---\n`)).toBe(
      true,
    )
    expect(skill).toContain("Do not ask the user to paste the email into the conversation")
    expect(skill).toContain("A regular forward is not sufficient")
    expect(skill).toContain("Never describe a verdict as a guarantee")
    expect(skill).not.toContain("scripts/")
  })
})
```

- [ ] **Step 2: Run the focused test and verify that the skill contract fails**

Run:

```powershell
npm test -- src/app/__tests__/agent-discovery.test.ts
```

Expected: existing Link and robots assertions pass; the skill assertions fail because the index, skill, and response-header rules do not exist.

- [ ] **Step 3: Create the exact instruction-only skill**

Create `public/.well-known/agent-skills/review-suspicious-email/SKILL.md` with:

```markdown
---
name: review-suspicious-email
description: Guide a user to privately check a suspicious email with Message Loupe, preserve original headers, and interpret the result. Use when the user asks whether an email may be phishing, spoofed, or business email compromise.
---

# Review a suspicious email with Message Loupe

## Protect the user's privacy

- Do not ask the user to paste the email into the conversation or send it to another service.
- Direct the user to [Message Loupe](https://messageloupe.com/), where parsing and verdict analysis run in their browser.
- The optional DNS and RDAP checks may send only the visible sender domain. They do not send the message, headers, links, or verdict.

## Obtain the original message

A regular forward is not sufficient because it replaces the original delivery headers. Ask the user to save the original message as an `.eml` file by following [How to save an email](https://messageloupe.com/how-to-save-an-email/).

## Run the private check

1. Ask the user to open [Message Loupe](https://messageloupe.com/).
2. Have the user drop the saved `.eml` file onto the page, or paste the original raw message directly into the page.
3. Wait for Message Loupe to finish its local analysis.
4. Ask the user to share only the displayed verdict level if they want help understanding what it means.

## Interpret the result

- **No warning signs:** Message Loupe did not detect a warning sign, but the message is not guaranteed safe.
- **Caution:** The user should independently verify the request, especially before sending money, changing payment details, entering credentials, or opening a link.
- **Likely fake:** The message shows strong evidence of impersonation, spoofing, or another deceptive pattern. The user should not act on it through the message.

Never describe a verdict as a guarantee. A real, authenticated account can still be compromised, so Message Loupe may not detect every business email compromise. Refer to the [methodology](https://messageloupe.com/methodology/) for the checked signals and deliberate limitations.

## Escalate consequential requests

For money, payment-detail, payroll, gift-card, or credential requests, tell the user to verify through an independently sourced phone number or another trusted channel. Do not use contact details supplied by the suspicious message.
```

- [ ] **Step 4: Create the deterministic index generator**

Create `scripts/generate-agent-skills-index.mjs` with:

```js
import { createHash } from "node:crypto"
import { mkdir, readFile, writeFile } from "node:fs/promises"
import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const skillDescription =
  "Guide a user to privately check a suspicious email with Message Loupe, preserve original headers, and interpret the result. Use when the user asks whether an email may be phishing, spoofed, or business email compromise."
const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const skillsRoot = resolve(projectRoot, "public/.well-known/agent-skills")
const skillPath = resolve(skillsRoot, "review-suspicious-email/SKILL.md")
const indexPath = resolve(skillsRoot, "index.json")

const skillBytes = await readFile(skillPath)
const digest = `sha256:${createHash("sha256").update(skillBytes).digest("hex")}`
const index = {
  $schema: "https://schemas.agentskills.io/discovery/0.2.0/schema.json",
  skills: [
    {
      name: "review-suspicious-email",
      type: "skill-md",
      description: skillDescription,
      url: "/.well-known/agent-skills/review-suspicious-email/SKILL.md",
      digest,
    },
  ],
}

await mkdir(dirname(indexPath), { recursive: true })
await writeFile(indexPath, `${JSON.stringify(index, null, 2)}\n`, "utf8")
console.log(`Wrote ${indexPath} with ${digest}`)
```

- [ ] **Step 5: Wire index generation into the project scripts**

Replace the `scripts` object in `package.json` with:

```json
"scripts": {
  "dev": "next dev",
  "generate:agent-skills": "node scripts/generate-agent-skills-index.mjs",
  "prebuild": "npm run generate:agent-skills",
  "build": "next build",
  "start": "next start",
  "lint": "eslint",
  "test": "vitest run",
  "test:email-eval": "vitest run src/lib/email/__tests__/corpus-eval.test.ts",
  "eval:private": "vitest run --config vitest.private.config.ts --reporter=verbose",
  "test:watch": "vitest"
}
```

- [ ] **Step 6: Add exact MIME, CORS, and cache rules**

Append these blocks to `public/_headers`:

```text

# Agent Skills discovery artifacts.
/.well-known/agent-skills/index.json
  Content-Type: application/json; charset=utf-8
  Access-Control-Allow-Origin: *
  Cache-Control: public, max-age=3600, must-revalidate

/.well-known/agent-skills/review-suspicious-email/SKILL.md
  Content-Type: text/markdown; charset=utf-8
  Access-Control-Allow-Origin: *
  Cache-Control: public, max-age=3600, must-revalidate
```

- [ ] **Step 7: Generate the committed index and run the focused test**

Run:

```powershell
npm run generate:agent-skills
npm test -- src/app/__tests__/agent-discovery.test.ts
```

Expected: the generator prints one `sha256:` digest containing 64 lowercase hexadecimal characters, writes `public/.well-known/agent-skills/index.json`, and all four focused tests pass.

- [ ] **Step 8: Verify the exported skill artifacts**

Run:

```powershell
npm run build
Get-Content out\.well-known\agent-skills\index.json
Get-Content out\.well-known\agent-skills\review-suspicious-email\SKILL.md
```

Expected: the build succeeds; both exported files exist and match the corresponding files under `public/.well-known/agent-skills/`.

- [ ] **Step 9: Commit the Agent Skill slice**

Run:

```powershell
git add package.json public/_headers public/.well-known/agent-skills scripts/generate-agent-skills-index.mjs src/app/__tests__/agent-discovery.test.ts
git commit -m "Publish suspicious email review skill"
```

Expected: one commit containing the skill, generated index, generator, response-header rules, package scripts, and final contract.

---

### Task 4: Run the complete local verification gate

**Files:**
- Verify: all files changed in Tasks 1-3

**Interfaces:**
- Consumes: the completed static-discovery implementation.
- Produces: evidence that tests, lint, build output, and exclusions all match the approved design.

- [ ] **Step 1: Regenerate and require a clean deterministic result**

Run:

```powershell
npm run generate:agent-skills
git diff --exit-code -- public/.well-known/agent-skills/index.json
```

Expected: the generator succeeds and `git diff --exit-code` returns exit code 0, proving the committed digest is current.

- [ ] **Step 2: Run the full repository checks**

Run each command separately:

```powershell
npm test
```

```powershell
npm run lint
```

```powershell
npm run build
```

```powershell
git diff --check
```

Expected: all tests pass, ESLint reports no errors, Next.js produces `out/`, and Git reports no whitespace errors.

- [ ] **Step 3: Verify the exact static export**

Run:

```powershell
Get-Content out\robots.txt
Get-Content out\_headers
Get-Content out\.well-known\agent-skills\index.json
Get-FileHash out\.well-known\agent-skills\review-suspicious-email\SKILL.md -Algorithm SHA256
```

Expected:

- `out/robots.txt` contains `Content-Signal: search=yes, ai-input=yes, ai-train=no`.
- `out/_headers` contains the homepage Link rule and both skill response-header blocks.
- The index contains one `review-suspicious-email` entry using schema v0.2.0.
- The displayed SHA-256 value, lowercased and prefixed with `sha256:`, equals the index `digest`.

- [ ] **Step 4: Prove that excluded discovery surfaces were not created**

Run:

```powershell
Test-Path out\.well-known\api-catalog
Test-Path out\.well-known\oauth-authorization-server
Test-Path out\.well-known\oauth-protected-resource
Test-Path out\.well-known\mcp\server-card.json
Test-Path out\auth.md
```

Expected: every command prints `False`.

- [ ] **Step 5: Confirm the worktree contains only approved changes**

Run:

```powershell
git status --short
git log --oneline origin/main..HEAD
```

Expected: the worktree is clean and the branch contains the design/plan documentation, the approved workflow-isolation setup, and the three focused implementation commits.

---

### Task 5: Land through the protected deployment path and verify production

**Files:**
- Verify: production responses and Is This Agent Ready results

**Interfaces:**
- Consumes: the locally verified branch.
- Produces: merged `main`, a completed Cloudflare Pages deployment, and production evidence for the three accepted findings.

- [ ] **Step 1: Use the project ship workflow**

Invoke the `ship` skill from the clean repository root. It must commit any approved residual documentation, push `codex/agent-readiness-implementation`, open the required pull request, and verify that the Cloudflare Pages deployment check starts.

Expected: the branch is pushed and a pull request targets `main`; no direct protected-branch push is attempted.

- [ ] **Step 2: Require repository checks before merge**

Wait for all required GitHub checks, including SonarCloud and Cloudflare Pages, to pass. Review the PR diff and require that it contains only the files enumerated in this plan.

Expected: all required checks are green and the PR diff contains no API, OAuth, MCP, DNS-AID, auth.md, or WebMCP implementation.

- [ ] **Step 3: Merge and synchronize the local checkout**

After the pull request merges, run:

```powershell
git switch main
git pull --ff-only origin main
git status --short --branch
```

Expected: local `main` matches `origin/main` and the worktree is clean.

- [ ] **Step 4: Verify production response behavior**

Use a real browser for `https://messageloupe.com/`, `https://messageloupe.com/robots.txt`, `https://messageloupe.com/.well-known/agent-skills/index.json`, and `https://messageloupe.com/.well-known/agent-skills/review-suspicious-email/SKILL.md`. Use browser developer tools or the successful Cloudflare response rather than treating a command-line Cloudflare challenge page as the application response.

Expected:

- Homepage response includes both Link values.
- `robots.txt` displays the exact Content Signals policy.
- The index returns JSON and its configured CORS header.
- `SKILL.md` returns Markdown and its configured CORS header.

- [ ] **Step 5: Re-run Is This Agent Ready with the correct site type**

Open [Is This Agent Ready](https://isitagentready.com/), scan `https://messageloupe.com/` as a content site, and confirm:

- Link Headers: pass.
- Content Signals: pass.
- Agent Skills: pass.

Record Markdown negotiation as unavailable on the Free plan. Treat DNS-AID, API Catalog, OAuth/OIDC, OAuth Protected Resource, auth.md, MCP Server Card, and WebMCP as intentionally not applicable or deferred rather than product defects.

- [ ] **Step 6: Run a final product smoke test**

Load the homepage in a normal browser, confirm the scanner UI renders, and analyze a non-sensitive known-good fixture through the existing browser workflow.

Expected: the application still produces its normal verdict and none of the static discovery changes alter the user-facing workflow.
