# Agent Readiness Discovery Design

**Status:** Approved
**Date:** 2026-07-21

## Goal

Improve Message Loupe's truthful discoverability for AI agents without inventing public APIs, authentication systems, agent endpoints, or data-sharing behavior that the product does not provide.

## Included Work

### Homepage discovery links

Add this homepage-only rule to `public/_headers`:

```text
/
  Link: </llms.txt>; rel="service-desc"; type="text/plain", </methodology/>; rel="service-doc"; type="text/html"
```

`/llms.txt` is the machine-readable product description. `/methodology/` is the human-readable service documentation. The registered RFC 8288 relations describe existing public resources and do not imply a supported public API.

### Content Signals

Replace the typed `src/app/robots.ts` generator with a static `src/app/robots.txt` so the non-standard `Content-Signal` directive can be emitted exactly:

```text
Content-Signal: search=yes, ai-input=yes, ai-train=no
```

This permits conventional indexing and real-time AI grounding while reserving Message Loupe's content from model training. Preserve the existing `User-Agent`, `Allow`, `Host`, and `Sitemap` behavior.

### Agent Skill discovery

Publish one instruction-only Agent Skill named `review-suspicious-email` under `/.well-known/agent-skills/` using the Cloudflare draft v0.2.0 format.

The skill must:

- Direct users to Message Loupe's browser-local workflow.
- Prefer an original saved `.eml` over a regular forward.
- Never ask the user to paste or upload the message into the agent conversation.
- Explain the three verdict levels and their limits.
- Recommend independent verification for requests involving money or credentials.
- Contain instructions only: no scripts, API calls, MCP claims, or executable assets.

Publish an `index.json` with the v0.2.0 `$schema`, one `skill-md` entry, and a `digest` value formatted as `sha256:<64 lowercase hexadecimal characters>`. Generate the index from the raw `SKILL.md` bytes so the digest cannot drift. Serve the index as JSON and the skill as Markdown, with permissive CORS for browser-based agent clients.

## Explicitly Deferred

- **Markdown for Agents:** Cloudflare's native HTML-to-Markdown negotiation is unavailable on the Free plan. Do not upgrade solely for this scanner result.
- **WebMCP:** The current API is experimental and the scanner's `navigator.modelContext.provideContext()` guidance is obsolete. A useful email-analysis tool could expose private message data to an agent provider and requires separate privacy and threat-model work.

## Explicitly Excluded

- DNS for AI Discovery: Message Loupe operates no DNS-discoverable A2A, MCP, or agent-index endpoint.
- API Catalog: `/api/rdap` is an internal same-origin relay, not a supported public API.
- OAuth or OIDC discovery: Message Loupe is not an authorization server or identity provider.
- OAuth Protected Resource Metadata: Message Loupe has no bearer-token-protected public resource.
- `auth.md`: Message Loupe has no accounts, agent registration, credential issuance, claim, or revocation flow.
- MCP Server Card: Message Loupe operates no MCP server or transport endpoint.

## Architecture

All included artifacts remain static and are deployed through the existing Next.js export and Cloudflare Pages pipeline:

1. `src/app/robots.txt` is emitted as `out/robots.txt`.
2. `public/_headers` is copied to `out/_headers` and interpreted by Cloudflare Pages.
3. `public/.well-known/agent-skills/` is copied into the static export.
4. A dependency-free Node script computes the skill's SHA-256 digest and writes its discovery index before each production build.
5. A focused Vitest contract verifies exact policy values, discovery paths, response-header configuration, and digest integrity.

## Security and Privacy Boundaries

- Do not expose email content, headers, links, verdicts, or internal application state through any new endpoint.
- Do not describe `/api/rdap` as public or supported.
- Do not instruct an agent to ingest the user's suspicious email.
- Do not add executable skill scripts or archives.
- Keep all new resources same-origin and publicly readable.
- Treat Content Signals as preference declarations, not technical access controls.

## Acceptance Criteria

1. The homepage advertises `/llms.txt` with `service-desc` and `/methodology/` with `service-doc` in one valid `Link` response header.
2. `/robots.txt` contains exactly `search=yes, ai-input=yes, ai-train=no` while preserving the existing crawl, host, and sitemap directives.
3. `/.well-known/agent-skills/index.json` validates against the documented v0.2.0 shape and its digest matches the raw published `SKILL.md` bytes.
4. The skill is instruction-only and preserves Message Loupe's browser-local privacy promise.
5. No excluded API, authentication, MCP, DNS-AID, or WebMCP surface is published.
6. Focused tests, the full test suite, lint, and the static production build pass.
7. The static export contains the expected `_headers`, `robots.txt`, skills index, and `SKILL.md` artifacts.
8. After protected-branch deployment, the production Link Headers, Content Signals, and Agent Skills checks pass in Is This Agent Ready.
