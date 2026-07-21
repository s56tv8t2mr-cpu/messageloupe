# Agent Discovery Link Headers Design

**Status:** Approved
**Date:** 2026-07-21

## Goal

Make Message Loupe's homepage advertise its existing machine-readable and human-readable documentation through an RFC 8288 `Link` response header, so agent-discovery tools can find useful context without implying that Message Loupe offers a supported public API.

## Decision

Add one homepage-only rule to `public/_headers`:

```text
/
  Link: </llms.txt>; rel="service-desc"; type="text/plain", </methodology/>; rel="service-doc"; type="text/html"
```

The two comma-separated link-values use registered relation types:

- `service-desc` points automated consumers to `/llms.txt`.
- `service-doc` points human consumers to `/methodology/`.

Cloudflare Pages copies `public/_headers` into the static export and applies the rule to the homepage response. No Worker, Transform Rule, middleware, or application runtime is needed.

## Scope

### Included

- Add the root-path `Link` header rule to `public/_headers`.
- Add a focused automated contract test for the exact homepage rule and both registered relations.
- Verify the rule survives the static export into `out/_headers`.
- Run the repository's full test, lint, and production-build checks.
- After deployment, confirm the production homepage returns the expected `Link` header and that the Is This Agent Ready link-header check passes.

### Excluded

- No `/.well-known/api-catalog` resource.
- No `api-catalog` link relation.
- No public API documentation or OpenAPI document.
- No change to the internal `/api/rdap` relay or its public support contract.
- No site-wide `Link` header; the recommendation and validator target the homepage.
- No Cloudflare Worker or dashboard-only Transform Rule.

## Rationale

Message Loupe already publishes the right discovery resources. `/llms.txt` is written for automated consumers and describes the product, privacy model, pages, and source repository. `/methodology/` explains the signals, verdict model, and limitations for human readers.

RFC 9727's `api-catalog` relation would be inaccurate here. A conforming API catalog must list supported API endpoints and be available as `application/linkset+json`. Message Loupe's RDAP route is an internal same-site relay, not a supported public API. Advertising an API catalog would create a public contract that the product does not intend to maintain.

Applying the header only to `/` is the smallest change that satisfies the discovery goal. Applying it to every page would repeat the same site-level metadata without improving the homepage-based scan.

## Data Flow

1. Next.js statically exports the site to `out/`.
2. The build copies `public/_headers` to `out/_headers`.
3. Cloudflare Pages reads `out/_headers` during deployment.
4. A request for `/` receives the comma-separated `Link` response header.
5. An agent resolves the relative targets against `https://messageloupe.com/` and can fetch `/llms.txt` or `/methodology/`.

## Error and Security Considerations

- Both targets are same-origin, existing, public resources.
- The change exposes no private endpoint, email data, headers, links, or verdicts.
- Relative link targets remain correct on the production domain and Cloudflare preview domains.
- The existing security headers remain unchanged.
- If Cloudflare challenges a raw command-line request, deployment verification should use the Cloudflare Pages check and a browser or the external scanner rather than treating the challenge response as the application response.

## Testing and Verification

### Automated contract

A focused test will read `public/_headers` and require:

- A root-only `/` rule.
- `</llms.txt>; rel="service-desc"; type="text/plain"`.
- `</methodology/>; rel="service-doc"; type="text/html"`.
- No `api-catalog` relation.

The test must fail before the header is added and pass after the minimal configuration change.

### Build verification

- `npm test`
- `npm run lint`
- `npm run build`
- Confirm `out/_headers` contains the exact homepage rule.

### Deployment verification

- Land through the protected pull-request workflow.
- Require SonarCloud and Cloudflare Pages checks to pass.
- Confirm local `main` matches `origin/main` after merge.
- Confirm the deployed homepage exposes both link-values.
- POST the production URL to `https://isitagentready.com/api/scan` and require `checks.discoverability.linkHeaders.status` to equal `pass`.

## Acceptance Criteria

1. The homepage response advertises `/llms.txt` as `service-desc` and `/methodology/` as `service-doc` using valid RFC 8288 syntax.
2. Message Loupe does not advertise an API catalog or imply that `/api/rdap` is a supported public API.
3. Existing security headers and application behavior are unchanged.
4. The automated contract, full tests, lint, and production build pass.
5. The deployed Is This Agent Ready link-header check reports `pass`.
