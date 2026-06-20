// RDAP domain-age lookup.
//
// Privacy boundary: this sends only the sender's registrable domain. Hosted
// browsers use the same-origin endpoint; Node and static/local hosts without
// that endpoint use public RDAP directly. It never sends message contents,
// headers, links, verdicts, or email addresses. Results are cached per runtime
// session and lookup failures are advisory only.

import { registrableDomain } from "./domain"

export interface RdapLookup {
  domain: string
  registeredAt: string | null
  ageDays: number | null
  status: "done" | "no-date" | "error"
  error?: string
}

interface RdapEvent {
  eventAction?: string
  eventDate?: string
}

interface RdapResponse {
  events?: RdapEvent[]
}

const RDAP_TIMEOUT_MS = 2500
const SAME_ORIGIN_RDAP_URL = "/api/rdap"
const cache = new Map<string, Promise<RdapLookup>>()

export function __resetRdapCacheForTests(): void {
  cache.clear()
}

function registrationDate(json: RdapResponse): string | null {
  const event = (json.events ?? []).find((item) =>
    /registration|registered|creation/i.test(item.eventAction ?? ""),
  )
  return event?.eventDate ?? null
}

function ageInDays(date: string, now = Date.now()): number | null {
  const parsed = Date.parse(date)
  if (!Number.isFinite(parsed)) return null
  return Math.max(0, Math.floor((now - parsed) / 86_400_000))
}

function directRdapUrl(domain: string): string {
  return `https://rdap.org/domain/${encodeURIComponent(domain)}`
}

function isNodeRuntime(): boolean {
  return typeof process !== "undefined" && process.release?.name === "node"
}

async function fetchRdap(domain: string, signal: AbortSignal): Promise<Response> {
  if (isNodeRuntime()) {
    return fetch(directRdapUrl(domain), {
      headers: { Accept: "application/rdap+json, application/json" },
      signal,
    })
  }

  const proxyResponse = await fetch(SAME_ORIGIN_RDAP_URL, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ domain }),
    signal,
  })
  if (proxyResponse.status !== 404 && proxyResponse.status !== 405) {
    return proxyResponse
  }

  return fetch(directRdapUrl(domain), {
    headers: { Accept: "application/rdap+json, application/json" },
    signal,
  })
}

async function doLookup(domain: string): Promise<RdapLookup> {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), RDAP_TIMEOUT_MS)

  try {
    const res = await fetchRdap(domain, controller.signal)
    if (!res.ok) {
      return {
        domain,
        registeredAt: null,
        ageDays: null,
        status: "error",
        error: `HTTP ${res.status}`,
      }
    }

    const registeredAt = registrationDate((await res.json()) as RdapResponse)
    if (!registeredAt) {
      return { domain, registeredAt: null, ageDays: null, status: "no-date" }
    }

    return {
      domain,
      registeredAt,
      ageDays: ageInDays(registeredAt),
      status: "done",
    }
  } catch (err) {
    return {
      domain,
      registeredAt: null,
      ageDays: null,
      status: "error",
      error: err instanceof Error ? err.message : String(err),
    }
  } finally {
    clearTimeout(timeout)
  }
}

export function lookupRdapDomainAge(
  domain: string | null | undefined,
): Promise<RdapLookup | null> {
  const key = registrableDomain(domain)
  if (!key) return Promise.resolve(null)
  const hit = cache.get(key)
  if (hit) return hit
  const p = doLookup(key)
  cache.set(key, p)
  return p
}
