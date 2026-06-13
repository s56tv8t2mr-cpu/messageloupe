// RDAP domain-age lookup.
//
// Privacy boundary: this sends only the sender's registrable domain to the
// public RDAP bootstrap service. It never sends message contents, headers,
// links, verdicts, or email addresses. Results are cached per browser session
// and lookup failures are advisory only.

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

async function doLookup(domain: string): Promise<RdapLookup> {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), RDAP_TIMEOUT_MS)

  try {
    const url = `https://rdap.org/domain/${encodeURIComponent(domain)}`
    const res = await fetch(url, {
      headers: { Accept: "application/rdap+json, application/json" },
      signal: controller.signal,
    })
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
