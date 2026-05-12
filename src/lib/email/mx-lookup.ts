// MX-record lookup over DNS-over-HTTPS.
//
// Used by the verdict engine to detect a high-confidence brand-impersonation
// pattern: the visible sender domain's MX records resolve to one inbound
// provider (e.g. Google Workspace, Microsoft 365), but the message was
// actually delivered by a third-party ESP (SendGrid, MailerLite, etc.) that
// the domain owner doesn't authorize. The MX/delivery split is the
// discriminator — a forged-sender attack where the domain owner is the
// victim, not a compromised source.
//
// Two queries shouldn't fire for the same domain concurrently, and a result
// should be reusable within the same browser session — we cache the Promise
// itself (not just the resolved value) in a Map keyed by lowercase domain.
//
// Provider classification is a closed list. First match wins; unmatched
// hosts → provider: null (we won't claim a mismatch on a provider we don't
// recognize).
//
// Lookup errors never affect the verdict. The verdict engine's
// auth-alignment gate dominates: only an aligned SPF/DKIM/DMARC pass plus
// a positively-classified MX/service mismatch fires the confirmed reason.
// A timeout, HTTP error, NXDOMAIN, or null provider all leave the MX block
// silent — there's no fallback that escalates without a successful lookup.

export interface MxRecord {
  priority: number | null
  host: string
}

export interface MxLookup {
  domain: string
  hosts: string[]
  records: MxRecord[]
  /** Provider name (e.g. "Google") if any host matched a known pattern, else null. */
  provider: string | null
  status: "pending" | "done" | "error"
  error?: string
}

interface ProviderPattern {
  provider: string
  match: (host: string) => boolean
}

const PROVIDER_MX_PATTERNS: readonly ProviderPattern[] = [
  {
    provider: "Google",
    match: (h) =>
      /(^|\.)aspmx\.l\.google\.com$|(^|\.)aspmx[0-9]*\.googlemail\.com$|(^|\.)googlemail\.com$/i.test(
        h,
      ),
  },
  {
    provider: "Microsoft 365",
    match: (h) => /(^|\.)mail\.protection\.outlook\.com$|(^|\.)olc\.protection\.outlook\.com$/i.test(h),
  },
  {
    provider: "Proofpoint",
    match: (h) => /(^|\.)pphosted\.com$|(^|\.)ppe-hosted\.com$/i.test(h),
  },
  {
    provider: "Mimecast",
    match: (h) => /(^|\.)mimecast\.com$|(^|\.)mimecast\.co\.[a-z]+$/i.test(h),
  },
  {
    provider: "Cisco Cloud Email Security",
    match: (h) => /(^|\.)iphmx\.com$|(^|\.)cesmail\.net$/i.test(h),
  },
  {
    provider: "AppRiver",
    match: (h) => /(^|\.)appriver\.com$/i.test(h),
  },
  {
    provider: "Barracuda",
    match: (h) => /(^|\.)barracudanetworks\.com$/i.test(h),
  },
  {
    provider: "Zoho Mail",
    match: (h) => /(^|\.)zoho\.com$|(^|\.)zohomail\.com$/i.test(h),
  },
  {
    provider: "Fastmail",
    match: (h) => /(^|\.)fastmail\.com$|(^|\.)messagingengine\.com$/i.test(h),
  },
  {
    provider: "Yahoo",
    match: (h) => /(^|\.)yahoodns\.net$/i.test(h),
  },
  {
    provider: "GoDaddy",
    match: (h) => /(^|\.)secureserver\.net$/i.test(h),
  },
  {
    provider: "Rackspace",
    match: (h) => /(^|\.)emailsrvr\.com$/i.test(h),
  },
]

// Session-memory cache only; no TTL, no persistence. Acceptable because the
// analyzer is per-message and a stale MX would only mislabel during the same
// browser session.
const cache = new Map<string, Promise<MxLookup>>()

/** Test-only: clear the in-flight/result cache between cases. */
export function __resetMxCacheForTests(): void {
  cache.clear()
}

function classifyProvider(hosts: readonly string[]): string | null {
  for (const host of hosts) {
    for (const pattern of PROVIDER_MX_PATTERNS) {
      if (pattern.match(host)) return pattern.provider
    }
  }
  return null
}

interface DnsAnswer {
  type: number
  data: string
}

interface DnsResponse {
  Status?: number
  Answer?: DnsAnswer[]
}

async function doLookup(domain: string): Promise<MxLookup> {
  try {
    const url = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=MX`
    const res = await fetch(url, {
      headers: { Accept: "application/dns-json" },
      signal: AbortSignal.timeout(3000),
    })
    if (!res.ok) {
      return {
        domain,
        hosts: [],
        records: [],
        provider: null,
        status: "error",
        error: `HTTP ${res.status}`,
      }
    }
    const json = (await res.json()) as DnsResponse
    // DNS-over-HTTPS Status: 0 = NOERROR, 3 = NXDOMAIN, others = various
    // resolver failures. Any non-zero status means "no usable answer."
    if (typeof json.Status === "number" && json.Status !== 0) {
      return {
        domain,
        hosts: [],
        records: [],
        provider: null,
        status: "error",
        error: `DNS Status ${json.Status}`,
      }
    }
    const records: MxRecord[] = []
    for (const ans of json.Answer ?? []) {
      if (ans.type !== 15) continue
      // Format: "<priority> <host>." — host may end with a trailing dot
      // from the canonical DNS representation; strip it.
      const parts = ans.data.trim().split(/\s+/)
      if (parts.length < 2) continue
      const priority = Number.parseInt(parts[0], 10)
      const host = parts[1].replace(/\.$/, "").toLowerCase()
      records.push({
        priority: Number.isFinite(priority) ? priority : null,
        host,
      })
    }
    records.sort((a, b) => (a.priority ?? 99999) - (b.priority ?? 99999))
    const hosts = records.map((r) => r.host)
    return {
      domain,
      hosts,
      records,
      provider: classifyProvider(hosts),
      status: "done",
    }
  } catch (err) {
    return {
      domain,
      hosts: [],
      records: [],
      provider: null,
      status: "error",
      error: err instanceof Error ? err.message : String(err),
    }
  }
}

/**
 * Lookup the MX records for the visible Header From domain. Do not pass
 * Return-Path, SPF MAIL FROM, DKIM d=, or any inferred ESP/service domain —
 * MX describes inbound mail routing for the visible sender, and only the
 * visible sender's MX/delivery split is the discriminator.
 *
 * Returns null on empty input. The result Promise is cached (per lowercase
 * domain) for the lifetime of the module so repeat lookups within a session
 * are free.
 *
 * Public-webmail gating (don't bother looking up gmail.com etc.) is the
 * caller's responsibility — this module doesn't know which domains are
 * webmail and doesn't need to.
 */
export function lookupMx(
  domain: string | null | undefined,
): Promise<MxLookup | null> {
  if (!domain) return Promise.resolve(null)
  const key = domain.toLowerCase()
  const hit = cache.get(key)
  if (hit) return hit
  const p = doLookup(key)
  cache.set(key, p)
  return p
}

/**
 * Intentionally conservative string compare. The verdict engine layers an
 * SPF/DKIM/DMARC alignment gate on top, which absorbs the equivalent-provider
 * edge cases (Google Workspace inbound + Gmail outbound, Microsoft 365
 * inbound + Outlook outbound, etc.) — those all authenticate, so the gate
 * suppresses the false positive.
 *
 * True iff the lookup completed, classified a provider, and that provider
 * doesn't match the ESP that actually delivered the message.
 */
export function mxConflictsWithDelivery(
  mx: MxLookup | null,
  sendingService: string | null | undefined,
): boolean {
  if (!mx || mx.status !== "done" || !mx.provider || !sendingService) return false
  return mx.provider.toLowerCase() !== sendingService.toLowerCase()
}
