const DOMAIN_LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
const DOMAIN_RE = new RegExp(`^(?=.{1,253}$)(?:${DOMAIN_LABEL}\\.)+(?!\\d+$)${DOMAIN_LABEL}$`)
const BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
const TIMEOUT_MS = 3000

function json(body, init = {}) {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...init.headers,
    },
  })
}

async function authoritativeRdapUrl(domain, signal) {
  const bootstrap = await fetch(BOOTSTRAP_URL, {
    headers: { Accept: "application/json" },
    signal,
  })
  if (!bootstrap.ok) throw new Error(`RDAP bootstrap failed with HTTP ${bootstrap.status}`)

  const payload = await bootstrap.json()
  const tld = domain.slice(domain.lastIndexOf(".") + 1)
  const service = Array.isArray(payload?.services)
    ? payload.services.find(
        (entry) =>
          Array.isArray(entry?.[0]) &&
          entry[0].some((candidate) => String(candidate).toLowerCase() === tld),
      )
    : null
  const base = Array.isArray(service?.[1])
    ? service[1].find((candidate) => String(candidate).startsWith("https://"))
    : null
  if (!base) throw new Error("No authoritative RDAP service found")

  const normalizedBase = String(base).endsWith("/") ? String(base) : `${base}/`
  return new URL(`domain/${encodeURIComponent(domain)}`, normalizedBase).toString()
}

export async function onRequestPost({ request }) {
  let domain = ""
  try {
    const body = await request.json()
    domain = typeof body?.domain === "string" ? body.domain.toLowerCase() : ""
  } catch {
    return json({ error: "Invalid request" }, { status: 400 })
  }

  if (!DOMAIN_RE.test(domain)) {
    return json({ error: "Invalid domain" }, { status: 400 })
  }

  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS)

  try {
    const rdapUrl = await authoritativeRdapUrl(domain, controller.signal)
    const upstream = await fetch(rdapUrl, {
      headers: { Accept: "application/rdap+json, application/json" },
      signal: controller.signal,
    })
    if (!upstream.ok) {
      return json({ error: `RDAP lookup failed with HTTP ${upstream.status}` }, { status: 502 })
    }

    const payload = await upstream.json()
    const events = Array.isArray(payload?.events)
      ? payload.events
          .filter((event) =>
            /registration|registered|creation/i.test(String(event?.eventAction ?? "")),
          )
          .slice(0, 3)
          .map((event) => ({
            eventAction: String(event.eventAction ?? ""),
            eventDate: String(event.eventDate ?? ""),
          }))
      : []

    return json({ events }, { headers: { "Cache-Control": "no-store" } })
  } catch (error) {
    const timedOut = error instanceof Error && error.name === "AbortError"
    return json({ error: timedOut ? "RDAP lookup timed out" : "RDAP lookup failed" }, { status: 502 })
  } finally {
    clearTimeout(timeout)
  }
}
