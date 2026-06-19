const DOMAIN_LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
const DOMAIN_RE = new RegExp(`^(?=.{1,253}$)(?:${DOMAIN_LABEL}\\.)+(?!\\d+$)${DOMAIN_LABEL}$`)
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
    const upstream = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
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
