import { afterEach, describe, expect, it, vi } from "vitest"

import { onRequestPost } from "./rdap.js"

afterEach(() => {
  vi.unstubAllGlobals()
})

describe("Cloudflare RDAP endpoint", () => {
  it("rejects invalid domains without calling upstream", async () => {
    const fetchMock = vi.fn()
    vi.stubGlobal("fetch", fetchMock)

    const response = await onRequestPost({
      request: new Request("https://messageloupe.com/api/rdap", {
        method: "POST",
        body: JSON.stringify({ domain: "not a domain" }),
      }),
    })

    expect(response.status).toBe(400)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it("returns only registration events for a valid domain", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          events: [
            { eventAction: "registration", eventDate: "2025-01-02T00:00:00Z" },
            { eventAction: "last changed", eventDate: "2026-01-02T00:00:00Z" },
          ],
          entities: [{ handle: "private-data-not-forwarded" }],
        }),
        { status: 200 },
      ),
    )
    vi.stubGlobal("fetch", fetchMock)

    const response = await onRequestPost({
      request: new Request("https://messageloupe.com/api/rdap", {
        method: "POST",
        body: JSON.stringify({ domain: "example.com" }),
      }),
    })

    expect(fetchMock).toHaveBeenCalledWith(
      "https://rdap.org/domain/example.com",
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    )
    expect(await response.json()).toEqual({
      events: [{ eventAction: "registration", eventDate: "2025-01-02T00:00:00Z" }],
    })
    expect(response.headers.get("Cache-Control")).toBe("no-store")
  })

  it("accepts a valid punycode top-level domain", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ events: [] }), { status: 200 }),
    )
    vi.stubGlobal("fetch", fetchMock)

    const response = await onRequestPost({
      request: new Request("https://messageloupe.com/api/rdap", {
        method: "POST",
        body: JSON.stringify({ domain: "example.xn--p1ai" }),
      }),
    })

    expect(response.status).toBe(200)
    expect(fetchMock).toHaveBeenCalledWith(
      "https://rdap.org/domain/example.xn--p1ai",
      expect.any(Object),
    )
  })

  it("does not expose upstream errors", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("private upstream detail")))

    const response = await onRequestPost({
      request: new Request("https://messageloupe.com/api/rdap", {
        method: "POST",
        body: JSON.stringify({ domain: "example.org" }),
      }),
    })

    expect(response.status).toBe(502)
    expect(await response.json()).toEqual({ error: "RDAP lookup failed" })
  })
})
