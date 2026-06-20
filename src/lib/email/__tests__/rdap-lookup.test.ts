import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { __resetRdapCacheForTests, lookupRdapDomainAge } from "../rdap-lookup"

const registrationResponse = () =>
  new Response(
    JSON.stringify({
      events: [{ eventAction: "registration", eventDate: "2025-01-02T00:00:00Z" }],
    }),
    { status: 200 },
  )

beforeEach(() => {
  __resetRdapCacheForTests()
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe("RDAP runtime routing", () => {
  it("uses an absolute public RDAP URL in Node", async () => {
    const fetchMock = vi.fn().mockResolvedValue(registrationResponse())
    vi.stubGlobal("fetch", fetchMock)

    const result = await lookupRdapDomainAge("mail.example.com")

    expect(result?.status).toBe("done")
    expect(fetchMock).toHaveBeenCalledWith(
      "https://rdap.org/domain/example.com",
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    )
  })

  it("uses the same-origin endpoint in a hosted browser", async () => {
    vi.stubGlobal("window", { location: { hostname: "messageloupe.com" } })
    vi.stubGlobal("process", undefined)
    const fetchMock = vi.fn().mockResolvedValue(registrationResponse())
    vi.stubGlobal("fetch", fetchMock)

    const result = await lookupRdapDomainAge("example.com")

    expect(result?.status).toBe("done")
    expect(fetchMock).toHaveBeenCalledOnce()
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/rdap",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ domain: "example.com" }),
      }),
    )
  })

  it("uses the same-origin endpoint inside a production Web Worker", async () => {
    vi.stubGlobal("window", undefined)
    vi.stubGlobal("process", undefined)
    const fetchMock = vi.fn().mockResolvedValue(registrationResponse())
    vi.stubGlobal("fetch", fetchMock)

    const result = await lookupRdapDomainAge("example.com")

    expect(result?.status).toBe("done")
    expect(fetchMock).toHaveBeenCalledOnce()
    expect(fetchMock.mock.calls[0][0]).toBe("/api/rdap")
  })

  it("falls back to public RDAP when a static host has no endpoint", async () => {
    vi.stubGlobal("window", { location: { hostname: "localhost" } })
    vi.stubGlobal("process", undefined)
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response(null, { status: 404 }))
      .mockResolvedValueOnce(registrationResponse())
    vi.stubGlobal("fetch", fetchMock)

    const result = await lookupRdapDomainAge("example.com")

    expect(result?.status).toBe("done")
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(fetchMock.mock.calls[0][0]).toBe("/api/rdap")
    expect(fetchMock.mock.calls[1][0]).toBe("https://rdap.org/domain/example.com")
  })
})
