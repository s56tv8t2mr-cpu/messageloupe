import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { __resetRdapCacheForTests, lookupRdapDomainAge } from "../rdap-lookup"

const registrationResponse = () =>
  new Response(
    JSON.stringify({
      events: [{ eventAction: "registration", eventDate: "2025-01-02T00:00:00Z" }],
    }),
    { status: 200 },
  )

const bootstrapResponse = () =>
  new Response(
    JSON.stringify({
      services: [
        [["com", "org"], ["https://rdap.registry.test/v1/"]],
      ],
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
  it("uses IANA to query the authoritative RDAP registry in Node", async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      if (String(input) === "https://data.iana.org/rdap/dns.json") {
        return Promise.resolve(bootstrapResponse())
      }
      return Promise.resolve(registrationResponse())
    })
    vi.stubGlobal("fetch", fetchMock)

    const result = await lookupRdapDomainAge("mail.example.com")

    expect(result?.status).toBe("done")
    expect(fetchMock).toHaveBeenCalledWith(
      "https://rdap.registry.test/v1/domain/example.com",
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    )
  })

  it("caches the IANA bootstrap across distinct Node lookups", async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      if (String(input) === "https://data.iana.org/rdap/dns.json") {
        return Promise.resolve(bootstrapResponse())
      }
      return Promise.resolve(registrationResponse())
    })
    vi.stubGlobal("fetch", fetchMock)

    await lookupRdapDomainAge("example.com")
    await lookupRdapDomainAge("example.org")

    const bootstrapCalls = fetchMock.mock.calls.filter(
      ([input]) => String(input) === "https://data.iana.org/rdap/dns.json",
    )
    expect(bootstrapCalls).toHaveLength(1)
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
      .mockResolvedValueOnce(bootstrapResponse())
      .mockResolvedValueOnce(registrationResponse())
    vi.stubGlobal("fetch", fetchMock)

    const result = await lookupRdapDomainAge("example.com")

    expect(result?.status).toBe("done")
    expect(fetchMock).toHaveBeenCalledTimes(3)
    expect(fetchMock.mock.calls[0][0]).toBe("/api/rdap")
    expect(fetchMock.mock.calls[1][0]).toBe("https://data.iana.org/rdap/dns.json")
    expect(fetchMock.mock.calls[2][0]).toBe(
      "https://rdap.registry.test/v1/domain/example.com",
    )
  })
})
