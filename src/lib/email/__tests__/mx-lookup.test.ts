// Unit tests for mx-lookup.ts.
//
// These test the DNS-over-HTTPS lookup, response parsing, provider
// classification, cache de-dup, and error paths in isolation from the
// verdict engine. The verdict-engine integration is covered separately by
// verdict.test.ts; this file's job is to pin down the lookup module's own
// contract — including the deliberate "errors never escalate" property
// (status: 'error' on HTTP failure, NXDOMAIN, timeout, and parse failure).

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import {
  __resetMxCacheForTests,
  lookupMx,
  mxConflictsWithDelivery,
  type MxLookup,
} from "../mx-lookup"

interface MockDnsAnswer {
  name?: string
  type: number
  TTL?: number
  data: string
}

function mockDnsResponse(
  answers: MockDnsAnswer[],
  status = 0,
): Response {
  return new Response(JSON.stringify({ Status: status, Answer: answers }), {
    status: 200,
    headers: { "Content-Type": "application/dns-json" },
  })
}

const mxAnswer = (priority: number, host: string): MockDnsAnswer => ({
  type: 15,
  data: `${priority} ${host}.`,
})

beforeEach(() => {
  __resetMxCacheForTests()
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
  vi.useRealTimers()
})

describe("lookupMx — input validation", () => {
  it("returns null on null input", async () => {
    const result = await lookupMx(null)
    expect(result).toBeNull()
  })

  it("returns null on undefined input", async () => {
    const result = await lookupMx(undefined)
    expect(result).toBeNull()
  })

  it("returns null on empty string input", async () => {
    const result = await lookupMx("")
    expect(result).toBeNull()
  })
})

describe("lookupMx — DNS response parsing", () => {
  it("parses MX answers and strips the trailing dot from the host", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        mockDnsResponse([mxAnswer(10, "ASPMX.L.GOOGLE.COM")]),
      ),
    )
    const result = (await lookupMx("foo.com")) as MxLookup
    expect(result.status).toBe("done")
    expect(result.records).toHaveLength(1)
    expect(result.records[0].host).toBe("aspmx.l.google.com")
    expect(result.records[0].priority).toBe(10)
    expect(result.hosts).toEqual(["aspmx.l.google.com"])
  })

  it("sorts records by priority ascending", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        mockDnsResponse([
          mxAnswer(20, "alt2.aspmx.l.google.com"),
          mxAnswer(1, "aspmx.l.google.com"),
          mxAnswer(10, "alt1.aspmx.l.google.com"),
        ]),
      ),
    )
    const result = (await lookupMx("foo.com")) as MxLookup
    expect(result.hosts).toEqual([
      "aspmx.l.google.com",
      "alt1.aspmx.l.google.com",
      "alt2.aspmx.l.google.com",
    ])
  })

  it("lowercases hostnames", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(mockDnsResponse([mxAnswer(1, "MX.EXAMPLE.NET")])),
    )
    const result = (await lookupMx("FOO.COM")) as MxLookup
    expect(result.domain).toBe("foo.com")
    expect(result.hosts).toEqual(["mx.example.net"])
  })

  it("ignores non-MX answer records", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        mockDnsResponse([
          { type: 1, data: "203.0.113.10" },
          mxAnswer(10, "mx.example.com"),
          { type: 16, data: '"v=spf1 ..."' },
        ]),
      ),
    )
    const result = (await lookupMx("foo.com")) as MxLookup
    expect(result.hosts).toEqual(["mx.example.com"])
  })

  it("returns an empty record list when DNS has no MX answers", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(mockDnsResponse([])),
    )
    const result = (await lookupMx("foo.com")) as MxLookup
    expect(result.status).toBe("done")
    expect(result.records).toEqual([])
    expect(result.hosts).toEqual([])
    expect(result.provider).toBeNull()
  })
})

describe("lookupMx — provider classification", () => {
  it("Google MX → provider 'Google'", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        mockDnsResponse([
          mxAnswer(1, "aspmx.l.google.com"),
          mxAnswer(5, "alt1.aspmx.l.google.com"),
        ]),
      ),
    )
    const result = (await lookupMx("a.com")) as MxLookup
    expect(result.provider).toBe("Google")
  })

  it("Google Workspace googlemail.com alt → provider 'Google'", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          mockDnsResponse([mxAnswer(10, "aspmx3.googlemail.com")]),
        ),
    )
    const result = (await lookupMx("b.com")) as MxLookup
    expect(result.provider).toBe("Google")
  })

  it("Microsoft 365 MX → provider 'Microsoft 365'", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          mockDnsResponse([
            mxAnswer(10, "contoso-com.mail.protection.outlook.com"),
          ]),
        ),
    )
    const result = (await lookupMx("contoso.com")) as MxLookup
    expect(result.provider).toBe("Microsoft 365")
  })

  it("unknown host → provider null", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          mockDnsResponse([mxAnswer(10, "mx.acme-corp-private.example")]),
        ),
    )
    const result = (await lookupMx("acme.example")) as MxLookup
    expect(result.status).toBe("done")
    expect(result.provider).toBeNull()
  })

  it("bare google.com host (an A record host, not Google Workspace MX) → provider null", async () => {
    // Guards against the previous over-broad google.com pattern. A domain
    // listing "google.com" as its MX is not Google Workspace.
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(mockDnsResponse([mxAnswer(10, "google.com")])),
    )
    const result = (await lookupMx("strange.example")) as MxLookup
    expect(result.provider).toBeNull()
  })

  it("bare yahoo.com host → provider null (no longer broadly matched)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(mockDnsResponse([mxAnswer(10, "yahoo.com")])),
    )
    const result = (await lookupMx("strange.example")) as MxLookup
    expect(result.provider).toBeNull()
  })

  it("Yahoo MX (yahoodns.net) → provider 'Yahoo'", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          mockDnsResponse([mxAnswer(1, "mta5.am0.yahoodns.net")]),
        ),
    )
    const result = (await lookupMx("yahoo-hosted.example")) as MxLookup
    expect(result.provider).toBe("Yahoo")
  })
})

describe("lookupMx — caching", () => {
  it("de-duplicates concurrent calls for the same domain into one fetch", async () => {
    const fetchSpy = vi
      .fn()
      .mockResolvedValue(
        mockDnsResponse([mxAnswer(1, "aspmx.l.google.com")]),
      )
    vi.stubGlobal("fetch", fetchSpy)
    const [a, b] = await Promise.all([
      lookupMx("foo.com"),
      lookupMx("foo.com"),
    ])
    expect(fetchSpy).toHaveBeenCalledTimes(1)
    expect(a).toBe(b)
  })

  it("uses the cached result on subsequent calls", async () => {
    const fetchSpy = vi
      .fn()
      .mockResolvedValue(
        mockDnsResponse([mxAnswer(1, "aspmx.l.google.com")]),
      )
    vi.stubGlobal("fetch", fetchSpy)
    await lookupMx("foo.com")
    await lookupMx("foo.com")
    await lookupMx("FOO.COM")
    expect(fetchSpy).toHaveBeenCalledTimes(1)
  })
})

describe("lookupMx — error paths", () => {
  it("HTTP error → status 'error', provider null", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("bad gateway", { status: 502 })),
    )
    const result = (await lookupMx("foo.com")) as MxLookup
    expect(result.status).toBe("error")
    expect(result.provider).toBeNull()
    expect(result.hosts).toEqual([])
    expect(result.error).toContain("502")
  })

  it("DNS Status 3 (NXDOMAIN) → status 'error'", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(mockDnsResponse([], 3)),
    )
    const result = (await lookupMx("not-a-domain.example")) as MxLookup
    expect(result.status).toBe("error")
    expect(result.provider).toBeNull()
    expect(result.error).toContain("3")
  })

  it("DNS Status 2 (SERVFAIL) → status 'error'", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(mockDnsResponse([], 2)),
    )
    const result = (await lookupMx("servfail.example")) as MxLookup
    expect(result.status).toBe("error")
    expect(result.provider).toBeNull()
  })

  it("fetch rejection (network error) → status 'error'", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new Error("network down")),
    )
    const result = (await lookupMx("foo.com")) as MxLookup
    expect(result.status).toBe("error")
    expect(result.provider).toBeNull()
    expect(result.error).toBe("network down")
  })

  it("timeout (AbortSignal fires before fetch resolves) → status 'error'", async () => {
    vi.useFakeTimers()
    // Mock fetch as a hanging promise that rejects when its abort signal fires.
    // AbortSignal.timeout(3000) inside doLookup installs a real setTimeout
    // intercepted by vi.useFakeTimers; advancing past 3000ms triggers the abort.
    const fetchMock = vi.fn(
      (_url: string, opts: { signal?: AbortSignal }) =>
        new Promise<Response>((_resolve, reject) => {
          opts.signal?.addEventListener("abort", () => {
            reject(new DOMException("The operation timed out.", "TimeoutError"))
          })
        }),
    )
    vi.stubGlobal("fetch", fetchMock)
    const promise = lookupMx("slow.example")
    await vi.advanceTimersByTimeAsync(3001)
    const result = (await promise) as MxLookup
    expect(result.status).toBe("error")
    expect(result.provider).toBeNull()
  })
})

describe("mxConflictsWithDelivery", () => {
  const baseDone: MxLookup = {
    domain: "foo.com",
    hosts: ["aspmx.l.google.com"],
    records: [{ priority: 1, host: "aspmx.l.google.com" }],
    provider: "Google",
    status: "done",
  }

  it("returns false on null mx", () => {
    expect(mxConflictsWithDelivery(null, "SendGrid")).toBe(false)
  })

  it("returns false when status is not 'done'", () => {
    expect(
      mxConflictsWithDelivery({ ...baseDone, status: "error" }, "SendGrid"),
    ).toBe(false)
    expect(
      mxConflictsWithDelivery({ ...baseDone, status: "pending" }, "SendGrid"),
    ).toBe(false)
  })

  it("returns false when provider is null (unclassified host)", () => {
    expect(
      mxConflictsWithDelivery({ ...baseDone, provider: null }, "SendGrid"),
    ).toBe(false)
  })

  it("returns false when sendingService is null/undefined/empty", () => {
    expect(mxConflictsWithDelivery(baseDone, null)).toBe(false)
    expect(mxConflictsWithDelivery(baseDone, undefined)).toBe(false)
    expect(mxConflictsWithDelivery(baseDone, "")).toBe(false)
  })

  it("returns false when provider matches the delivering service (case-insensitive)", () => {
    expect(mxConflictsWithDelivery(baseDone, "Google")).toBe(false)
    expect(mxConflictsWithDelivery(baseDone, "google")).toBe(false)
    expect(mxConflictsWithDelivery(baseDone, "GOOGLE")).toBe(false)
  })

  it("returns true when provider differs from the delivering service", () => {
    expect(mxConflictsWithDelivery(baseDone, "SendGrid")).toBe(true)
    expect(
      mxConflictsWithDelivery(
        { ...baseDone, provider: "Microsoft 365" },
        "Mailchimp",
      ),
    ).toBe(true)
  })
})
