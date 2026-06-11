import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { analyze } from "@/lib/email"
import { __resetMxCacheForTests } from "@/lib/email/mx-lookup"
import { authResults, buildEml } from "@/lib/email/__tests__/fixtures"
import {
  assertTeamReportMetadataOnly,
  createTeamReportMetadata,
} from "@/lib/team/report"

function mockFetchMxAnswer(): void {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ Status: 0, Answer: [] }), {
        status: 200,
        headers: { "Content-Type": "application/dns-json" },
      }),
    ),
  )
}

beforeEach(() => {
  __resetMxCacheForTests()
  mockFetchMxAnswer()
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe("team report metadata", () => {
  it("keeps dashboard records to metadata only", async () => {
    const analysis = await analyze(
      buildEml({
        from: "Accounts Payable <payables@example.com>",
        subject: "Secret invoice subject",
        authResults: authResults({ domain: "example.com" }),
        body:
          "Please wire money today. The private body text should never be stored. https://evil.example/pay",
      }),
    )

    const metadata = createTeamReportMetadata(analysis, {
      channel: "web-scanner",
      reportId: "report_123",
      reporterId: "user_456",
      organizationId: "org_789",
      createdAt: new Date("2026-05-25T12:00:00.000Z"),
    })

    expect(metadata).toMatchObject({
      schemaVersion: 1,
      reportId: "report_123",
      channel: "web-scanner",
      reporterId: "user_456",
      organizationId: "org_789",
      verdictTier: "danger",
      senderDomain: "example.com",
      riskFlags: {
        hasMoneyLanguage: true,
        hasWireTransferLure: true,
        linkCount: 1,
        suspiciousLinkCount: 1,
      },
      linkHosts: ["evil.example"],
    })

    const serialized = JSON.stringify(metadata)
    expect(serialized).not.toContain("Secret invoice subject")
    expect(serialized).not.toContain("private body text")
    expect(serialized).not.toContain("https://evil.example/pay")
    expect(serialized).not.toContain("payables@example.com")
    expect(serialized).not.toContain("Message-ID")
  })

  it("rejects raw email fields and full URLs", () => {
    expect(() =>
      assertTeamReportMetadataOnly({
        verdictTier: "caution",
        subject: "Do not store this",
      }),
    ).toThrow(/subject/)

    expect(() =>
      assertTeamReportMetadataOnly({
        linkHosts: ["https://evil.example/pay"],
      }),
    ).toThrow(/full URLs/)
  })
})
