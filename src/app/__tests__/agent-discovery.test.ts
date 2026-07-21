import { existsSync, readFileSync } from "node:fs"
import { resolve } from "node:path"
import { describe, expect, it } from "vitest"

function readNormalized(path: string): string {
  return readFileSync(resolve(process.cwd(), path), "utf8").replace(/\r\n/g, "\n")
}

describe("agent discovery headers", () => {
  it("advertises existing description and documentation from the homepage", () => {
    const headers = readNormalized("public/_headers")

    expect(headers).toContain(
      [
        "/",
        '  Link: </llms.txt>; rel="service-desc"; type="text/plain", </methodology/>; rel="service-doc"; type="text/html"',
      ].join("\n"),
    )
    expect(headers).not.toContain('rel="api-catalog"')
  })
})

describe("robots policy", () => {
  it("allows search and AI input while reserving content from training", () => {
    expect(existsSync(resolve(process.cwd(), "src/app/robots.ts"))).toBe(false)

    const robots = readNormalized("src/app/robots.txt").trimEnd()
    expect(robots).toBe(
      [
        "User-Agent: *",
        "Content-Signal: search=yes, ai-input=yes, ai-train=no",
        "Allow: /",
        "",
        "Host: https://messageloupe.com",
        "Sitemap: https://messageloupe.com/sitemap.xml",
      ].join("\n"),
    )
  })
})
