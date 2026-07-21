import { createHash } from "node:crypto"
import { existsSync, readFileSync } from "node:fs"
import { resolve } from "node:path"
import { describe, expect, it } from "vitest"

const skillDescription =
  "Guide a user to privately check a suspicious email with Message Loupe, preserve original headers, and interpret the result. Use when the user asks whether an email may be phishing, spoofed, or business email compromise."

function repoPath(path: string): string {
  return resolve(process.cwd(), path)
}

function readNormalized(path: string): string {
  return readFileSync(repoPath(path), "utf8").replace(/\r\n/g, "\n")
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

  it("serves the skills index and skill with explicit types and CORS", () => {
    const headers = readNormalized("public/_headers")

    expect(headers).toContain(
      [
        "/.well-known/agent-skills/index.json",
        "  Content-Type: application/json; charset=utf-8",
        "  Access-Control-Allow-Origin: *",
        "  Cache-Control: public, max-age=3600, must-revalidate",
      ].join("\n"),
    )
    expect(headers).toContain(
      [
        "/.well-known/agent-skills/review-suspicious-email/SKILL.md",
        "  Content-Type: text/markdown; charset=utf-8",
        "  Access-Control-Allow-Origin: *",
        "  Cache-Control: public, max-age=3600, must-revalidate",
      ].join("\n"),
    )
  })
})

describe("robots policy", () => {
  it("allows search and AI input while reserving content from training", () => {
    expect(existsSync(repoPath("src/app/robots.ts"))).toBe(false)

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

describe("Agent Skills discovery", () => {
  it("pins published skill bytes to LF across Windows checkouts", () => {
    expect(existsSync(repoPath(".gitattributes"))).toBe(true)

    const attributes = readNormalized(".gitattributes")
    expect(attributes).toContain(
      "public/.well-known/agent-skills/review-suspicious-email/SKILL.md text eol=lf",
    )
  })

  it("publishes one instruction-only skill with a matching SHA-256 digest", () => {
    const skillPath = "public/.well-known/agent-skills/review-suspicious-email/SKILL.md"
    const skillBytes = readFileSync(repoPath(skillPath))
    const skill = skillBytes.toString("utf8").replace(/\r\n/g, "\n")
    const digest = `sha256:${createHash("sha256").update(skillBytes).digest("hex")}`
    const index = JSON.parse(
      readFileSync(repoPath("public/.well-known/agent-skills/index.json"), "utf8"),
    )

    expect(index).toEqual({
      $schema: "https://schemas.agentskills.io/discovery/0.2.0/schema.json",
      skills: [
        {
          name: "review-suspicious-email",
          type: "skill-md",
          description: skillDescription,
          url: "/.well-known/agent-skills/review-suspicious-email/SKILL.md",
          digest,
        },
      ],
    })
    expect(skill.startsWith(`---\nname: review-suspicious-email\ndescription: ${skillDescription}\n---\n`)).toBe(
      true,
    )
    expect(skill).toContain("Do not ask the user to paste the email into the conversation")
    expect(skill).toContain("A regular forward is not sufficient")
    expect(skill).toContain("Never describe a verdict as a guarantee")
    expect(skill).not.toContain("scripts/")
  })
})
