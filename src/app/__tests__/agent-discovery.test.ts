import { createHash } from "node:crypto"
import { existsSync, readFileSync, readdirSync } from "node:fs"
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

function headerRule(headers: string, path: string): string | undefined {
  const escapedPath = path.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
  const match = headers.match(new RegExp(`(?:^|\\n)${escapedPath}\\n((?:  [^\\n]+(?:\\n|$))*)`))

  return match?.[1].trimEnd()
}

describe("agent discovery headers", () => {
  it("advertises existing description and documentation from the homepage", () => {
    const headers = readNormalized("public/_headers")

    expect(headerRule(headers, "/")).toBe(
      '  Link: </llms.txt>; rel="service-desc"; type="text/plain", </methodology/>; rel="service-doc"; type="text/html"',
    )
    expect(headers).not.toContain('rel="api-catalog"')
  })

  it("serves the skills index and skill with explicit types and CORS", () => {
    const headers = readNormalized("public/_headers")

    expect(headerRule(headers, "/.well-known/agent-skills/index.json")).toBe(
      [
        "  Content-Type: application/json; charset=utf-8",
        "  Access-Control-Allow-Origin: *",
        "  Cache-Control: public, max-age=3600, must-revalidate",
      ].join("\n"),
    )
    expect(headerRule(headers, "/.well-known/agent-skills/review-suspicious-email/SKILL.md")).toBe(
      [
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
    expect(readdirSync(repoPath("public/.well-known/agent-skills/review-suspicious-email"), { recursive: true })).toEqual([
      "SKILL.md",
    ])
    expect(skill).not.toMatch(/^#!/m)
    expect(skill).not.toMatch(
      /^```(?:shell|sh|bash|zsh|fish|powershell|pwsh|ps1|javascript|js|jsx|node|nodejs|typescript|ts|tsx|python|py)\b/im,
    )
  })
})
