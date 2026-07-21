import { createHash } from "node:crypto"
import { mkdir, readFile, writeFile } from "node:fs/promises"
import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const skillDescription =
  "Guide a user to privately check a suspicious email with Message Loupe, preserve original headers, and interpret the result. Use when the user asks whether an email may be phishing, spoofed, or business email compromise."
const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const skillsRoot = resolve(projectRoot, "public/.well-known/agent-skills")
const skillPath = resolve(skillsRoot, "review-suspicious-email/SKILL.md")
const indexPath = resolve(skillsRoot, "index.json")

const skillBytes = await readFile(skillPath)
const digest = `sha256:${createHash("sha256").update(skillBytes).digest("hex")}`
const index = {
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
}

await mkdir(dirname(indexPath), { recursive: true })
await writeFile(indexPath, `${JSON.stringify(index, null, 2)}\n`, "utf8")
console.log(`Wrote ${indexPath} with ${digest}`)
