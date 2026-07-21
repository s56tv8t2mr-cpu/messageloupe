import { readFileSync } from "node:fs"
import { resolve } from "node:path"
import { describe, expect, it } from "vitest"

describe("how to save an email page", () => {
  it("uses explicit JSX whitespace after the inline Gmail URL", () => {
    const source = readFileSync(
      resolve(process.cwd(), "src/app/how-to-save-an-email/page.tsx"),
      "utf8",
    )

    expect(source).toContain('<code>gmail.com</code>{" "}in your phone')
  })
})
