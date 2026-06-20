// Lightweight attachment detector.
//
// The toolkit's parser intentionally skips attachment bodies — analyst
// triage doesn't need them. For the consumer verdict, however, attachment
// presence is real evidence: phishing kits routinely deliver payloads as
// PDF/DOCX/HTM attachments (fake invoices, "offer letters," shared-doc
// lures), and the user should at minimum know an attachment exists.
//
// We don't decode or scan attachment contents — that would balloon the
// bundle and break the privacy promise's simplicity. We just enumerate
// filenames and content types from the MIME structure, by scanning for
// `Content-Disposition: attachment` blocks and adjacent headers.

import type { AttachmentInfo } from "./types"
import { decodeEncodedWords } from "./encodedWords.js"

// Extract a filename from a Content-Disposition or Content-Type header.
// Handles: filename="x.pdf", filename=x.pdf, name="x.pdf", filename*=UTF-8''x.pdf
function extractFilename(headerBlock: string): string | null {
  const quoted = headerBlock.match(/(?:filename|name)\s*=\s*"([^"]+)"/i)
  if (quoted?.[1]) return decodeEncodedWords(quoted[1])

  const unquoted = headerBlock.match(/(?:filename|name)\s*=\s*([^;\s]+)/i)
  if (unquoted?.[1]) return decodeEncodedWords(unquoted[1])

  // RFC 5987 extended form
  const extended = headerBlock.match(/filename\*\s*=\s*[^']*'[^']*'([^;\s]+)/i)
  if (extended?.[1]) {
    try {
      return decodeURIComponent(extended[1])
    } catch {
      return extended[1]
    }
  }

  return null
}

const ATTACHMENT_BLOCK_REGEX = /Content-Disposition:\s*attachment[^\r\n]*(?:\r?\n[ \t][^\r\n]*)*/gi
const PART_HEADER_REGEX = /(?:Content-Type|Content-Disposition):\s*[^\r\n]*(?:\r?\n[ \t][^\r\n]*)*/gi

function inferredContentType(filename: string): string {
  const extension = filename.toLowerCase().split(".").at(-1) ?? ""
  const imageTypes: Record<string, string> = {
    gif: "image/gif",
    jpeg: "image/jpeg",
    jpg: "image/jpeg",
    png: "image/png",
    svg: "image/svg+xml",
    webp: "image/webp",
  }
  return imageTypes[extension] ?? "application/octet-stream"
}

function unfoldedHeaderBlock(rawSource: string): string {
  const headerEnd = rawSource.search(/\r?\n\r?\n/)
  const headerBlock = headerEnd < 0 ? rawSource : rawSource.slice(0, headerEnd)
  return headerBlock.replace(/\r?\n[ \t]+/g, " ")
}

export function extractAttachments(rawSource: string): AttachmentInfo[] {
  if (!rawSource) return []

  const found: AttachmentInfo[] = []
  const seen = new Set<string>()

  // Strategy: walk Content-Disposition: attachment lines. For each, search
  // backwards within ~4 lines for an adjacent Content-Type header to pair
  // up the MIME type. Covers the common structure where a part header
  // block contains both Content-Type and Content-Disposition.
  for (const match of rawSource.matchAll(ATTACHMENT_BLOCK_REGEX)) {
    const block = match[0]
    const start = match.index ?? 0
    const filename = extractFilename(block)
    if (!filename) continue

    // Look at the ~500-char window before this Content-Disposition for a
    // Content-Type header in the same MIME part.
    const windowStart = Math.max(0, start - 500)
    const window = rawSource.slice(windowStart, start)
    const ctMatch = window.match(/Content-Type:\s*([a-z0-9._+-]+\/[a-z0-9._+-]+)/i)
    const contentType = ctMatch?.[1]?.toLowerCase() ?? "application/octet-stream"

    const key = `${filename}:${contentType}`
    if (seen.has(key)) continue
    seen.add(key)

    found.push({ filename, contentType })
  }

  // Also catch parts with `Content-Type: application/...; name="..."` and no
  // explicit Content-Disposition (older Outlook senders do this).
  for (const match of rawSource.matchAll(PART_HEADER_REGEX)) {
    const block = match[0]
    if (!/Content-Type/i.test(block)) continue
    const ctMatch = block.match(/Content-Type:\s*([a-z0-9._+-]+\/[a-z0-9._+-]+)/i)
    if (!ctMatch) continue
    const contentType = ctMatch[1].toLowerCase()
    // Skip text and multipart bodies — those aren't attachments.
    if (contentType.startsWith("text/")) continue
    if (contentType.startsWith("multipart/")) continue
    const filename = extractFilename(block)
    if (!filename) continue
    const key = `${filename}:${contentType}`
    if (seen.has(key)) continue
    seen.add(key)
    found.push({ filename, contentType })
  }

  // Proton's headers-only export lists files in X-Attached even though the
  // MIME parts are omitted. Preserve that evidence so image-only scams do
  // not look like clean, empty messages to the verdict engine.
  for (const line of unfoldedHeaderBlock(rawSource).split(/\r?\n/)) {
    const colon = line.indexOf(":")
    if (colon < 0 || line.slice(0, colon).trim().toLowerCase() !== "x-attached") {
      continue
    }
    const filename = decodeEncodedWords(line.slice(colon + 1).trim())
    if (!filename) continue
    const contentType = inferredContentType(filename)
    const key = `${filename}:${contentType}`
    if (seen.has(key)) continue
    seen.add(key)
    found.push({ filename, contentType })
  }

  return found
}
