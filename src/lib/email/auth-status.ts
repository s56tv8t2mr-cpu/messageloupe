// Shared mapping from raw SPF/DKIM/DMARC result strings to a coarse
// status. Used by the result-panel signal chip and by the under-the-hood
// AuthBadge so both surfaces interpret the same string the same way.

export type AuthStatus = "ok" | "warn" | "fail" | "unknown"

export function authResultStatus(value: string | null | undefined): AuthStatus {
  if (!value) return "unknown"
  const lower = value.toLowerCase()
  if (lower === "pass") return "ok"
  if (lower === "fail" || lower === "permerror") return "fail"
  if (
    lower === "softfail" ||
    lower === "neutral" ||
    lower === "temperror" ||
    lower === "none"
  ) {
    return "warn"
  }
  return "unknown"
}
