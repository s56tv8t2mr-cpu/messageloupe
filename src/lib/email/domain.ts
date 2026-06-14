// Domain-name helpers shared across the email pipeline.
//
// Why the explicit list: we don't want a Public Suffix List dependency for
// what is otherwise a fully self-contained client-side bundle. The list
// covers the multi-label TLDs that show up in our phishing corpus and in
// real ESP traffic. For a small set of country-code TLDs known to reserve
// common second-level labels, use a conservative heuristic so RDAP queries
// don't ask for the public suffix itself.

const KNOWN_MULTI_LABEL_SUFFIXES = [
  "com.au", "com.br", "com.cn", "com.co", "com.hk", "com.mx", "com.my",
  "com.ng", "com.sg", "com.tr", "com.vn",
  "co.jp", "co.kr", "co.nz", "co.uk", "co.za",
  "net.au", "org.au", "org.uk", "ac.uk", "gov.uk",
]

const COMMON_COUNTRY_CODE_SECOND_LEVELS = new Set([
  "ac",
  "co",
  "com",
  "edu",
  "gov",
  "net",
  "org",
])

const COUNTRY_CODE_TLDS_WITH_RESERVED_SECOND_LEVELS = new Set([
  "in",
])

export function registrableDomain(domain: string | null | undefined): string | null {
  if (!domain) return null
  const lower = domain.toLowerCase().replace(/\.$/, "")
  for (const suffix of KNOWN_MULTI_LABEL_SUFFIXES) {
    if (lower.endsWith(`.${suffix}`)) {
      const before = lower.slice(0, -suffix.length - 1)
      const lastLabel = before.split(".").pop()
      return lastLabel ? `${lastLabel}.${suffix}` : lower
    }
  }
  const labels = lower.split(".").filter(Boolean)
  const tld = labels.at(-1)
  const secondLevel = labels.at(-2)
  if (
    labels.length >= 3 &&
    tld?.length === 2 &&
    secondLevel !== undefined &&
    COUNTRY_CODE_TLDS_WITH_RESERVED_SECOND_LEVELS.has(tld) &&
    COMMON_COUNTRY_CODE_SECOND_LEVELS.has(secondLevel)
  ) {
    return labels.slice(-3).join(".")
  }
  return labels.slice(-2).join(".")
}

export function sameRegistrable(
  a: string | null | undefined,
  b: string | null | undefined,
): boolean {
  const ra = registrableDomain(a)
  const rb = registrableDomain(b)
  return ra !== null && ra === rb
}
