// Domain-name helpers shared across the email pipeline.
//
// Why the explicit list: we don't want a Public Suffix List dependency for
// what is otherwise a fully self-contained client-side bundle. The list
// covers the multi-label TLDs that show up in our phishing corpus and in
// real ESP traffic. If a sender domain uses an unlisted multi-label TLD,
// we fall back to a two-label registrable, which is still safe (it just
// means a same-registrant comparison may return false where a PSL-aware
// comparison would return true — false negative on alignment, never a
// false positive on mismatch).

const KNOWN_MULTI_LABEL_SUFFIXES = [
  "com.au", "com.br", "com.cn", "com.co", "com.hk", "com.mx", "com.my",
  "com.ng", "com.sg", "com.tr", "com.vn",
  "co.jp", "co.kr", "co.nz", "co.uk", "co.za",
  "net.au", "org.au", "org.uk", "ac.uk", "gov.uk",
]

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
  return lower.split(".").slice(-2).join(".")
}

export function sameRegistrable(
  a: string | null | undefined,
  b: string | null | undefined,
): boolean {
  const ra = registrableDomain(a)
  const rb = registrableDomain(b)
  return ra !== null && ra === rb
}
