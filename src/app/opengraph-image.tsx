import { ImageResponse } from "next/og"

export const size = { width: 1200, height: 630 }
export const contentType = "image/png"
export const alt = "Message Loupe — is this email real?"
export const dynamic = "force-static"

// Generated at build time during `next build`; ships as a static PNG in
// the static export. No runtime cost, no edge function.

export default async function OpengraphImage() {
  // Load Geist Bold once for the headline. Inter is a close enough
  // fallback for the smaller body if Geist fetch ever fails.
  const [geistBold, geistRegular] = await Promise.all([
    fetch(
      "https://github.com/vercel/geist-font/raw/main/packages/next/dist/fonts/geist-sans/Geist-Bold.ttf",
    ).then((r) => (r.ok ? r.arrayBuffer() : null)),
    fetch(
      "https://github.com/vercel/geist-font/raw/main/packages/next/dist/fonts/geist-sans/Geist-Regular.ttf",
    ).then((r) => (r.ok ? r.arrayBuffer() : null)),
  ])

  const fonts = [
    geistBold && {
      name: "Geist",
      data: geistBold,
      weight: 700 as const,
      style: "normal" as const,
    },
    geistRegular && {
      name: "Geist",
      data: geistRegular,
      weight: 400 as const,
      style: "normal" as const,
    },
  ].filter(Boolean) as {
    name: string
    data: ArrayBuffer
    weight: 400 | 700
    style: "normal"
  }[]

  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "space-between",
          padding: "72px 80px",
          backgroundColor: "#F7F8FB",
          backgroundImage:
            "radial-gradient(ellipse 800px 500px at 80% 0%, rgba(56,88,176,0.10), transparent 70%)",
          fontFamily: "Geist, sans-serif",
          color: "#1A1F2E",
        }}
      >
        {/* Brand row */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 16,
          }}
        >
          <svg
            width="48"
            height="48"
            viewBox="0 0 24 24"
            fill="none"
            stroke="#3858B0"
            strokeWidth="2.4"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M3 7V5a2 2 0 0 1 2-2h2" />
            <path d="M17 3h2a2 2 0 0 1 2 2v2" />
            <path d="M21 17v2a2 2 0 0 1-2 2h-2" />
            <path d="M7 21H5a2 2 0 0 1-2-2v-2" />
            <circle cx="12" cy="12" r="3" />
            <path d="m16 16-1.9-1.9" />
          </svg>
          <span
            style={{
              fontSize: 32,
              fontWeight: 700,
              letterSpacing: "-0.02em",
            }}
          >
            Message Loupe
          </span>
        </div>

        {/* Headline + tagline */}
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            gap: 24,
          }}
        >
          <h1
            style={{
              fontSize: 104,
              fontWeight: 700,
              letterSpacing: "-0.035em",
              lineHeight: 1.02,
              margin: 0,
            }}
          >
            Is this email real?
          </h1>
          <p
            style={{
              fontSize: 32,
              fontWeight: 400,
              lineHeight: 1.35,
              color: "#4B5366",
              margin: 0,
              maxWidth: 920,
            }}
          >
            A free, browser-only second opinion. Drop a saved email, get a
            plain-English verdict. Nothing leaves your device.
          </p>
        </div>

        {/* Footer strip */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            fontSize: 22,
            color: "#6B7387",
          }}
        >
          <span style={{ fontWeight: 700, color: "#3858B0" }}>
            messageloupe.com
          </span>
          <span>by Babbitt &amp; Co.</span>
        </div>
      </div>
    ),
    {
      ...size,
      fonts,
    },
  )
}
