import { ImageResponse } from "next/og"

export const size = { width: 1200, height: 630 }
export const contentType = "image/png"
export const alt = "Message Loupe: is this a fake email?"
export const dynamic = "force-static"

// Generated at build time during `next build`; ships as a static PNG in
// the static export. No runtime cost, no edge function.

export default async function OpengraphImage() {
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
          backgroundColor: "#0A0D16",
          backgroundImage:
            "radial-gradient(ellipse 900px 600px at 85% -10%, rgba(108,140,230,0.22), transparent 65%)",
        }}
      >
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "space-between",
          padding: "72px 80px",
          backgroundImage:
            "radial-gradient(ellipse 600px 400px at 0% 110%, rgba(108,140,230,0.08), transparent 60%)",
          fontFamily: "Geist, sans-serif",
          color: "#F4F6FA",
        }}
      >
        {/* Brand row */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 14,
          }}
        >
          <svg
            width="40"
            height="40"
            viewBox="0 0 24 24"
            fill="none"
            stroke="#7B9CF0"
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
              fontSize: 28,
              fontWeight: 700,
              letterSpacing: "-0.02em",
              color: "#E6E9F2",
            }}
          >
            Message Loupe
          </span>
        </div>

        {/* Verdict chip + headline + tagline */}
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            gap: 28,
          }}
        >
          <div style={{ display: "flex", alignItems: "center" }}>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                padding: "8px 14px",
                borderRadius: 999,
                backgroundColor: "rgba(247, 89, 89, 0.12)",
                border: "1px solid rgba(247, 89, 89, 0.32)",
                color: "#FF8A8A",
                fontSize: 18,
                fontWeight: 700,
                letterSpacing: "0.18em",
                textTransform: "uppercase",
              }}
            >
              Likely Fake
            </div>
          </div>
          <h1
            style={{
              fontSize: 112,
              fontWeight: 700,
              letterSpacing: "-0.04em",
              lineHeight: 1.0,
              margin: 0,
              color: "#FFFFFF",
            }}
          >
            Is this a fake email?
          </h1>
          <p
            style={{
              fontSize: 30,
              fontWeight: 400,
              lineHeight: 1.4,
              color: "#9AA3B8",
              margin: 0,
              maxWidth: 940,
            }}
          >
            Drop a saved email, get a plain-English verdict in seconds.
            Runs in your browser. Nothing leaves your device.
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
          <span style={{ fontWeight: 700, color: "#7B9CF0" }}>
            messageloupe.com
          </span>
          <span>by Babbitt &amp; Co.</span>
        </div>
      </div>
      </div>
    ),
    {
      ...size,
      fonts,
    },
  )
}
