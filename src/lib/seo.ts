import type { Metadata } from "next"

export const SITE_NAME = "Message Loupe"
export const SITE_URL = "https://messageloupe.com"

type PageMetadata = {
  title: string
  description: string
  path: `/${string}` | "/"
  keywords?: string[]
}

export function createPageMetadata({
  title,
  description,
  path,
  keywords,
}: PageMetadata): Metadata {
  const brandedTitle = `${title} | ${SITE_NAME}`

  return {
    title,
    description,
    alternates: { canonical: path },
    keywords,
    openGraph: {
      type: "website",
      siteName: SITE_NAME,
      title: brandedTitle,
      description,
      url: path,
      images: [
        {
          url: "/opengraph-image",
          width: 1200,
          height: 630,
          type: "image/png",
          alt: "Message Loupe: is this a fake email?",
        },
      ],
    },
    twitter: {
      card: "summary_large_image",
      title: brandedTitle,
      description,
      images: ["/opengraph-image"],
    },
  }
}
