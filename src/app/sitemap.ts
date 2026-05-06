import type { MetadataRoute } from "next"

export const dynamic = "force-static"

const SITE = "https://messageloupe.com"

export default function sitemap(): MetadataRoute.Sitemap {
  const lastModified = new Date()
  return [
    {
      url: `${SITE}/`,
      lastModified,
      changeFrequency: "weekly",
      priority: 1,
    },
    {
      url: `${SITE}/how-to-save-an-email`,
      lastModified,
      changeFrequency: "monthly",
      priority: 0.9,
    },
    {
      url: `${SITE}/methodology`,
      lastModified,
      changeFrequency: "monthly",
      priority: 0.7,
    },
    {
      url: `${SITE}/about`,
      lastModified,
      changeFrequency: "monthly",
      priority: 0.5,
    },
    {
      url: `${SITE}/privacy`,
      lastModified,
      changeFrequency: "yearly",
      priority: 0.4,
    },
  ]
}
