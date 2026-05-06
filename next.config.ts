import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Fully static export — every route prerenders to HTML in `out/`.
  // Lets Message Loupe ship to any static host (Netlify today, FTP/Cloudflare
  // Pages later) without code changes.
  output: "export",
  // Required when using `output: 'export'` if next/image is ever used.
  images: { unoptimized: true },
  // Trailing slashes give us cleaner URLs on static hosts that map to
  // <path>/index.html instead of <path>.html.
  trailingSlash: true,
};

export default nextConfig;
