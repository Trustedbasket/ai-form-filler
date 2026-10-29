/** @type {import('next').NextConfig} */
const nextConfig = {
  // Generate static HTML/CSS/JS into the `out` directory
  output: 'export',

  // Required for static export since GitHub Pages has no Node.js image server
  images: {
    unoptimized: true,
  },

  // Maps routes like `/dashboard` to `/dashboard/index.html` to prevent 404s on page refresh
  trailingSlash: true,

  // Automatically set by GitHub Actions to `/<repo-name>` in production, or empty locally
  basePath: process.env.NEXT_PUBLIC_BASE_PATH || '',
  assetPrefix: process.env.NEXT_PUBLIC_BASE_PATH || '',
};

export default nextConfig;
