/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  output: 'standalone',
  // Automatically handles rewrites to the FastAPI engine backend 
  // ensuring we map exactly to the logic found in dashboard_patch_fix.yaml
  async rewrites() {
    return [
      {
        source: '/api/bas-proxy/:path*',
        destination: `${process.env.API_URL || 'http://127.0.0.1:8000'}/api/v1/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;