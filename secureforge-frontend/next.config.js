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
      {
        source: '/ws/:path*',
        destination: `${process.env.INTERNAL_API_URL || 'http://bas-engine:8000'}/ws/:path*`,
      },
    ];
  },
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'Content-Security-Policy',
            value: "default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:; font-src 'self' data:; frame-ancestors 'none';"
          },
          {
            key: 'X-Frame-Options',
            value: 'DENY'
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff'
          }
        ],
      },
    ];
  },
};

module.exports = nextConfig;