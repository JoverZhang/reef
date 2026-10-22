import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  logging: false,
  outputFileTracingIncludes: { "/*": ["./generated/input.json", "./generated/runtime/**/*"] },
  async headers() {
    return [{ source: "/:path*", headers: [
      { key: "Cache-Control", value: "no-store" },
      { key: "Referrer-Policy", value: "no-referrer" },
      { key: "X-Robots-Tag", value: "noindex, nofollow, noarchive" },
    ] }];
  },
};

export default nextConfig;
