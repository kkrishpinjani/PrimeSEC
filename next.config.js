const isProd = process.env.NODE_ENV === "production";

// Headers sent with every response. The CSP is deliberately limited to the directives that do not depend on how Next.js
// injects its own scripts (clickjacking, base tag, form targets, plugins), so it cannot break the app; a script-src policy
// would need a nonce set up and tested separately.
const securityHeaders = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=(), usb=()" },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
  { key: "Content-Security-Policy", value: "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'" },
  // Only meaningful over HTTPS, so only sent by a production build.
  ...(isProd ? [{ key: "Strict-Transport-Security", value: "max-age=15552000; includeSubDomains" }] : [])
];

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
  // The OpenTelemetry SDK is loaded from instrumentation.ts at runtime; keep it out of the webpack bundle.
  serverExternalPackages: [
    "@opentelemetry/sdk-node",
    "@opentelemetry/exporter-trace-otlp-http",
    "@opentelemetry/exporter-metrics-otlp-http",
    "@opentelemetry/sdk-metrics",
    "@opentelemetry/resources"
  ]
};
module.exports = nextConfig;
