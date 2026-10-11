import type { NextConfig } from "next";

// Every page reads the session cookie, so every page is dynamic: Cache Components is left off.
// standalone builds the small server the Dockerfile runs.
const nextConfig: NextConfig = {
  output: "standalone",
};

export default nextConfig;
