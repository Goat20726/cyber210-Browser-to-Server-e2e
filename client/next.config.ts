import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Hardcode the exact IP the error message is complaining about
  allowedDevOrigins: ['10.160.2.20','0.0.0.0'], 
};

export default nextConfig;
