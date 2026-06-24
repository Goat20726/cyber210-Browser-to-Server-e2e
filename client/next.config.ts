import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Catch all possible variations of the local network requests
  allowedDevOrigins: [
    '10.160.2.20', 
    '10.160.2.20:3000', 
    'localhost:3000', 
    '0.0.0.0', 
    '0.0.0.0:3000'
  ],
};

export default nextConfig;
