import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  env: {
    NEXT_PUBLIC_AUTH_API_URL: process.env.NEXT_PUBLIC_AUTH_API_URL || 'http://localhost:8001',
    NEXT_PUBLIC_CART_API_URL: process.env.NEXT_PUBLIC_CART_API_URL || 'http://localhost:8003',
    NEXT_PUBLIC_PRODUCT_API_URL: process.env.NEXT_PUBLIC_PRODUCT_API_URL || 'http://localhost:8004'
  }
};

export default nextConfig;
