import type { MetadataRoute } from 'next';

// PWA manifest (served at /manifest.webmanifest). Android/Chrome use these icons for "Add to Home
// screen"; iOS uses app/apple-icon.png. Theme colour matches the app accent (#2557d6).
export default function manifest(): MetadataRoute.Manifest {
  return {
    name: 'minisoc2',
    short_name: 'minisoc2',
    description: 'Self-hosted Linux SOC — vulnerabilities, log threats and file integrity across your hosts.',
    start_url: '/',
    display: 'standalone',
    background_color: '#0f131a',
    theme_color: '#2557d6',
    icons: [
      { src: '/icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any' },
      { src: '/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any' },
      { src: '/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' },
    ],
  };
}
