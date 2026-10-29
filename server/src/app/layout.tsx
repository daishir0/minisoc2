import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'minisoc2',
  description: '軽量SOC：サーバーの脆弱性とログを見守る',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="ja" className="h-full antialiased">
      <body className="min-h-full">{children}</body>
    </html>
  );
}
