import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Toaster } from "@/components/ui/toaster";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "WebCryptoScan — сканер QR-кодов: ключи и сид-фразы",
  description:
    "Веб-сканер WebCryptoScan: каскадное декодирование QR-кодов (pyzbar, WeChatQRCode, OpenCV), офлайн-валидация приватных ключей, BIP39 сид-фраз и мультивалютных адресов (BTC, ETH, LTC, DOGE, DASH, BCH, XRP, TRX, SOL), отчёты TXT/JSON/CSV.",
  keywords: ["WebCryptoScan", "QR", "Bitcoin", "BIP39", "seed phrase", "WIF", "security research"],
  icons: {
    icon: [
      { url: "/logo.svg", type: "image/svg+xml" },
      { url: "/favicon-32.png", sizes: "32x32", type: "image/png" },
    ],
    apple: "/apple-touch-icon.png",
  },
  openGraph: {
    title: "WebCryptoScan — сканер QR-кодов",
    description: "Каскадное декодирование QR-кодов, офлайн-валидация приватных ключей и сид-фраз",
    siteName: "WebCryptoScan",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "WebCryptoScan — сканер QR-кодов",
    description: "Каскадное декодирование QR-кодов, офлайн-валидация ключей и сид-фраз",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="ru" className="dark" suppressHydrationWarning>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-background text-foreground`}
      >
        {children}
        <Toaster />
      </body>
    </html>
  );
}
