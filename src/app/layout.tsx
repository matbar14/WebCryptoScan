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
  title: "MrRobotQR 2.0 — сканер QR-кодов: ключи и сид-фразы",
  description:
    "Модернизированный веб-сканер MrRobotQR: каскадное декодирование QR-кодов (pyzbar, WeChatQRCode, OpenCV), офлайн-валидация WIF-ключей Bitcoin и BIP39 сид-фраз, отчёты TXT/JSON/CSV.",
  keywords: ["MrRobotQR", "QR", "Bitcoin", "BIP39", "seed phrase", "WIF", "security research"],
  icons: {
    icon: "https://z-cdn.chatglm.cn/z-ai/static/logo.svg",
  },
  openGraph: {
    title: "MrRobotQR 2.0 — сканер QR-кодов",
    description: "Каскадное декодирование QR-кодов, офлайн-валидация приватных ключей и сид-фраз",
    siteName: "MrRobotQR 2.0",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "MrRobotQR 2.0 — сканер QR-кодов",
    description: "Каскадное декодирование QR-кодов, офлайн-валидация ключей и сид-фраз",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="ru" suppressHydrationWarning>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-background text-foreground`}
      >
        {children}
        <Toaster />
      </body>
    </html>
  );
}
