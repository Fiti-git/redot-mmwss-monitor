import type { Metadata } from "next";
import "./globals.css";
import { SessionProvider } from "@/components/session-provider";

export const metadata: Metadata = {
  title: "MMWSS — Redot Global",
  description: "Internal security & uptime monitoring for MMWSS Cloudflare-protected sites",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="h-full bg-white">
      <body className="h-full antialiased">
        <SessionProvider>{children}</SessionProvider>
      </body>
    </html>
  );
}
