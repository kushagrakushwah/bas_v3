// src/app/layout.tsx
import type { Metadata } from "next";
import { AuthProvider } from "@/components/AuthProvider";
import "./globals.css";


export const metadata: Metadata = {
  title: "SecureForge BAS Console",
  description: "Enterprise Breach and Attack Simulation Environment",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="bg-background text-foreground antialiased min-h-screen">
        <AuthProvider>
          {children}
        </AuthProvider>
      </body>
    </html>
  );
}