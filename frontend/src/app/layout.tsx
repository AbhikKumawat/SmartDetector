import type { Metadata } from "next";
import Navbar from "@/components/Navbar";
import "./globals.css";

export const metadata: Metadata = {
  title: "Web3 Sentinel | Smart Contract Security & Exploitation Lab",
  description: "Production-grade smart contract vulnerability analysis, controlled exploit reproduction, and automated security audit report generator.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-cyber-950 text-slate-100 flex flex-col bg-grid-pattern antialiased">
        <Navbar />
        <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {children}
        </main>
        <footer className="border-t border-cyber-800 bg-cyber-950 py-6 text-center text-xs font-mono text-slate-500">
          <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-4">
            <p>WEB3 SENTINEL © 2026 • Production Smart Contract Security Research</p>
            <div className="flex items-center gap-4 text-slate-400">
              <span>Foundry Lab</span>
              <span>•</span>
              <span>Slither AST</span>
              <span>•</span>
              <span>Automated Audit Reports</span>
            </div>
          </div>
        </footer>
      </body>
    </html>
  );
}
