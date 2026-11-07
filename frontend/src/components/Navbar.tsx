"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Shield, Terminal, Search, BookOpen, Activity, GitBranch } from "lucide-react";

export default function Navbar() {
  const pathname = usePathname();

  const links = [
    { href: "/", label: "Dashboard", icon: Activity },
    { href: "/scan", label: "Contract Scanner", icon: Search },
    { href: "/lab", label: "Exploitation Lab", icon: Terminal },
    { href: "/remediations", label: "Remediations", icon: BookOpen },
  ];

  return (
    <header className="sticky top-0 z-50 border-b border-cyber-800 bg-cyber-950/80 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Brand */}
        <Link href="/" className="flex items-center gap-3 group">
          <div className="p-2 rounded-lg bg-cyber-900 border border-cyber-700 group-hover:border-sentinel-cyan transition-colors">
            <Shield className="w-6 h-6 text-sentinel-cyan group-hover:scale-105 transition-transform" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-lg tracking-wider text-white">WEB3</span>
              <span className="font-bold text-lg tracking-wider text-sentinel-cyan">SENTINEL</span>
              <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-cyber-800 text-sentinel-emerald border border-sentinel-emerald/30">
                v1.0
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-mono hidden sm:block">Smart Contract Security Platform</p>
          </div>
        </Link>

        {/* Navigation */}
        <nav className="flex items-center gap-1 sm:gap-2">
          {links.map((link) => {
            const Icon = link.icon;
            const isActive = pathname === link.href;
            return (
              <Link
                key={link.href}
                href={link.href}
                className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-all ${
                  isActive
                    ? "bg-cyber-850 text-sentinel-cyan border border-sentinel-cyan/40 shadow-sm"
                    : "text-slate-300 hover:text-white hover:bg-cyber-900"
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? "text-sentinel-cyan" : "text-slate-400"}`} />
                <span>{link.label}</span>
              </Link>
            );
          })}
        </nav>

        {/* Engine Status Indicators */}
        <div className="hidden lg:flex items-center gap-3">
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-cyber-900 border border-cyber-800 text-xs font-mono">
            <span className="w-2 h-2 rounded-full bg-sentinel-emerald animate-pulse"></span>
            <span className="text-slate-300">Foundry:</span>
            <span className="text-sentinel-emerald">1.9.0</span>
          </div>

          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-cyber-900 border border-cyber-800 text-xs font-mono">
            <span className="w-2 h-2 rounded-full bg-sentinel-cyan animate-pulse"></span>
            <span className="text-slate-300">Slither:</span>
            <span className="text-sentinel-cyan">0.11.6</span>
          </div>
        </div>
      </div>
    </header>
  );
}
