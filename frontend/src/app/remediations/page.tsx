"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { 
  BookOpen, 
  ShieldCheck, 
  ShieldAlert, 
  Copy, 
  Check, 
  ArrowRight,
  Code
} from "lucide-react";
import { fetchSampleContracts } from "@/lib/api";
import { SampleContract } from "@/lib/types";

export default function RemediationsPage() {
  const [samples, setSamples] = useState<SampleContract[]>([]);
  const [activeTab, setActiveTab] = useState<string>("reentrancy");
  const [copiedType, setCopiedType] = useState<string | null>(null);

  useEffect(() => {
    fetchSampleContracts()
      .then((data) => {
        setSamples(data);
        if (data.length > 0) setActiveTab(data[0].id);
      })
      .catch((err) => console.error("Error loading remediation samples:", err));
  }, []);

  const current = samples.find((s) => s.id === activeTab);

  const handleCopy = (text: string, type: string) => {
    navigator.clipboard.writeText(text);
    setCopiedType(type);
    setTimeout(() => setCopiedType(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="pb-4 border-b border-cyber-800">
        <h1 className="text-2xl font-extrabold text-white flex items-center gap-2">
          <BookOpen className="w-6 h-6 text-sentinel-cyan" /> Vulnerability Remediation Encyclopedia
        </h1>
        <p className="text-xs text-slate-400 font-mono mt-1">
          Side-by-side comparative analysis of vulnerable Solidity patterns versus production-grade remediations
        </p>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-2 overflow-x-auto pb-2 scrollbar-none">
        {samples.map((s) => (
          <button
            key={s.id}
            onClick={() => setActiveTab(s.id)}
            className={`px-4 py-2 rounded-xl text-xs font-mono font-medium whitespace-nowrap transition-all border ${
              activeTab === s.id
                ? "bg-cyber-850 text-sentinel-cyan border-sentinel-cyan/50 shadow-sm"
                : "bg-cyber-900/60 text-slate-400 border-cyber-800 hover:text-white hover:bg-cyber-850"
            }`}
          >
            {s.name}
          </button>
        ))}
      </div>

      {/* Side-by-Side Comparison */}
      {current && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Vulnerable Contract Box */}
            <div className="rounded-xl border border-red-900/40 bg-cyber-950 overflow-hidden">
              <div className="px-4 py-3 bg-red-950/30 border-b border-red-900/40 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-red-400" />
                  <span className="text-xs font-mono font-bold text-red-400 uppercase tracking-wider">
                    Vulnerable Implementation
                  </span>
                </div>
                <button
                  onClick={() => handleCopy(current.vulnerable_code, "vuln")}
                  className="px-2 py-1 rounded bg-cyber-900 hover:bg-cyber-800 text-slate-400 hover:text-white text-[11px] font-mono flex items-center gap-1 border border-cyber-800"
                >
                  {copiedType === "vuln" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedType === "vuln" ? "Copied" : "Copy"}</span>
                </button>
              </div>
              <div className="p-4 max-h-[520px] overflow-y-auto font-mono text-xs text-red-200/90 leading-5 bg-cyber-950">
                <pre>{current.vulnerable_code}</pre>
              </div>
            </div>

            {/* Patched Contract Box */}
            <div className="rounded-xl border border-emerald-900/40 bg-cyber-950 overflow-hidden">
              <div className="px-4 py-3 bg-emerald-950/30 border-b border-emerald-900/40 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  <span className="text-xs font-mono font-bold text-emerald-400 uppercase tracking-wider">
                    Remediated Secure Implementation
                  </span>
                </div>
                <button
                  onClick={() => handleCopy(current.patched_code, "patch")}
                  className="px-2 py-1 rounded bg-cyber-900 hover:bg-cyber-800 text-slate-400 hover:text-white text-[11px] font-mono flex items-center gap-1 border border-cyber-800"
                >
                  {copiedType === "patch" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedType === "patch" ? "Copied" : "Copy"}</span>
                </button>
              </div>
              <div className="p-4 max-h-[520px] overflow-y-auto font-mono text-xs text-emerald-200/90 leading-5 bg-cyber-950">
                <pre>{current.patched_code}</pre>
              </div>
            </div>
          </div>

          {/* Remediation Action Link */}
          <div className="p-5 rounded-xl border border-cyber-800 bg-cyber-900/40 flex items-center justify-between">
            <div>
              <h4 className="text-sm font-bold text-white">Test this remediation in the Live Scanner</h4>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Scan both files in Monaco Editor to verify zero false positives on the patched contract.
              </p>
            </div>
            <Link
              href="/scan"
              className="px-4 py-2 rounded-lg bg-sentinel-cyan text-cyber-950 font-bold text-xs hover:bg-cyan-300 transition-colors flex items-center gap-1.5"
            >
              <span>Scan in Editor</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}
