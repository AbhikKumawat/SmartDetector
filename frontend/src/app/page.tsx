"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { 
  ShieldAlert, 
  Search, 
  Terminal, 
  FileText, 
  CheckCircle, 
  AlertTriangle, 
  ArrowUpRight, 
  Flame,
  Activity,
  Layers
} from "lucide-react";
import { fetchDashboardMetrics, getPdfReportUrl, getJsonReportUrl } from "@/lib/api";
import { DashboardMetrics } from "@/lib/types";
import VulnerabilityChart from "@/components/VulnerabilityChart";

export default function DashboardPage() {
  const [data, setData] = useState<DashboardMetrics | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDashboardMetrics()
      .then((res) => setData(res))
      .catch((err) => console.error("Error loading dashboard metrics:", err))
      .finally(() => setLoading(false));
  }, []);

  const metrics = data?.metrics || {
    total_contracts_scanned: 0,
    total_vulnerabilities: 0,
    severity_distribution: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
  };

  const recentScans = data?.recent_scans || [];

  return (
    <div className="space-y-8">
      {/* Hero / Banner */}
      <div className="relative overflow-hidden rounded-2xl border border-cyber-800 bg-cyber-900/60 p-6 sm:p-8 backdrop-blur-sm">
        <div className="absolute top-0 right-0 -mr-16 -mt-16 w-64 h-64 rounded-full bg-sentinel-cyan/10 blur-3xl pointer-events-none"></div>
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
          <div className="space-y-2 max-w-2xl">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyber-800 border border-cyber-700 text-xs font-mono text-sentinel-cyan">
              <span className="w-2 h-2 rounded-full bg-sentinel-cyan animate-ping"></span>
              Real-time EVM Vulnerability Analysis
            </div>
            <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
              Smart Contract Security & Exploitation Lab
            </h1>
            <p className="text-slate-400 text-sm leading-relaxed">
              Scan Solidity contracts with Slither and custom AST heuristics. Reproduce confirmed exploits 
              in an isolated local Foundry sandbox with step-by-step transaction call traces.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <Link
              href="/scan"
              className="px-5 py-2.5 rounded-xl bg-sentinel-cyan text-cyber-950 font-bold text-sm hover:bg-cyan-300 transition-all flex items-center gap-2 shadow-lg shadow-cyan-500/20"
            >
              <Search className="w-4 h-4" />
              <span>Scan Contract</span>
            </Link>
            <Link
              href="/lab"
              className="px-5 py-2.5 rounded-xl bg-cyber-800 hover:bg-cyber-700 text-white font-medium text-sm border border-cyber-700 transition-all flex items-center gap-2"
            >
              <Terminal className="w-4 h-4 text-sentinel-cyan" />
              <span>Launch Lab</span>
            </Link>
          </div>
        </div>
      </div>

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1 */}
        <div className="p-5 rounded-xl border border-cyber-800 bg-cyber-900/60">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider">Contracts Audited</span>
            <Layers className="w-4 h-4 text-sentinel-cyan" />
          </div>
          <div className="text-3xl font-extrabold text-white font-mono">
            {metrics.total_contracts_scanned}
          </div>
          <p className="text-[11px] text-slate-500 font-mono mt-1">Foundry & static analysis runs</p>
        </div>

        {/* Card 2 */}
        <div className="p-5 rounded-xl border border-cyber-800 bg-cyber-900/60">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider">Vulnerabilities Found</span>
            <ShieldAlert className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-3xl font-extrabold text-white font-mono">
            {metrics.total_vulnerabilities}
          </div>
          <p className="text-[11px] text-slate-500 font-mono mt-1">Total AST & rule detections</p>
        </div>

        {/* Card 3 */}
        <div className="p-5 rounded-xl border border-cyber-800 bg-cyber-900/60">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider">Critical Threats</span>
            <Flame className="w-4 h-4 text-red-500" />
          </div>
          <div className="text-3xl font-extrabold text-red-400 font-mono">
            {metrics.severity_distribution.critical}
          </div>
          <p className="text-[11px] text-red-400/80 font-mono mt-1">High-risk capital drain vectors</p>
        </div>

        {/* Card 4 */}
        <div className="p-5 rounded-xl border border-cyber-800 bg-cyber-900/60">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider">Average Health Score</span>
            <CheckCircle className="w-4 h-4 text-sentinel-emerald" />
          </div>
          <div className="text-3xl font-extrabold text-sentinel-emerald font-mono">
            {recentScans.length > 0
              ? `${Math.round(
                  recentScans.reduce((acc, s) => acc + s.security_score, 0) / recentScans.length
                )}%`
              : "100%"}
          </div>
          <p className="text-[11px] text-slate-500 font-mono mt-1">Algorithmic risk evaluation</p>
        </div>
      </div>

      {/* Main Analytics Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Distribution */}
        <div className="p-6 rounded-2xl border border-cyber-800 bg-cyber-900/60 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Activity className="w-4 h-4 text-sentinel-cyan" /> Severity Breakdown
              </h3>
              <span className="text-xs font-mono text-slate-500">Live Breakdown</span>
            </div>
            <VulnerabilityChart severityCounts={metrics.severity_distribution} />
          </div>

          <div className="grid grid-cols-2 gap-2 mt-4 pt-4 border-t border-cyber-800 text-xs font-mono">
            <div className="flex items-center justify-between p-2 rounded bg-cyber-950">
              <span className="text-red-400 flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-red-500"></span> Critical
              </span>
              <span className="text-white font-bold">{metrics.severity_distribution.critical}</span>
            </div>
            <div className="flex items-center justify-between p-2 rounded bg-cyber-950">
              <span className="text-orange-400 flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-orange-500"></span> High
              </span>
              <span className="text-white font-bold">{metrics.severity_distribution.high}</span>
            </div>
            <div className="flex items-center justify-between p-2 rounded bg-cyber-950">
              <span className="text-amber-400 flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-amber-500"></span> Medium
              </span>
              <span className="text-white font-bold">{metrics.severity_distribution.medium}</span>
            </div>
            <div className="flex items-center justify-between p-2 rounded bg-cyber-950">
              <span className="text-blue-400 flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-blue-500"></span> Low
              </span>
              <span className="text-white font-bold">{metrics.severity_distribution.low}</span>
            </div>
          </div>
        </div>

        {/* Recent Scans Table */}
        <div className="lg:col-span-2 p-6 rounded-2xl border border-cyber-800 bg-cyber-900/60">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <FileText className="w-4 h-4 text-sentinel-cyan" /> Recent Security Scans
            </h3>
            <Link
              href="/scan"
              className="text-xs font-mono text-sentinel-cyan hover:underline flex items-center gap-1"
            >
              New Scan <ArrowUpRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          {recentScans.length === 0 ? (
            <div className="py-12 text-center text-slate-500 font-mono text-sm">
              <p>No scans performed yet.</p>
              <Link
                href="/scan"
                className="mt-3 inline-block px-4 py-2 rounded-lg bg-cyber-800 text-sentinel-cyan text-xs border border-cyber-700"
              >
                Scan Your First Solidity File
              </Link>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-cyber-800 text-slate-400">
                    <th className="pb-3 font-semibold">Target File</th>
                    <th className="pb-3 font-semibold">Findings</th>
                    <th className="pb-3 font-semibold">Health Score</th>
                    <th className="pb-3 font-semibold">Severity Counts</th>
                    <th className="pb-3 font-semibold text-right">Reports</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-cyber-800/60">
                  {recentScans.map((scan) => (
                    <tr key={scan.id} className="hover:bg-cyber-850/40 transition-colors">
                      <td className="py-3 font-semibold text-white">{scan.target_name}</td>
                      <td className="py-3 text-slate-300">{scan.total_findings} issues</td>
                      <td className="py-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                            scan.security_score >= 80
                              ? "bg-emerald-950 text-emerald-400 border border-emerald-800/40"
                              : scan.security_score >= 50
                              ? "bg-amber-950 text-amber-400 border border-amber-800/40"
                              : "bg-red-950 text-red-400 border border-red-800/40"
                          }`}
                        >
                          {scan.security_score}/100
                        </span>
                      </td>
                      <td className="py-3">
                        <div className="flex items-center gap-1.5 text-[10px]">
                          {scan.critical_count > 0 && (
                            <span className="px-1.5 py-0.2 rounded bg-red-950 text-red-400">
                              {scan.critical_count} Crit
                            </span>
                          )}
                          {scan.high_count > 0 && (
                            <span className="px-1.5 py-0.2 rounded bg-orange-950 text-orange-400">
                              {scan.high_count} High
                            </span>
                          )}
                          {scan.critical_count === 0 && scan.high_count === 0 && (
                            <span className="text-slate-500">None</span>
                          )}
                        </div>
                      </td>
                      <td className="py-3 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <a
                            href={getPdfReportUrl(scan.id)}
                            download
                            className="px-2 py-1 rounded bg-cyber-800 hover:bg-cyber-700 text-sentinel-cyan text-[11px] border border-cyber-700"
                          >
                            PDF
                          </a>
                          <a
                            href={getJsonReportUrl(scan.id)}
                            download
                            className="px-2 py-1 rounded bg-cyber-800 hover:bg-cyber-700 text-slate-300 text-[11px] border border-cyber-700"
                          >
                            JSON
                          </a>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Educational Notice Banner */}
      <div className="p-4 rounded-xl border border-sentinel-cyan/30 bg-sentinel-cyan/5 text-xs text-slate-300 flex items-start gap-3">
        <AlertTriangle className="w-4 h-4 text-sentinel-cyan shrink-0 mt-0.5" />
        <p>
          <strong className="text-sentinel-cyan">Security Auditor Note:</strong> Web3 Sentinel calculates 
          security metrics based on static AST pattern heuristics and Slither detectors. Scores reflect automated 
          checks and do not guarantee contract invulnerability against novel economic or multi-protocol attack vectors.
        </p>
      </div>
    </div>
  );
}
