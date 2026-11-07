"use client";

import { useState, useEffect } from "react";
import dynamic from "next/dynamic";
import { 
  Play, 
  Upload, 
  FileCode, 
  Download, 
  CheckCircle, 
  AlertTriangle, 
  RefreshCw, 
  Filter, 
  Shield 
} from "lucide-react";
import { 
  scanContractCode, 
  uploadContractFile, 
  fetchSampleContracts, 
  getPdfReportUrl, 
  getJsonReportUrl 
} from "@/lib/api";
import { ScanResponse, SampleContract, Severity } from "@/lib/types";
import FindingCard from "@/components/FindingCard";
import SeverityBadge from "@/components/SeverityBadge";

// Dynamic import Monaco Editor to avoid SSR hydration issues
const Editor = dynamic(() => import("@monaco-editor/react"), { ssr: false });

export default function ScanPage() {
  const [sourceCode, setSourceCode] = useState<string>("");
  const [filename, setFilename] = useState<string>("Contract.sol");
  const [samples, setSamples] = useState<SampleContract[]>([]);
  const [selectedSample, setSelectedSample] = useState<string>("");
  const [enableSlither, setEnableSlither] = useState<boolean>(true);
  const [enableCustomRules, setEnableCustomRules] = useState<boolean>(true);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanResult, setScanResult] = useState<ScanResponse | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<string>("ALL");

  useEffect(() => {
    fetchSampleContracts()
      .then((data) => {
        setSamples(data);
        if (data.length > 0) {
          // Default to Reentrancy sample
          setSelectedSample(data[0].id);
          setSourceCode(data[0].vulnerable_code);
          setFilename(data[0].name);
        }
      })
      .catch((err) => console.error("Error fetching samples:", err));
  }, []);

  const handleSelectSample = (sampleId: string) => {
    setSelectedSample(sampleId);
    const found = samples.find((s) => s.id === sampleId);
    if (found) {
      setSourceCode(found.vulnerable_code);
      setFilename(found.name);
      setScanResult(null);
      setErrorMsg(null);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setFilename(file.name);
    setErrorMsg(null);
    setIsScanning(true);

    try {
      const res = await uploadContractFile(file, enableSlither, enableCustomRules);
      setScanResult(res);
      // Read file content for the editor
      const text = await file.text();
      setSourceCode(text);
    } catch (err: any) {
      setErrorMsg(err.message || "File scan failed");
    } finally {
      setIsScanning(false);
    }
  };

  const handleRunScan = async () => {
    if (!sourceCode.trim()) {
      setErrorMsg("Please provide Solidity source code to analyze.");
      return;
    }

    setIsScanning(true);
    setErrorMsg(null);

    try {
      const res = await scanContractCode(sourceCode, filename, enableSlither, enableCustomRules);
      setScanResult(res);
    } catch (err: any) {
      setErrorMsg(err.message || "Contract scan failed");
    } finally {
      setIsScanning(false);
    }
  };

  const findings = scanResult?.findings || [];
  const filteredFindings = findings.filter((f) => {
    if (filterSeverity === "ALL") return true;
    return f.severity.toUpperCase() === filterSeverity.toUpperCase();
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 border-b border-cyber-800">
        <div>
          <h1 className="text-2xl font-extrabold text-white flex items-center gap-2">
            <Shield className="w-6 h-6 text-sentinel-cyan" /> Smart Contract Vulnerability Scanner
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Static AST analysis, Slither detectors, and vulnerability classification
          </p>
        </div>

        {/* Toolbar Controls */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Sample Templates Dropdown */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 font-mono">Template:</span>
            <select
              value={selectedSample}
              onChange={(e) => handleSelectSample(e.target.value)}
              className="bg-cyber-900 border border-cyber-700 text-xs font-mono rounded-lg px-3 py-1.5 text-white focus:outline-none focus:border-sentinel-cyan"
            >
              {samples.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name} ({s.category})
                </option>
              ))}
            </select>
          </div>

          {/* Upload Button */}
          <label className="cursor-pointer px-3 py-1.5 rounded-lg bg-cyber-850 hover:bg-cyber-800 text-xs font-mono text-slate-300 border border-cyber-700 flex items-center gap-1.5 transition-colors">
            <Upload className="w-3.5 h-3.5 text-sentinel-cyan" />
            <span>Upload .sol</span>
            <input
              type="file"
              accept=".sol"
              onChange={handleFileUpload}
              className="hidden"
            />
          </label>

          {/* Scan Action */}
          <button
            onClick={handleRunScan}
            disabled={isScanning}
            className="px-5 py-2 rounded-lg bg-sentinel-cyan text-cyber-950 font-bold text-xs hover:bg-cyan-300 transition-all flex items-center gap-2 disabled:opacity-50 shadow-md shadow-cyan-500/20"
          >
            {isScanning ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>Auditing AST...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Analyze Contract</span>
              </>
            )}
          </button>
        </div>
      </div>

      {errorMsg && (
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-800/50 text-red-300 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Editor & Scan Panel Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Monaco Code Editor (7 cols) */}
        <div className="lg:col-span-7 flex flex-col rounded-xl border border-cyber-800 bg-cyber-950 overflow-hidden shadow-2xl">
          <div className="px-4 py-2.5 bg-cyber-900 border-b border-cyber-800 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FileCode className="w-4 h-4 text-sentinel-cyan" />
              <input
                type="text"
                value={filename}
                onChange={(e) => setFilename(e.target.value)}
                className="bg-transparent border-b border-transparent hover:border-cyber-700 text-xs font-mono text-white focus:outline-none focus:border-sentinel-cyan px-1 py-0.5"
              />
            </div>
            <div className="flex items-center gap-3 text-[11px] font-mono text-slate-400">
              <label className="flex items-center gap-1 cursor-pointer">
                <input
                  type="checkbox"
                  checked={enableSlither}
                  onChange={(e) => setEnableSlither(e.target.checked)}
                  className="rounded border-cyber-700 bg-cyber-800 text-sentinel-cyan focus:ring-0"
                />
                <span>Slither</span>
              </label>
              <label className="flex items-center gap-1 cursor-pointer">
                <input
                  type="checkbox"
                  checked={enableCustomRules}
                  onChange={(e) => setEnableCustomRules(e.target.checked)}
                  className="rounded border-cyber-700 bg-cyber-800 text-sentinel-cyan focus:ring-0"
                />
                <span>Custom Rules</span>
              </label>
            </div>
          </div>

          <div className="h-[560px]">
            <Editor
              height="100%"
              defaultLanguage="sol"
              language="sol"
              theme="vs-dark"
              value={sourceCode}
              onChange={(val) => setSourceCode(val || "")}
              options={{
                minimap: { enabled: false },
                fontSize: 13,
                fontFamily: "JetBrains Mono, monospace",
                lineNumbers: "on",
                scrollBeyondLastLine: false,
                automaticLayout: true,
                renderLineHighlight: "all",
              }}
            />
          </div>
        </div>

        {/* Right Column: Scan Findings & Audit Score (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          {scanResult ? (
            <>
              {/* Summary Card */}
              <div className="p-5 rounded-xl border border-cyber-800 bg-cyber-900/80 space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-bold text-white">Security Health Score</h3>
                    <p className="text-[11px] text-slate-400 font-mono mt-0.5">
                      Analyzed in {scanResult.summary.execution_time_ms} ms
                    </p>
                  </div>
                  <div
                    className={`text-2xl font-mono font-extrabold px-3 py-1 rounded-lg border ${
                      scanResult.summary.security_score >= 80
                        ? "bg-emerald-950/60 text-emerald-400 border-emerald-800/50"
                        : scanResult.summary.security_score >= 50
                        ? "bg-amber-950/60 text-amber-400 border-amber-800/50"
                        : "bg-red-950/60 text-red-400 border-red-800/50"
                    }`}
                  >
                    {scanResult.summary.security_score}/100
                  </div>
                </div>

                {/* Severity Counters */}
                <div className="grid grid-cols-4 gap-2 text-center text-xs font-mono">
                  <div className="p-2 rounded bg-cyber-950 border border-cyber-800">
                    <span className="block text-red-400 font-bold">{scanResult.summary.critical_count}</span>
                    <span className="text-[10px] text-slate-400">CRIT</span>
                  </div>
                  <div className="p-2 rounded bg-cyber-950 border border-cyber-800">
                    <span className="block text-orange-400 font-bold">{scanResult.summary.high_count}</span>
                    <span className="text-[10px] text-slate-400">HIGH</span>
                  </div>
                  <div className="p-2 rounded bg-cyber-950 border border-cyber-800">
                    <span className="block text-amber-400 font-bold">{scanResult.summary.medium_count}</span>
                    <span className="text-[10px] text-slate-400">MED</span>
                  </div>
                  <div className="p-2 rounded bg-cyber-950 border border-cyber-800">
                    <span className="block text-blue-400 font-bold">{scanResult.summary.low_count}</span>
                    <span className="text-[10px] text-slate-400">LOW</span>
                  </div>
                </div>

                {/* Download Audit Reports */}
                <div className="flex items-center gap-2 pt-2 border-t border-cyber-800">
                  <a
                    href={getPdfReportUrl(scanResult.scan_id)}
                    download
                    className="flex-1 py-2 rounded-lg bg-cyber-800 hover:bg-cyber-700 text-sentinel-cyan text-xs font-mono font-semibold border border-cyber-700 flex items-center justify-center gap-1.5 transition-colors"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Download PDF Audit</span>
                  </a>
                  <a
                    href={getJsonReportUrl(scanResult.scan_id)}
                    download
                    className="flex-1 py-2 rounded-lg bg-cyber-800 hover:bg-cyber-700 text-slate-300 text-xs font-mono font-semibold border border-cyber-700 flex items-center justify-center gap-1.5 transition-colors"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Export JSON</span>
                  </a>
                </div>
              </div>

              {/* Findings Filter Bar */}
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-slate-400">
                  Showing {filteredFindings.length} of {findings.length} findings:
                </span>
                <div className="flex items-center gap-1">
                  {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
                    <button
                      key={sev}
                      onClick={() => setFilterSeverity(sev)}
                      className={`px-2 py-0.5 rounded text-[10px] transition-colors ${
                        filterSeverity === sev
                          ? "bg-sentinel-cyan/20 text-sentinel-cyan font-bold border border-sentinel-cyan/40"
                          : "text-slate-400 hover:text-white"
                      }`}
                    >
                      {sev}
                    </button>
                  ))}
                </div>
              </div>

              {/* Findings List */}
              <div className="max-h-[380px] overflow-y-auto pr-1">
                {filteredFindings.length === 0 ? (
                  <div className="p-8 text-center rounded-xl bg-cyber-900/40 border border-cyber-800 text-slate-500 font-mono text-xs">
                    {findings.length === 0 ? (
                      <div className="flex flex-col items-center gap-2">
                        <CheckCircle className="w-8 h-8 text-sentinel-emerald" />
                        <span className="text-white font-semibold text-sm">No Vulnerabilities Detected</span>
                        <span className="text-slate-400 text-xs">Contract passed all static analysis rules</span>
                      </div>
                    ) : (
                      <span>No findings matching the selected filter</span>
                    )}
                  </div>
                ) : (
                  filteredFindings.map((finding, idx) => (
                    <FindingCard key={finding.id} finding={finding} index={idx + 1} />
                  ))
                )}
              </div>
            </>
          ) : (
            <div className="h-full flex flex-col items-center justify-center p-8 rounded-xl border border-cyber-800 bg-cyber-900/40 text-center font-mono text-xs text-slate-400">
              <Shield className="w-12 h-12 text-cyber-700 mb-3" />
              <h4 className="text-white font-semibold text-sm mb-1">Ready for Security Analysis</h4>
              <p className="max-w-xs text-slate-500 leading-relaxed mb-4">
                Choose a vulnerable template or paste Solidity source code and click "Analyze Contract" to inspect AST rules and Slither detectors.
              </p>
              <button
                onClick={handleRunScan}
                className="px-4 py-2 rounded-lg bg-cyber-800 hover:bg-cyber-700 text-sentinel-cyan border border-cyber-700 text-xs transition-colors"
              >
                Start Quick Scan
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
