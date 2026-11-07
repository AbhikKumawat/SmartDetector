"use client";

import { useState, useEffect } from "react";
import { 
  Terminal, 
  Play, 
  ShieldCheck, 
  ShieldAlert, 
  Flame, 
  RefreshCw, 
  Clock, 
  Layers, 
  CheckCircle2, 
  AlertOctagon,
  ArrowRight
} from "lucide-react";
import { fetchLabScenarios, runExploitLab } from "@/lib/api";
import { LabScenario, ExploitLabRunResponse } from "@/lib/types";
import TraceViewer from "@/components/TraceViewer";

export default function LabPage() {
  const [scenarios, setScenarios] = useState<LabScenario[]>([]);
  const [selectedLabId, setSelectedLabId] = useState<string>("reentrancy");
  const [targetType, setTargetType] = useState<"vulnerable" | "patched">("vulnerable");
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [result, setResult] = useState<ExploitLabRunResponse | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    fetchLabScenarios()
      .then((data) => {
        setScenarios(data);
        if (data.length > 0) {
          setSelectedLabId(data[0].lab_id);
        }
      })
      .catch((err) => console.error("Error loading lab scenarios:", err));
  }, []);

  const currentScenario = scenarios.find((s) => s.lab_id === selectedLabId);

  const handleExecute = async () => {
    setIsRunning(true);
    setErrorMsg(null);

    try {
      const res = await runExploitLab(selectedLabId, targetType);
      setResult(res);
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to execute exploit in Foundry sandbox");
    } finally {
      setIsRunning(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 border-b border-cyber-800">
        <div>
          <h1 className="text-2xl font-extrabold text-white flex items-center gap-2">
            <Terminal className="w-6 h-6 text-sentinel-cyan" /> Controlled Exploitation Lab
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Sandboxed Foundry EVM test environment demonstrating real exploits vs verified patches
          </p>
        </div>

        {/* Execution Mode & Trigger */}
        <div className="flex items-center gap-3">
          {/* Target Mode Toggle */}
          <div className="flex items-center rounded-xl bg-cyber-900 p-1 border border-cyber-800 text-xs font-mono">
            <button
              onClick={() => {
                setTargetType("vulnerable");
                setResult(null);
              }}
              className={`px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition-all ${
                targetType === "vulnerable"
                  ? "bg-red-500/20 text-red-400 font-bold border border-red-500/40 shadow-sm"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              <span>Vulnerable Mode</span>
            </button>
            <button
              onClick={() => {
                setTargetType("patched");
                setResult(null);
              }}
              className={`px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition-all ${
                targetType === "patched"
                  ? "bg-emerald-500/20 text-emerald-400 font-bold border border-emerald-500/40 shadow-sm"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>Patched Mode</span>
            </button>
          </div>

          {/* Run Exploit Action */}
          <button
            onClick={handleExecute}
            disabled={isRunning}
            className={`px-5 py-2.5 rounded-xl font-bold text-xs flex items-center gap-2 transition-all shadow-lg ${
              targetType === "vulnerable"
                ? "bg-red-500 hover:bg-red-400 text-white shadow-red-500/20"
                : "bg-sentinel-emerald hover:bg-emerald-400 text-cyber-950 shadow-emerald-500/20"
            } disabled:opacity-50`}
          >
            {isRunning ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Simulating EVM...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-current" />
                <span>
                  {targetType === "vulnerable" ? "Execute Exploit PoC" : "Verify Patch Defense"}
                </span>
              </>
            )}
          </button>
        </div>
      </div>

      {errorMsg && (
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-800/50 text-red-300 text-xs flex items-center gap-2">
          <AlertOctagon className="w-4 h-4 text-red-400 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Lab Scenarios Navigation Tabs */}
      <div className="flex items-center gap-2 overflow-x-auto pb-2 scrollbar-none">
        {scenarios.map((sc) => (
          <button
            key={sc.lab_id}
            onClick={() => {
              setSelectedLabId(sc.lab_id);
              setResult(null);
            }}
            className={`px-4 py-2 rounded-xl text-xs font-mono font-medium whitespace-nowrap transition-all border ${
              selectedLabId === sc.lab_id
                ? "bg-cyber-850 text-sentinel-cyan border-sentinel-cyan/50 shadow-sm"
                : "bg-cyber-900/60 text-slate-400 border-cyber-800 hover:text-white hover:bg-cyber-850"
            }`}
          >
            {sc.title}
          </button>
        ))}
      </div>

      {/* Scenario Overview Card */}
      {currentScenario && (
        <div className="p-5 rounded-xl border border-cyber-800 bg-cyber-900/50">
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <span>{currentScenario.title}</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyber-800 text-slate-400 border border-cyber-700">
                  {currentScenario.test_file}
                </span>
              </h3>
              <p className="text-xs text-slate-300 font-sans mt-1 max-w-3xl leading-relaxed">
                {currentScenario.explanation}
              </p>
            </div>

            <div className="flex items-center gap-2 text-xs font-mono">
              <span className="text-slate-400">Target File:</span>
              <span className="text-sentinel-cyan bg-cyber-950 px-2.5 py-1 rounded border border-cyber-800">
                {targetType === "vulnerable"
                  ? currentScenario.vulnerable_contract
                  : currentScenario.patched_contract}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Execution Results View */}
      {result ? (
        <div className="space-y-6">
          {/* Status & Metrics Bar */}
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
            <div className="p-4 rounded-xl border border-cyber-800 bg-cyber-900/60">
              <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                Foundry Test Status
              </span>
              <div className="flex items-center gap-2">
                {result.passed ? (
                  <>
                    <CheckCircle2 className="w-5 h-5 text-sentinel-emerald" />
                    <span className="text-lg font-bold font-mono text-sentinel-emerald">
                      PASSED (100%)
                    </span>
                  </>
                ) : (
                  <>
                    <AlertOctagon className="w-5 h-5 text-red-400" />
                    <span className="text-lg font-bold font-mono text-red-400">FAILED</span>
                  </>
                )}
              </div>
            </div>

            <div className="p-4 rounded-xl border border-cyber-800 bg-cyber-900/60">
              <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                Gas Consumed
              </span>
              <div className="flex items-center gap-2 text-lg font-bold font-mono text-amber-400">
                <Flame className="w-5 h-5 text-amber-400" />
                <span>{result.gas_used.toLocaleString()}</span>
              </div>
            </div>

            <div className="p-4 rounded-xl border border-cyber-800 bg-cyber-900/60">
              <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                Execution Time
              </span>
              <div className="flex items-center gap-2 text-lg font-bold font-mono text-sentinel-cyan">
                <Clock className="w-5 h-5 text-sentinel-cyan" />
                <span>{result.duration_ms} ms</span>
              </div>
            </div>

            <div className="p-4 rounded-xl border border-cyber-800 bg-cyber-900/60">
              <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                Execution Mode
              </span>
              <div className="flex items-center gap-2">
                {result.target_type === "vulnerable" ? (
                  <span className="text-sm font-bold font-mono px-2.5 py-1 rounded bg-red-950 text-red-400 border border-red-800/50">
                    EXPLOIT DEMONSTRATED
                  </span>
                ) : (
                  <span className="text-sm font-bold font-mono px-2.5 py-1 rounded bg-emerald-950 text-emerald-400 border border-emerald-800/50">
                    DEFENSE VERIFIED
                  </span>
                )}
              </div>
            </div>
          </div>

          {/* State Diff Inspector */}
          {Object.keys(result.state_diff).length > 0 && (
            <div className="p-5 rounded-xl border border-cyber-800 bg-cyber-900/40">
              <h4 className="text-xs font-mono font-bold text-white uppercase tracking-wider mb-3 flex items-center gap-2">
                <Layers className="w-4 h-4 text-sentinel-cyan" /> EVM State Transition Logs
              </h4>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
                {Object.entries(result.state_diff).map(([key, val]) => (
                  <div
                    key={key}
                    className="p-3 rounded-lg bg-cyber-950 border border-cyber-800 flex items-center justify-between"
                  >
                    <span className="text-slate-400">{key}:</span>
                    <span className="text-sentinel-cyan font-bold truncate max-w-[200px]" title={val}>
                      {val.endsWith("000000000000000000")
                        ? `${Number(val) / 1e18} ETH`
                        : val}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Interactive Call Trace Visualizer */}
          <TraceViewer
            parsedTrace={result.parsed_trace}
            rawTraces={result.call_traces}
            rawLogs={result.raw_logs}
          />
        </div>
      ) : (
        <div className="p-12 text-center rounded-2xl border border-cyber-800 bg-cyber-900/40">
          <Terminal className="w-12 h-12 text-cyber-700 mx-auto mb-3" />
          <h3 className="text-white font-bold text-base mb-1">Foundry Sandbox Ready</h3>
          <p className="text-slate-400 text-xs max-w-md mx-auto mb-5 leading-relaxed">
            Select Vulnerable Mode to witness the automated exploit drain capital, or Patched Mode to verify that the remediation successfully blocks the attack.
          </p>
          <button
            onClick={handleExecute}
            disabled={isRunning}
            className="px-6 py-2.5 rounded-xl bg-sentinel-cyan text-cyber-950 font-bold text-xs hover:bg-cyan-300 transition-all shadow-md shadow-cyan-500/20"
          >
            Run Scenario Simulation
          </button>
        </div>
      )}
    </div>
  );
}
