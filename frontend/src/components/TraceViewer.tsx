"use client";

import { useState } from "react";
import { ExploitTraceStep } from "@/lib/types";
import { ArrowRight, ShieldAlert, CheckCircle, Flame, Eye, Terminal } from "lucide-react";

interface Props {
  parsedTrace: ExploitTraceStep[];
  rawTraces: string[];
  rawLogs: string[];
}

export default function TraceViewer({ parsedTrace, rawTraces, rawLogs }: Props) {
  const [viewMode, setViewMode] = useState<"visual" | "raw">("visual");

  return (
    <div className="rounded-xl border border-cyber-800 bg-cyber-950 overflow-hidden">
      {/* Top Header */}
      <div className="px-4 py-3 bg-cyber-900 border-b border-cyber-800 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-sentinel-cyan" />
          <h4 className="text-xs font-mono font-semibold text-white uppercase tracking-wider">
            Transaction Execution Call Trace
          </h4>
          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-cyber-800 text-slate-400">
            {parsedTrace.length} calls recorded
          </span>
        </div>

        {/* View Switcher */}
        <div className="flex items-center rounded-lg bg-cyber-950 p-0.5 border border-cyber-800 text-xs font-mono">
          <button
            onClick={() => setViewMode("visual")}
            className={`px-3 py-1 rounded transition-colors ${
              viewMode === "visual"
                ? "bg-sentinel-cyan/20 text-sentinel-cyan font-bold"
                : "text-slate-400 hover:text-white"
            }`}
          >
            Visual Trace
          </button>
          <button
            onClick={() => setViewMode("raw")}
            className={`px-3 py-1 rounded transition-colors ${
              viewMode === "raw"
                ? "bg-sentinel-cyan/20 text-sentinel-cyan font-bold"
                : "text-slate-400 hover:text-white"
            }`}
          >
            Raw Logs
          </button>
        </div>
      </div>

      {/* Content */}
      <div className="p-4 max-h-[480px] overflow-y-auto font-mono text-xs">
        {viewMode === "visual" ? (
          <div className="space-y-1.5">
            {parsedTrace.length === 0 ? (
              <div className="text-slate-500 py-6 text-center">No trace steps captured yet.</div>
            ) : (
              parsedTrace.map((step, idx) => {
                const isRevert = step.status === "REVERT";
                const isReentrancy = step.function === "withdraw" && idx > 3;

                return (
                  <div
                    key={idx}
                    style={{ paddingLeft: `${Math.min(step.depth * 18, 180)}px` }}
                    className="flex items-center gap-2 py-1 px-2 rounded hover:bg-cyber-900/60 transition-colors border-l-2 border-cyber-700 hover:border-sentinel-cyan"
                  >
                    {/* Depth Arrow */}
                    <span className="text-slate-600">└─</span>

                    {/* Status Badge */}
                    {isRevert ? (
                      <span className="px-1.5 py-0.5 rounded bg-red-950 text-red-400 border border-red-800/50 text-[10px]">
                        REVERT
                      </span>
                    ) : (
                      <span className="px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800/50 text-[10px]">
                        CALL
                      </span>
                    )}

                    {/* Gas */}
                    <span className="text-slate-400 text-[10px] flex items-center gap-0.5">
                      <Flame className="w-2.5 h-2.5 text-amber-500" />
                      {step.gas.toLocaleString()}
                    </span>

                    {/* Contract Target & Function */}
                    <span className="text-sentinel-cyan font-semibold">{step.contract}</span>
                    <span className="text-slate-500">::</span>
                    <span className={isReentrancy ? "text-amber-300 font-bold underline" : "text-white"}>
                      {step.function}()
                    </span>

                    {/* Value Transferred */}
                    {step.value_wei !== "0" && (
                      <span className="text-[11px] px-1.5 py-0.2 rounded bg-sentinel-purple/20 text-purple-300 border border-purple-500/30">
                        {(Number(step.value_wei) / 1e18).toFixed(2)} ETH
                      </span>
                    )}

                    {/* Call Arguments preview */}
                    {step.arguments && (
                      <span className="text-slate-500 truncate max-w-[200px]" title={step.arguments}>
                        ({step.arguments})
                      </span>
                    )}

                    {isReentrancy && (
                      <span className="ml-auto text-[10px] text-amber-400 font-semibold px-2 py-0.5 rounded bg-amber-950/60 border border-amber-800/40 animate-pulse">
                        ⚠️ Reentrant Call Frame
                      </span>
                    )}
                  </div>
                );
              })
            )}
          </div>
        ) : (
          <div className="bg-cyber-950 p-3 rounded text-slate-300 whitespace-pre-wrap leading-5 text-[11px]">
            {rawTraces.length > 0
              ? rawTraces.join("\n")
              : rawLogs.length > 0
              ? rawLogs.join("\n")
              : "No raw logs available."}
          </div>
        )}
      </div>
    </div>
  );
}
