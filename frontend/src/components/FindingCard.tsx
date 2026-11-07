"use client";

import { useState } from "react";
import { Finding } from "@/lib/types";
import SeverityBadge from "./SeverityBadge";
import { 
  ChevronDown, 
  ChevronRight, 
  AlertTriangle, 
  ShieldCheck, 
  Code, 
  Terminal, 
  ExternalLink 
} from "lucide-react";

interface Props {
  finding: Finding;
  index: number;
}

export default function FindingCard({ finding, index }: Props) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="rounded-xl border border-cyber-800 bg-cyber-900/60 hover:border-cyber-700 transition-all overflow-hidden mb-3">
      {/* Header / Click to Expand */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full text-left p-4 flex items-center justify-between gap-4 hover:bg-cyber-850/40 transition-colors"
      >
        <div className="flex items-center gap-3 flex-1 min-w-0">
          <div className="text-slate-500 font-mono text-xs w-6 text-center">#{index}</div>
          <SeverityBadge severity={finding.severity} size="sm" />
          <div className="min-w-0 flex-1">
            <h4 className="text-sm font-semibold text-white truncate">{finding.name}</h4>
            <div className="flex items-center gap-3 text-xs text-slate-400 font-mono mt-0.5">
              <span>{finding.file_path}:{finding.line_start}</span>
              <span>•</span>
              <span className="text-sentinel-cyan">{finding.function_name}()</span>
              <span>•</span>
              <span className="text-slate-500">{finding.category}</span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-cyber-800 text-slate-300 border border-cyber-700 hidden sm:inline-block">
            {finding.confidence} Confidence
          </span>
          {expanded ? (
            <ChevronDown className="w-5 h-5 text-slate-400" />
          ) : (
            <ChevronRight className="w-5 h-5 text-slate-400" />
          )}
        </div>
      </button>

      {/* Expanded Details */}
      {expanded && (
        <div className="px-5 pb-5 pt-2 border-t border-cyber-800/80 space-y-4 bg-cyber-950/40">
          {/* Explanation */}
          <div>
            <h5 className="text-xs uppercase font-mono tracking-wider text-slate-400 mb-1 flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400" /> Technical Explanation
            </h5>
            <p className="text-sm text-slate-300 leading-relaxed">{finding.description}</p>
          </div>

          {/* Impact */}
          <div>
            <h5 className="text-xs uppercase font-mono tracking-wider text-slate-400 mb-1">
              Potential Impact
            </h5>
            <p className="text-sm text-red-300/90 leading-relaxed bg-red-950/20 p-2.5 rounded-lg border border-red-900/30">
              {finding.impact}
            </p>
          </div>

          {/* Code Snippet */}
          {finding.code_snippet && (
            <div>
              <h5 className="text-xs uppercase font-mono tracking-wider text-slate-400 mb-1 flex items-center gap-1.5">
                <Code className="w-3.5 h-3.5 text-sentinel-cyan" /> Vulnerable Code Location (Lines {finding.line_start}-{finding.line_end})
              </h5>
              <div className="rounded-lg bg-cyber-950 border border-cyber-800 p-3 overflow-x-auto font-mono text-xs text-sentinel-cyan/90 leading-5">
                <pre>{finding.code_snippet}</pre>
              </div>
            </div>
          )}

          {/* Reproduction */}
          {finding.reproduction && (
            <div>
              <h5 className="text-xs uppercase font-mono tracking-wider text-slate-400 mb-1 flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-sentinel-emerald" /> Proof-of-Concept Reproduction
              </h5>
              <div className="bg-cyber-900/90 p-3 rounded-lg border border-cyber-800 text-xs font-mono text-slate-300 whitespace-pre-wrap leading-relaxed">
                {finding.reproduction}
              </div>
            </div>
          )}

          {/* Remediation */}
          <div>
            <h5 className="text-xs uppercase font-mono tracking-wider text-slate-400 mb-1 flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5 text-sentinel-emerald" /> Recommended Remediation
            </h5>
            <div className="bg-emerald-950/20 p-3 rounded-lg border border-emerald-900/30 text-xs text-emerald-300/90 whitespace-pre-wrap leading-relaxed">
              {finding.remediation}
            </div>
          </div>

          {/* Meta footer */}
          <div className="flex items-center justify-between pt-2 border-t border-cyber-800 text-[11px] font-mono text-slate-500">
            <span>Detected by: <strong className="text-slate-400">{finding.tool}</strong></span>
            <span>Contract: <strong className="text-slate-400">{finding.contract_name}</strong></span>
          </div>
        </div>
      )}
    </div>
  );
}
