import React from "react";
import { Severity } from "@/lib/types";

interface Props {
  severity: Severity;
  size?: "sm" | "md" | "lg";
}

export default function SeverityBadge({ severity, size = "md" }: Props) {
  const config = {
    Critical: {
      bg: "bg-red-500/10",
      text: "text-red-400",
      border: "border-red-500/30",
      dot: "bg-red-500",
      glow: "shadow-[0_0_8px_rgba(239,68,68,0.4)]",
    },
    High: {
      bg: "bg-orange-500/10",
      text: "text-orange-400",
      border: "border-orange-500/30",
      dot: "bg-orange-500",
      glow: "shadow-[0_0_8px_rgba(249,115,22,0.4)]",
    },
    Medium: {
      bg: "bg-amber-500/10",
      text: "text-amber-400",
      border: "border-amber-500/30",
      dot: "bg-amber-500",
      glow: "shadow-[0_0_8px_rgba(245,158,11,0.4)]",
    },
    Low: {
      bg: "bg-blue-500/10",
      text: "text-blue-400",
      border: "border-blue-500/30",
      dot: "bg-blue-500",
      glow: "shadow-[0_0_8px_rgba(59,130,246,0.4)]",
    },
    Informational: {
      bg: "bg-slate-500/10",
      text: "text-slate-400",
      border: "border-slate-500/30",
      dot: "bg-slate-500",
      glow: "",
    },
  }[severity] || {
    bg: "bg-slate-500/10",
    text: "text-slate-400",
    border: "border-slate-500/30",
    dot: "bg-slate-500",
    glow: "",
  };

  const sizeClasses = {
    sm: "px-2 py-0.5 text-[11px]",
    md: "px-2.5 py-1 text-xs",
    lg: "px-3 py-1.5 text-sm",
  }[size];

  return (
    <span
      className={`inline-flex items-center gap-1.5 font-mono font-medium rounded-md border ${config.bg} ${config.text} ${config.border} ${config.glow} ${sizeClasses}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${config.dot}`}></span>
      <span>{severity.toUpperCase()}</span>
    </span>
  );
}
