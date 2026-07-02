"use client";

import { useEffect, useState, useCallback } from "react";
import { CheckCircle2, AlertTriangle } from "lucide-react";
import { api } from "@/lib/api";

// ── Helpers ──────────────────────────────────────────────────────────────────

// detection_validation structure from backend:
//   .detection_simulation.coverage_metrics  — { tactic_id: float% }
//   .detection_simulation.blind_spots_tactics — [tactic_id]
//   .detection_simulation.sigma_rules        — [{ status, sigma_rule, mitre_id }]
// findings come from module_results[].findings[].mitre_id (technique level, e.g. T1110)

// MITRE tactic definitions used for the grid
const MITRE_TACTICS: { id: string; name: string; color: string }[] = [
  { id: "TA0001", name: "Initial Access",       color: "#8b5cf6" },
  { id: "TA0002", name: "Execution",            color: "#7c3aed" },
  { id: "TA0003", name: "Persistence",          color: "#6d28d9" },
  { id: "TA0004", name: "Priv. Escalation",     color: "#5b21b6" },
  { id: "TA0005", name: "Defense Evasion",      color: "#4c1d95" },
  { id: "TA0006", name: "Credential Access",    color: "#ef4444" },
  { id: "TA0007", name: "Discovery",            color: "#dc2626" },
  { id: "TA0008", name: "Lateral Movement",     color: "#b91c1c" },
  { id: "TA0009", name: "Collection",           color: "#f97316" },
  { id: "TA0010", name: "Exfiltration",         color: "#ea580c" },
  { id: "TA0011", name: "C2",                   color: "#c2410c" },
  { id: "TA0040", name: "Impact",               color: "#f59e0b" },
  { id: "TA0042", name: "Resource Dev.",        color: "#d97706" },
  { id: "TA0043", name: "Reconnaissance",       color: "#b45309" },
];

const SEVERITY_WEIGHT: Record<string, number> = {
  critical: 4, high: 3, medium: 2, low: 1, info: 0,
};

export default function MitrePage() {
  const [simulations, setSimulations] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const loadData = useCallback(async () => {
    try {
      const data = await api.getSimulations();
      setSimulations(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  // ── Aggregation ───────────────────────────────────────────────────────────
  //
  // For the ATT&CK grid, we aggregate from two sources:
  // 1. findings[].mitre_id (technique IDs, e.g. T1110) mapped to tactic via coverage_metrics keys
  // 2. detection_simulation.coverage_metrics (tactic_id -> coverage %)
  //
  // We map tactic coverage from the coverage_metrics field when available.

  // All findings across all sims (findings are now eagerly loaded)
  const allFindings = simulations.flatMap(s =>
    s.module_results?.flatMap((r: any) => r.findings || []) ?? []
  );

  // Tactic coverage map: tactic_id -> { pct: float, techniques: string[], maxSeverity: string }
  // Built from coverage_metrics in completed simulations
  const tacticMap: Record<string, {
    pct: number; techniques: Set<string>; severities: string[];
  }> = {};

  simulations.forEach(s => {
    const cm = s.metadata?.detection_validation?.detection_simulation?.coverage_metrics ?? {};
    Object.entries(cm).forEach(([tactic, pct]) => {
      if (!tacticMap[tactic]) {
        tacticMap[tactic] = { pct: 0, techniques: new Set(), severities: [] };
      }
      tacticMap[tactic].pct = Math.max(tacticMap[tactic].pct, Number(pct));
    });
  });

  // Also track which techniques (mitre_id) fired, grouped by tactic
  // We use coverage_metrics tactic keys from each sim to know which tactic a technique belongs to
  // For technique-level data, we aggregate from findings directly
  const techniqueMap: Record<string, {
    findings: any[]; maxSeverity: string;
  }> = {};

  allFindings.forEach((f: any) => {
    if (!f.mitre_id) return;
    if (!techniqueMap[f.mitre_id]) {
      techniqueMap[f.mitre_id] = { findings: [], maxSeverity: "info" };
    }
    techniqueMap[f.mitre_id].findings.push(f);
    if ((SEVERITY_WEIGHT[f.severity] || 0) > (SEVERITY_WEIGHT[techniqueMap[f.mitre_id].maxSeverity] || 0)) {
      techniqueMap[f.mitre_id].maxSeverity = f.severity;
    }
  });

  // Metrics
  const tacticsCovered = Object.keys(tacticMap).length;
  const totalTechniques = Object.keys(techniqueMap).length;
  const criticalTechniques = Object.values(techniqueMap).filter(t => t.maxSeverity === "critical").length;
  const totalSimulations = simulations.length;

  // Per-tactic summary for the table
  const tableTactics = MITRE_TACTICS.map(t => ({
    ...t,
    pct: tacticMap[t.id]?.pct ?? 0,
    covered: !!tacticMap[t.id],
  })).sort((a, b) => b.pct - a.pct);

  if (loading) {
    return (
      <div className="space-y-6 animate-pulse">
        <div className="h-8 w-56 bg-white/5 rounded-xl" />
        <div className="grid grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => <div key={i} className="h-24 bg-white/5 rounded-2xl" />)}
        </div>
        <div className="h-64 bg-white/5 rounded-2xl" />
        <div className="h-40 bg-white/5 rounded-2xl" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight">MITRE ATT&CK Coverage</h1>
        <p className="text-sm text-white/40 mt-0.5">Coverage generated from completed BAS assessments</p>
      </div>

      {/* Metrics */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
        {[
          { label: "Simulations",        value: totalSimulations, color: "border-violet-500/20 from-violet-500/[0.06]" },
          { label: "Tactics Covered",    value: tacticsCovered,   color: "border-emerald-500/20 from-emerald-500/[0.06]" },
          { label: "Techniques Tested",  value: totalTechniques,  color: "border-blue-500/20 from-blue-500/[0.06]" },
          { label: "Critical Techniques",value: criticalTechniques,color: "border-red-500/20 from-red-500/[0.06]" },
        ].map(item => (
          <div key={item.label}
            className={`glass-card p-5 border bg-gradient-to-br ${item.color} to-transparent`}>
            <div className="text-[10px] font-bold uppercase tracking-widest text-white/40 mb-2">{item.label}</div>
            <div className="text-3xl font-bold text-white tabular-nums">{item.value}</div>
          </div>
        ))}
      </div>

      {/* ATT&CK Navigator Grid */}
      <div className="glass-card p-5">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-[10px] font-bold uppercase tracking-widest text-white/40">ATT&CK Tactic Coverage Map</h2>
          <div className="flex items-center gap-3 text-[10px] text-white/40">
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-violet-500 inline-block" /> Covered</span>
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-red-500/60 inline-block" /> Critical</span>
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-white/[0.06] border border-white/10 inline-block" /> Not tested</span>
          </div>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-7 gap-2">
          {MITRE_TACTICS.map(tactic => {
            const covered = !!tacticMap[tactic.id];
            const pct = tacticMap[tactic.id]?.pct ?? 0;

            return (
              <div
                key={tactic.id}
                title={`${tactic.name} — ${pct.toFixed(0)}% coverage`}
                className={`rounded-xl border p-3 transition-all duration-200 ${
                  covered
                    ? "border-violet-500/30 bg-violet-500/10"
                    : "border-white/[0.06] bg-white/[0.02]"
                }`}
              >
                <div className="font-mono text-[9px] text-white/30 mb-1">{tactic.id}</div>
                <div className="text-xs font-semibold text-white leading-tight mb-2">{tactic.name}</div>
                <div className="h-1 rounded-full bg-white/[0.06] overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-700"
                    style={{
                      width: `${pct}%`,
                      backgroundColor: covered ? tactic.color : "transparent",
                    }}
                  />
                </div>
                <div className={`text-[9px] mt-1.5 font-mono ${covered ? "text-violet-300" : "text-white/20"}`}>
                  {covered ? `${pct.toFixed(0)}%` : "—"}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Coverage summary table */}
      <div className="glass-card p-5">
        <h2 className="text-[10px] font-bold uppercase tracking-widest text-white/40 mb-4">Coverage Summary</h2>
        {tableTactics.filter(t => t.covered).length === 0 ? (
          <p className="text-sm text-white/25 py-4 text-center">
            No completed assessments with MITRE data yet
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-white/[0.06]">
                  {["Tactic ID", "Tactic Name", "Coverage", "Status"].map(h => (
                    <th key={h} className="text-left text-[10px] font-bold uppercase tracking-widest text-white/30 pb-3 pr-4">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {tableTactics.map(t => (
                  <tr key={t.id} className="border-b border-white/[0.04] hover:bg-white/[0.015] transition-colors">
                    <td className="py-3 pr-4 font-mono text-xs text-violet-300">{t.id}</td>
                    <td className="py-3 pr-4 text-white/80 font-medium">{t.name}</td>
                    <td className="py-3 pr-4">
                      <div className="flex items-center gap-3">
                        <div className="w-24 h-1.5 rounded-full bg-white/[0.06] overflow-hidden">
                          <div
                            className="h-full rounded-full transition-all"
                            style={{
                              width: `${t.pct}%`,
                              backgroundColor: t.pct >= 50 ? "#10b981" : t.pct > 0 ? "#f59e0b" : "transparent",
                            }}
                          />
                        </div>
                        <span className="text-xs text-white/50 tabular-nums w-8">{t.pct.toFixed(0)}%</span>
                      </div>
                    </td>
                    <td className="py-3 pr-4">
                      {t.covered ? (
                        <span className="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full border border-emerald-500/25 bg-emerald-500/10 text-emerald-400">
                          <CheckCircle2 className="w-3 h-3" /> Detected
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full border border-white/10 bg-white/[0.03] text-white/30">
                          <AlertTriangle className="w-3 h-3" /> Not Tested
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Technique frequency from findings */}
      {Object.keys(techniqueMap).length > 0 && (
        <div className="glass-card p-5">
          <h2 className="text-[10px] font-bold uppercase tracking-widest text-white/40 mb-4">
            Technique Findings ({Object.keys(techniqueMap).length} techniques)
          </h2>
          <div className="grid sm:grid-cols-2 xl:grid-cols-3 gap-3">
            {Object.entries(techniqueMap)
              .sort((a, b) => b[1].findings.length - a[1].findings.length)
              .slice(0, 12)
              .map(([id, data]) => {
                const sevColor =
                  data.maxSeverity === "critical" ? "border-red-500/25 bg-red-500/[0.05]" :
                  data.maxSeverity === "high"     ? "border-orange-500/25 bg-orange-500/[0.05]" :
                  data.maxSeverity === "medium"   ? "border-amber-500/25 bg-amber-500/[0.05]" :
                                                    "border-violet-500/20 bg-violet-500/[0.04]";
                const sevText =
                  data.maxSeverity === "critical" ? "text-red-400" :
                  data.maxSeverity === "high"     ? "text-orange-400" :
                  data.maxSeverity === "medium"   ? "text-amber-400" : "text-violet-300";
                return (
                  <div key={id} className={`rounded-xl border ${sevColor} p-3`}>
                    <div className="flex items-center justify-between mb-1">
                      <span className={`font-mono text-xs font-bold ${sevText}`}>{id}</span>
                      <span className="text-[10px] text-white/30">{data.findings.length} finding{data.findings.length !== 1 ? "s" : ""}</span>
                    </div>
                    <p className="text-xs text-white/60 truncate">
                      {data.findings[0]?.title || "Unknown"}
                    </p>
                  </div>
                );
              })}
          </div>
        </div>
      )}
    </div>
  );
}