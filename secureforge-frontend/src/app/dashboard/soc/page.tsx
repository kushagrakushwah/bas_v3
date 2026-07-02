"use client";

import { useEffect, useState, useCallback } from "react";
import {
  Shield, AlertTriangle, CheckCircle2, Radar,
  Eye, TrendingDown, Lock, Activity,
} from "lucide-react";
import { api } from "@/lib/api";

// ── Helpers ──────────────────────────────────────────────────────────────────

function formatTs(ts: string | null | undefined): string {
  if (!ts) return "—";
  const s = ts.endsWith("Z") ? ts : ts + "Z";
  return new Date(s).toLocaleString("en-US", {
    timeZone: "Asia/Kolkata",
    month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit", hour12: false,
  });
}

// ── Score Ring ────────────────────────────────────────────────────────────────

function ScoreRing({ score, label }: { score: number; label: string }) {
  const r = 52;
  const circ = 2 * Math.PI * r;
  const dash = (score / 100) * circ;

  const color =
    score >= 70 ? "#10b981" :
    score >= 40 ? "#f59e0b" : "#ef4444";

  return (
    <div className="flex flex-col items-center">
      <svg width="140" height="140" className="-rotate-90">
        <circle cx="70" cy="70" r={r} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="10" />
        <circle
          cx="70" cy="70" r={r} fill="none"
          stroke={color} strokeWidth="10"
          strokeDasharray={`${dash} ${circ}`}
          strokeLinecap="round"
          style={{ transition: "stroke-dasharray 1s ease" }}
        />
      </svg>
      <div className="mt-[-110px] flex flex-col items-center">
        <span className="text-4xl font-bold tabular-nums" style={{ color }}>
          {score}
        </span>
        <span className="text-xs text-white/40 mt-1 uppercase tracking-widest">{label}</span>
      </div>
      <div className="mt-[54px]" />
    </div>
  );
}

// ── NIST Tier Chip ────────────────────────────────────────────────────────────

function NistTierBadge({ tier }: { tier: string }) {
  const n = parseInt(tier.replace(/\D/g, "")) || 1;
  const config: Record<number, { label: string; color: string; bg: string; border: string }> = {
    1: { label: tier, color: "text-red-400",     bg: "bg-red-500/10",     border: "border-red-500/25" },
    2: { label: tier, color: "text-amber-400",   bg: "bg-amber-500/10",   border: "border-amber-500/25" },
    3: { label: tier, color: "text-lime-400",    bg: "bg-lime-500/10",    border: "border-lime-500/25" },
    4: { label: tier, color: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/25" },
    5: { label: tier, color: "text-cyan-400",    bg: "bg-cyan-500/10",    border: "border-cyan-500/25" },
  };
  const c = config[n] || config[1];
  return (
    <span className={`inline-block text-xs font-semibold px-3 py-1 rounded-full border ${c.color} ${c.bg} ${c.border}`}>
      {c.label}
    </span>
  );
}

// ── Coverage Bar ──────────────────────────────────────────────────────────────

function CoverageBar({ tactic, pct }: { tactic: string; pct: number }) {
  const color = pct >= 75 ? "#10b981" : pct >= 40 ? "#f59e0b" : "#ef4444";
  return (
    <div>
      <div className="flex justify-between text-xs mb-1">
        <span className="text-white/60 font-mono">{tactic}</span>
        <span className="text-white/40">{pct.toFixed(0)}%</span>
      </div>
      <div className="h-1.5 rounded-full bg-white/[0.06] overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-700"
          style={{ width: `${Math.min(pct, 100)}%`, backgroundColor: color }}
        />
      </div>
    </div>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function SocPage() {
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

  // Pick the latest COMPLETED simulation (most likely to have validation data)
  const completedSims = [...simulations]
    .filter(s => s.status === "completed" && s.metadata?.detection_validation)
    .sort((a, b) => new Date(b.finished_at || b.created_at).getTime() - new Date(a.finished_at || a.created_at).getTime());

  const latest = completedSims[0] ?? null;

  // ── Parse backend response ─────────────────────────────────────────────────
  // detection_validation is the full object from validation_engine.validate()
  //
  // Structure:
  //   .methodology      { disclaimer, exposure_score, detection_score }
  //   .attack_surface   { exposure_score, critical_findings, high_findings, medium_findings, low_findings, techniques_tested }
  //   .detection_simulation { detection_score, nist_maturity_tier, tactics_detected, sigma_rules_matched,
  //                           blind_spots_tactics, untested_subtechniques, coverage_metrics, sigma_rules }
  //
  // Note: detection_summary is stored from the orchestrator BEFORE the repo fallback path,
  // so it is the raw validation_engine output.
  //
  // The OLD paths (.soc_score, .blindspots) are only present when the repo uses the FALLBACK
  // branch (when detection_summary is null but soc_score column is set). We read BOTH to be safe.

  const dv = latest?.metadata?.detection_validation ?? {};
  const ds = dv.detection_simulation ?? {};
  const as_ = dv.attack_surface ?? {};

  // Prefer new schema; fall back to old repo-reconstructed schema
  const detectionScore: number = ds.detection_score ?? dv.soc_score?.soc_score ?? 0;
  const nistTier: string = ds.nist_maturity_tier ?? "N/A";
  const blindSpotsTactics: string[] = ds.blind_spots_tactics ?? dv.blindspots?.blind_spots ?? [];
  const detectedTactics: string[] = (dv.blindspots?.detected_tactics ?? []);
  const coveragePercent: number = dv.blindspots?.coverage_percent ?? 0;
  const coverageMetrics: Record<string, number> = ds.coverage_metrics ?? {};
  const sigmaRules: any[] = ds.sigma_rules ?? dv.sigma_rules ?? [];
  const exposureScore: number = as_.exposure_score ?? 0;
  const criticalFindings: number = as_.critical_findings ?? 0;
  const highFindings: number = as_.high_findings ?? 0;
  const mediumFindings: number = as_.medium_findings ?? 0;
  const lowFindings: number = as_.low_findings ?? 0;
  const techniquesTested: number = as_.techniques_tested ?? 0;
  const sigmaRulesMatched: number = ds.sigma_rules_matched ?? 0;
  const tacticsDetected: number = typeof ds.tactics_detected === "number" ? ds.tactics_detected : detectedTactics.length;

  // ── Skeleton ───────────────────────────────────────────────────────────────

  if (loading) {
    return (
      <div className="space-y-6 animate-pulse">
        <div className="h-8 w-56 bg-white/5 rounded-xl" />
        <div className="grid grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => <div key={i} className="h-28 bg-white/5 rounded-2xl" />)}
        </div>
        <div className="grid xl:grid-cols-3 gap-5">
          {[...Array(3)].map((_, i) => <div key={i} className="h-64 bg-white/5 rounded-2xl" />)}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">SOC Validation</h1>
          <p className="text-sm text-white/40 mt-0.5">Detection engineering validation and ATT&CK coverage analysis</p>
        </div>
        {latest && (
          <div className="text-right">
            <p className="text-xs text-white/30 uppercase tracking-wider">Based on</p>
            <p className="text-sm font-medium text-white/70">{latest.name}</p>
            <p className="text-xs text-white/30 font-mono mt-0.5">{latest.target}</p>
          </div>
        )}
      </div>

      {/* No data state */}
      {!latest && (
        <div className="glass-card p-12 flex flex-col items-center text-center">
          <Shield className="w-12 h-12 text-white/15 mb-4" />
          <p className="text-lg font-medium text-white/40">No completed assessments</p>
          <p className="text-sm text-white/25 mt-1">Run a simulation to generate SOC validation data</p>
        </div>
      )}

      {latest && (
        <>
          {/* Top metric row */}
          <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
            {[
              { label: "Exposure Score",     value: `${exposureScore.toFixed(0)}%`,     icon: Activity,       accent: exposureScore > 60 ? "red" : "amber" },
              { label: "Techniques Tested",  value: techniquesTested,                    icon: Eye,            accent: "purple" },
              { label: "Sigma Rules Matched",value: sigmaRulesMatched,                  icon: CheckCircle2,   accent: "green" },
              { label: "Blind Spot Tactics", value: blindSpotsTactics.length,           icon: AlertTriangle,  accent: blindSpotsTactics.length > 5 ? "red" : "amber" },
            ].map((item) => (
              <div key={item.label}
                className={`glass-card p-5 border ${
                  item.accent === "red"    ? "border-red-500/20 bg-gradient-to-br from-red-500/[0.06]" :
                  item.accent === "amber"  ? "border-amber-500/20 bg-gradient-to-br from-amber-500/[0.06]" :
                  item.accent === "green"  ? "border-emerald-500/20 bg-gradient-to-br from-emerald-500/[0.06]" :
                  "border-violet-500/20 bg-gradient-to-br from-violet-500/[0.06]"
                } to-transparent`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[10px] font-bold uppercase tracking-widest text-white/35">{item.label}</span>
                  <item.icon className={`w-3.5 h-3.5 ${
                    item.accent === "red" ? "text-red-400" :
                    item.accent === "amber" ? "text-amber-400" :
                    item.accent === "green" ? "text-emerald-400" : "text-violet-400"
                  }`} />
                </div>
                <div className="text-3xl font-bold text-white tabular-nums">{item.value}</div>
              </div>
            ))}
          </div>

          {/* Main panels */}
          <div className="grid xl:grid-cols-3 gap-5">

            {/* SOC Score Ring */}
            <div className="glass-card p-6 flex flex-col items-center gap-4">
              <h2 className="self-start text-[10px] font-bold uppercase tracking-widest text-white/40">Detection Score</h2>
              <ScoreRing score={Math.round(detectionScore)} label="out of 100" />
              <div className="w-full border-t border-white/[0.06] pt-4 text-center">
                <p className="text-xs text-white/40 mb-2 uppercase tracking-wider">NIST Maturity</p>
                <NistTierBadge tier={nistTier} />
              </div>
              <div className="w-full grid grid-cols-2 gap-2 text-center">
                <div className="rounded-xl bg-white/[0.03] border border-white/[0.06] px-2 py-2">
                  <div className="text-xl font-bold text-emerald-400">{tacticsDetected}</div>
                  <div className="text-[9px] text-white/30 uppercase tracking-wider mt-0.5">Tactics Detected</div>
                </div>
                <div className="rounded-xl bg-white/[0.03] border border-white/[0.06] px-2 py-2">
                  <div className="text-xl font-bold text-amber-400">{coveragePercent.toFixed(0)}%</div>
                  <div className="text-[9px] text-white/30 uppercase tracking-wider mt-0.5">ATT&CK Coverage</div>
                </div>
              </div>
            </div>

            {/* Detected Tactics vs Blind Spots */}
            <div className="glass-card p-5 flex flex-col gap-4">
              <div>
                <h2 className="text-[10px] font-bold uppercase tracking-widest text-white/40 mb-3">Detected Tactics</h2>
                <div className="space-y-1.5 max-h-[150px] overflow-y-auto pr-1">
                  {detectedTactics.length === 0 ? (
                    <p className="text-xs text-white/25">No tactics detected</p>
                  ) : detectedTactics.map(t => (
                    <div key={t}
                      className="flex items-center justify-between rounded-lg border border-emerald-500/15 bg-emerald-500/[0.04] px-3 py-1.5">
                      <span className="font-mono text-xs text-emerald-300">{t}</span>
                      <CheckCircle2 className="w-3 h-3 text-emerald-400 flex-shrink-0" />
                    </div>
                  ))}
                </div>
              </div>
              <div className="border-t border-white/[0.06] pt-4">
                <h2 className="text-[10px] font-bold uppercase tracking-widest text-white/40 mb-3">Blind Spot Tactics</h2>
                <div className="space-y-1.5 max-h-[130px] overflow-y-auto pr-1">
                  {blindSpotsTactics.length === 0 ? (
                    <p className="text-xs text-emerald-400 font-medium">No blind spots detected</p>
                  ) : blindSpotsTactics.map(t => (
                    <div key={t}
                      className="flex items-center justify-between rounded-lg border border-red-500/15 bg-red-500/[0.04] px-3 py-1.5">
                      <span className="font-mono text-xs text-red-300">{t}</span>
                      <AlertTriangle className="w-3 h-3 text-red-400 flex-shrink-0" />
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Coverage Analysis */}
            <div className="glass-card p-5">
              <h2 className="text-[10px] font-bold uppercase tracking-widest text-white/40 mb-4">Tactic Coverage Breakdown</h2>
              {Object.keys(coverageMetrics).length === 0 ? (
                <p className="text-xs text-white/25">No coverage data</p>
              ) : (
                <div className="space-y-3">
                  {Object.entries(coverageMetrics).map(([tactic, pct]) => (
                    <CoverageBar key={tactic} tactic={tactic} pct={Number(pct)} />
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Sigma Rules */}
          {sigmaRules.length > 0 && (
            <div className="glass-card p-5">
              <h2 className="text-[10px] font-bold uppercase tracking-widest text-white/40 mb-4">
                Generated Sigma Rules ({sigmaRules.length})
              </h2>
              <div className="grid md:grid-cols-2 xl:grid-cols-3 gap-4">
                {sigmaRules.slice(0, 6).map((rule: any, idx: number) => (
                  <div key={idx} className="rounded-xl border border-white/[0.06] bg-black/30 overflow-hidden">
                    <div className="flex items-center justify-between px-3 py-2 border-b border-white/[0.06] bg-white/[0.02]">
                      <span className="font-mono text-[10px] text-violet-300">{rule.mitre_id}</span>
                      <span className={`text-[9px] uppercase font-bold px-1.5 py-0.5 rounded ${
                        rule.status === "success"
                          ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/20"
                          : "bg-red-500/15 text-red-400 border border-red-500/20"
                      }`}>{rule.status}</span>
                    </div>
                    <pre className="p-3 text-[10px] font-mono text-white/50 leading-relaxed overflow-x-auto max-h-[120px] whitespace-pre-wrap">
                      {rule.sigma_rule}
                    </pre>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Finding severity summary */}
          <div className="glass-card p-5">
            <h2 className="text-[10px] font-bold uppercase tracking-widest text-white/40 mb-4">Finding Severity Breakdown</h2>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {[
                { label: "Critical", val: criticalFindings, color: "text-red-400",     bg: "bg-red-500/10",     border: "border-red-500/20" },
                { label: "High",     val: highFindings,     color: "text-orange-400",  bg: "bg-orange-500/10",  border: "border-orange-500/20" },
                { label: "Medium",   val: mediumFindings,   color: "text-amber-400",   bg: "bg-amber-500/10",   border: "border-amber-500/20" },
                { label: "Low",      val: lowFindings,      color: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/20" },
              ].map(s => (
                <div key={s.label} className={`rounded-xl border ${s.border} ${s.bg} px-4 py-3 text-center`}>
                  <div className={`text-2xl font-bold tabular-nums ${s.color}`}>{s.val}</div>
                  <div className="text-[10px] text-white/40 uppercase tracking-wider mt-1">{s.label}</div>
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}