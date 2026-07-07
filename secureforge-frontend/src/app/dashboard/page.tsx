"use client";

import { useEffect, useState, useCallback } from "react";
import {
  Shield, Target, AlertTriangle, Activity,
  TrendingUp, Clock, ChevronRight, Zap, Eye
} from "lucide-react";
import DOMPurify from "dompurify";
import {
  ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell,
  Tooltip, XAxis, YAxis, CartesianGrid, Legend,
} from "recharts";
import { useEvents } from "@/hooks/useEvents";
import SimulationStatusBadge from "@/components/SimulationStatusBadge";
import SeverityBadge from "@/components/ui/SeverityBadge";
import { api } from "@/lib/api";

// ── Helpers ──────────────────────────────────────────────────────────────────

function formatTs(ts: string | null | undefined): string {
  if (!ts) return "—";
  const s = ts.endsWith("Z") ? ts : ts + "Z";
  return new Date(s).toLocaleString("en-US", {
    timeZone: "Asia/Kolkata",
    month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit",
    hour12: false,
  });
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#f59e0b",
  info: "#3b82f6",
  low: "#10b981",
};

const CHART_COLORS = ["#8b5cf6", "#10b981", "#f59e0b", "#ef4444", "#3b82f6", "#ec4899"];

// ── Sub-components ───────────────────────────────────────────────────────────

function StatBlock({
  label, value, sub, icon: Icon, accent = "purple",
}: {
  label: string; value: string | number; sub?: string;
  icon: any; accent?: "purple" | "green" | "red" | "amber" | "blue";
}) {
  const colors = {
    purple: "from-violet-500/10 to-transparent border-violet-500/20 text-violet-400",
    green:  "from-emerald-500/10 to-transparent border-emerald-500/20 text-emerald-400",
    red:    "from-red-500/10 to-transparent border-red-500/20 text-red-400",
    amber:  "from-amber-500/10 to-transparent border-amber-500/20 text-amber-400",
    blue:   "from-blue-500/10 to-transparent border-blue-500/20 text-blue-400",
  };
  return (
    <div className={`glass-card p-5 bg-gradient-to-br border ${colors[accent]}`}>
      <div className="flex items-start justify-between mb-3">
        <span className="text-xs font-semibold uppercase tracking-widest text-white/40">{label}</span>
        <Icon className={`w-4 h-4 ${colors[accent].split(" ").pop()}`} />
      </div>
      <div className="text-3xl font-bold text-white tabular-nums">{value}</div>
      {sub && <div className="mt-1 text-xs text-white/35">{sub}</div>}
    </div>
  );
}

const CustomTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-zinc-900 border border-white/10 rounded-xl px-3 py-2 text-xs shadow-xl">
      {label && <p className="text-white/50 mb-1">{label}</p>}
      {payload.map((p: any, i: number) => (
        <p key={i} style={{ color: p.fill || p.color }} className="font-semibold">
          {p.name}: {p.value}
        </p>
      ))}
    </div>
  );
};

// ── Page ─────────────────────────────────────────────────────────────────────

export default function DashboardHomePage() {
  const [simulations, setSimulations] = useState<any[]>([]);
  const [summary, setSummary] = useState({ total: 0, completed: 0, running: 0, failed: 0, queued: 0 });
  const [loading, setLoading] = useState(true);
  const events = useEvents();

  const loadData = useCallback(async () => {
    try {
      const [sims, stats] = await Promise.all([
        api.getSimulations(),
        api.getSimulationSummary(),
      ]);
      setSimulations(sims);
      setSummary(stats);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  // Refresh on new events — debounce to avoid cascade
  useEffect(() => {
    if (!events.length) return;
    const t = setTimeout(loadData, 800);
    return () => clearTimeout(t);
  }, [events.length, loadData]);

  // ── Derived metrics ───────────────────────────────────────────────────────

  const allFindings = simulations.flatMap(s =>
    s.module_results?.flatMap((r: any) => r.findings || []) ?? []
  );

  const sortedFindings = [...allFindings].sort((a: any, b: any) =>
    new Date(b.timestamp || 0).getTime() - new Date(a.timestamp || 0).getTime()
  );

  // detection_score lives at: metadata.detection_validation.detection_simulation.detection_score
  const avgDetectionScore =
    simulations.length > 0
      ? Math.round(
          simulations.reduce((sum, s) =>
            sum + (s.metadata?.detection_validation?.detection_simulation?.detection_score ?? 0), 0
          ) / simulations.length
        )
      : 0;

  // coverage_percent lives at: metadata.detection_validation.blindspots.coverage_percent
  // (blindspot_analyzer returns coverage_percent as a scalar)
  const maxCoverage = simulations.length > 0
    ? Math.max(...simulations.map(s =>
        s.metadata?.detection_validation?.blindspots?.coverage_percent ?? 0
      ))
    : 0;

  // Severity breakdown for bar chart
  const severityData = [
    { name: "Critical", value: allFindings.filter((f: any) => f.severity === "critical").length, fill: "#ef4444" },
    { name: "High",     value: allFindings.filter((f: any) => f.severity === "high").length,     fill: "#f97316" },
    { name: "Medium",   value: allFindings.filter((f: any) => f.severity === "medium").length,   fill: "#f59e0b" },
    { name: "Info",     value: allFindings.filter((f: any) => f.severity === "info").length,      fill: "#3b82f6" },
  ];

  // MITRE technique frequency (from findings)
  const mitreMap: Record<string, number> = {};
  allFindings.forEach((f: any) => {
    if (f.mitre_id) mitreMap[f.mitre_id] = (mitreMap[f.mitre_id] || 0) + 1;
  });
  const mitreChartData = Object.entries(mitreMap)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([name, value]) => ({ name, value }));

  // Attack timeline
  const timeline = simulations
    .flatMap(s => [
      s.started_at  ? { time: s.started_at,  text: `${s.modules?.join(", ") || "Unknown"} — started`, status: "start" } : null,
      s.finished_at ? { time: s.finished_at, text: `${s.modules?.join(", ") || "Unknown"} — ${s.status}`, status: s.status } : null,
    ])
    .filter(Boolean)
    .sort((a: any, b: any) => new Date(b.time).getTime() - new Date(a.time).getTime())
    .slice(0, 8) as any[];

  // Recent simulations
  const recentSims = [...simulations]
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
    .slice(0, 6);

  // ── Render ────────────────────────────────────────────────────────────────

  if (loading) {
    return (
      <div className="space-y-6 animate-pulse">
        <div className="h-8 w-64 bg-white/5 rounded-xl" />
        <div className="grid grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => <div key={i} className="h-28 bg-white/5 rounded-2xl" />)}
        </div>
        <div className="grid grid-cols-2 gap-6">
          {[...Array(2)].map((_, i) => <div key={i} className="h-64 bg-white/5 rounded-2xl" />)}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Command Center</h1>
        <p className="text-sm text-white/40 mt-0.5">Executive overview of SecureForge BAS operations</p>
      </div>

      {/* Stat row */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
        <StatBlock label="Total Simulations" value={summary.total}
          sub={`${summary.completed} completed, ${summary.running} running`}
          icon={Shield} accent="purple" />
        <StatBlock label="Detection Score" value={simulations.length > 0 ? `${avgDetectionScore}%` : "N/A"}
          sub="avg across all simulations"
          icon={Eye} accent="green" />
        <StatBlock label="ATT&CK Coverage" value={simulations.length > 0 ? `${maxCoverage}%` : "N/A"}
          sub="best coverage across sims"
          icon={Target} accent="blue" />
        <StatBlock label="Total Findings" value={allFindings.length}
          sub={`${allFindings.filter((f: any) => f.severity === "critical").length} critical`}
          icon={AlertTriangle} accent="red" />
      </div>

      {/* Middle row */}
      <div className="grid xl:grid-cols-2 gap-5">
        {/* Recent Simulations */}
        <div className="glass-card p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-semibold text-sm uppercase tracking-widest text-white/50">Recent Assessments</h2>
            <span className="text-xs text-white/25">{simulations.length} total</span>
          </div>
          <div className="space-y-2">
            {recentSims.length === 0 ? (
              <p className="text-sm text-white/30 py-4 text-center">No simulations yet</p>
            ) : recentSims.map(sim => (
              <div key={sim.id}
                className="flex items-center justify-between rounded-xl border border-white/[0.06] bg-white/[0.015] px-4 py-3 hover:border-violet-500/20 transition-colors">
                <div className="min-w-0">
                  <div className="text-sm font-medium text-white truncate">{sim.name}</div>
                  <div className="text-xs text-white/35 mt-0.5 flex items-center gap-2 truncate">
                    <span className="font-mono">{sim.target}</span>
                    <span>·</span>
                    <span>{formatTs(sim.created_at)}</span>
                  </div>
                </div>
                <SimulationStatusBadge status={sim.status} />
              </div>
            ))}
          </div>
        </div>

        {/* Latest Findings */}
        <div className="glass-card p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-semibold text-sm uppercase tracking-widest text-white/50">Latest Findings</h2>
            <span className="text-xs text-white/25">{allFindings.length} total</span>
          </div>
          <div className="space-y-2">
            {sortedFindings.length === 0 ? (
              <p className="text-sm text-white/30 py-4 text-center">No findings from completed simulations</p>
            ) : sortedFindings.slice(0, 6).map((f: any, idx: number) => (
              <div key={idx}
                className="rounded-xl border border-white/[0.06] bg-white/[0.015] px-4 py-3">
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-medium text-white leading-tight">{f.title}</span>
                      {f.mitre_id && (
                        <span className="font-mono text-[10px] bg-violet-500/10 border border-violet-500/20 text-violet-300 px-1.5 py-0.5 rounded">
                          {f.mitre_id}
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-white/40 mt-1 line-clamp-1"
                      dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(f.description || "") }} />
                  </div>
                  <SeverityBadge severity={f.severity} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Charts row */}
      <div className="grid xl:grid-cols-3 gap-5">
        {/* Findings by Severity */}
        <div className="glass-card p-5">
          <h2 className="font-semibold text-sm uppercase tracking-widest text-white/50 mb-4">Findings by Severity</h2>
          {allFindings.length === 0 ? (
            <div className="h-[220px] flex items-center justify-center text-sm text-white/25">No findings yet</div>
          ) : (
            <div className="h-[220px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={severityData} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeOpacity={0.06} vertical={false} />
                  <XAxis dataKey="name" tick={{ fontSize: 11, fill: "rgba(255,255,255,0.35)" }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fontSize: 11, fill: "rgba(255,255,255,0.35)" }} axisLine={false} tickLine={false} allowDecimals={false} />
                  <Tooltip content={<CustomTooltip />} cursor={{ fill: "rgba(255,255,255,0.03)" }} />
                  <Bar dataKey="value" name="Count" radius={[4, 4, 0, 0]}>
                    {severityData.map((entry, i) => (
                      <Cell key={i} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        {/* MITRE Technique Frequency */}
        <div className="glass-card p-5">
          <h2 className="font-semibold text-sm uppercase tracking-widest text-white/50 mb-4">Top Techniques</h2>
          {mitreChartData.length === 0 ? (
            <div className="h-[220px] flex items-center justify-center text-sm text-white/25">No MITRE data</div>
          ) : (
            <div className="h-[220px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={mitreChartData} layout="vertical" margin={{ top: 0, right: 10, left: 10, bottom: 0 }}>
                  <CartesianGrid strokeOpacity={0.06} horizontal={false} />
                  <XAxis type="number" tick={{ fontSize: 10, fill: "rgba(255,255,255,0.35)" }} axisLine={false} tickLine={false} allowDecimals={false} />
                  <YAxis dataKey="name" type="category" tick={{ fontSize: 10, fill: "rgba(255,255,255,0.5)", fontFamily: "monospace" }} axisLine={false} tickLine={false} width={60} />
                  <Tooltip content={<CustomTooltip />} cursor={{ fill: "rgba(255,255,255,0.03)" }} />
                  <Bar dataKey="value" name="Count" fill="#8b5cf6" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        {/* Attack Timeline */}
        <div className="glass-card p-5">
          <h2 className="font-semibold text-sm uppercase tracking-widest text-white/50 mb-4">Attack Timeline</h2>
          {timeline.length === 0 ? (
            <div className="h-[220px] flex items-center justify-center text-sm text-white/25">No activity yet</div>
          ) : (
            <div className="space-y-3 max-h-[220px] overflow-y-auto pr-1">
              {timeline.map((ev: any, i: number) => (
                <div key={i} className="flex gap-3 items-start">
                  <div className={`mt-1 w-1.5 h-1.5 rounded-full flex-shrink-0 ${
                    ev.status === "completed" ? "bg-emerald-400" :
                    ev.status === "failed"    ? "bg-red-400" :
                    ev.status === "start"     ? "bg-violet-400" : "bg-white/20"
                  }`} />
                  <div className="min-w-0">
                    <div className="text-xs text-white/70 leading-snug">{ev.text}</div>
                    <div className="text-[10px] text-white/30 mt-0.5 font-mono">{formatTs(ev.time)}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Simulation health bar */}
      {summary.total > 0 && (
        <div className="glass-card p-5">
          <div className="flex items-center justify-between mb-3">
            <h2 className="font-semibold text-sm uppercase tracking-widest text-white/50">Simulation Health</h2>
            <div className="flex items-center gap-4 text-xs">
              {[
                { label: "Completed", val: summary.completed, color: "text-emerald-400" },
                { label: "Running",   val: summary.running,   color: "text-violet-400" },
                { label: "Failed",    val: summary.failed,    color: "text-red-400" },
              ].map(item => (
                <span key={item.label} className={`${item.color} font-semibold`}>
                  {item.val} {item.label}
                </span>
              ))}
            </div>
          </div>
          <div className="h-2 rounded-full bg-white/5 overflow-hidden flex">
            {summary.total > 0 && [
              { val: summary.completed, color: "bg-emerald-500" },
              { val: summary.running,   color: "bg-violet-500" },
              { val: summary.failed,    color: "bg-red-500" },
            ].map((seg, i) => (
              <div key={i}
                className={`h-full ${seg.color} transition-all duration-700`}
                style={{ width: `${(seg.val / summary.total) * 100}%` }}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}