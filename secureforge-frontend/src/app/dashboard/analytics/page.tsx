"use client";

import { useEffect, useState, useCallback } from "react";
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  ResponsiveContainer, CartesianGrid, Tooltip, XAxis, YAxis, Legend,
} from "recharts";
import { useEvents } from "@/hooks/useEvents";
import { Shield, CheckCircle2, XCircle, Clock, Activity } from "lucide-react";
import { api } from "@/lib/api";

// ── Custom tooltip ────────────────────────────────────────────────────────────

const CustomTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-zinc-900 border border-white/10 rounded-xl px-3 py-2 text-xs shadow-xl">
      {label && <p className="text-white/40 mb-1">{label}</p>}
      {payload.map((p: any, i: number) => (
        <p key={i} style={{ color: p.fill || p.color || p.stroke }} className="font-semibold">
          {p.name}: {p.value}
        </p>
      ))}
    </div>
  );
};

const CustomLegend = ({ payload }: any) => (
  <div className="flex flex-wrap justify-center gap-3 mt-3">
    {payload?.map((entry: any, i: number) => (
      <div key={i} className="flex items-center gap-1.5 text-xs text-white/50">
        <span className="w-2.5 h-2.5 rounded-sm flex-shrink-0" style={{ backgroundColor: entry.color }} />
        {entry.value}
      </div>
    ))}
  </div>
);

// ── Page ─────────────────────────────────────────────────────────────────────

export default function AnalyticsPage() {
  const [simulations, setSimulations] = useState<any[]>([]);
  const [summary, setSummary] = useState({ total: 0, queued: 0, running: 0, completed: 0, failed: 0 });
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
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  useEffect(() => {
    if (!events.length) return;
    const t = setTimeout(loadData, 800);
    return () => clearTimeout(t);
  }, [events.length, loadData]);

  // ── Derived data ──────────────────────────────────────────────────────────

  const allFindings = simulations.flatMap(s =>
    s.module_results?.flatMap((r: any) => r.findings || []) ?? []
  );

  // Simulation trend (grouped by date)
  const grouped = simulations.reduce((acc: Record<string, number>, s: any) => {
    const day = new Date(s.created_at).toLocaleDateString("en-US", {
      month: "short", day: "numeric", timeZone: "Asia/Kolkata",
    });
    acc[day] = (acc[day] || 0) + 1;
    return acc;
  }, {});
  const trendData = Object.entries(grouped)
    .map(([day, count]) => ({ day, count }))
    .slice(-14);

  // Execution distribution
  const pieData = [
    { name: "Completed", value: summary.completed, color: "#10b981" },
    { name: "Running",   value: summary.running,   color: "#8b5cf6" },
    { name: "Queued",    value: summary.queued,     color: "#f59e0b" },
    { name: "Failed",    value: summary.failed,     color: "#ef4444" },
  ].filter(d => d.value > 0);

  // Severity distribution
  const severityData = [
    { name: "Critical", value: allFindings.filter((f: any) => f.severity === "critical").length, color: "#ef4444" },
    { name: "High",     value: allFindings.filter((f: any) => f.severity === "high").length,     color: "#f97316" },
    { name: "Medium",   value: allFindings.filter((f: any) => f.severity === "medium").length,   color: "#f59e0b" },
    { name: "Info",     value: allFindings.filter((f: any) => f.severity === "info").length,     color: "#3b82f6" },
  ].filter(d => d.value > 0);

  // Module usage frequency
  const moduleMap: Record<string, number> = {};
  simulations.forEach((s: any) => {
    s.modules?.forEach((m: string) => {
      moduleMap[m] = (moduleMap[m] || 0) + 1;
    });
  });
  const moduleData = Object.entries(moduleMap)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([name, count]) => ({ name, count }));

  if (loading) {
    return (
      <div className="space-y-6 animate-pulse">
        <div className="h-8 w-48 bg-white/5 rounded-xl" />
        <div className="grid grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => <div key={i} className="h-24 bg-white/5 rounded-2xl" />)}
        </div>
        <div className="grid xl:grid-cols-2 gap-5">
          {[...Array(2)].map((_, i) => <div key={i} className="h-56 bg-white/5 rounded-2xl" />)}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Analytics</h1>
        <p className="text-sm text-white/40 mt-0.5">Executive overview of BAS execution activity</p>
      </div>

      {/* Metrics */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
        {[
          { label: "Total",     value: summary.total,     icon: Shield,       color: "border-violet-500/20 from-violet-500/[0.06] text-violet-400" },
          { label: "Completed", value: summary.completed, icon: CheckCircle2, color: "border-emerald-500/20 from-emerald-500/[0.06] text-emerald-400" },
          { label: "Running",   value: summary.running,   icon: Clock,        color: "border-amber-500/20 from-amber-500/[0.06] text-amber-400" },
          { label: "Failed",    value: summary.failed,    icon: XCircle,      color: "border-red-500/20 from-red-500/[0.06] text-red-400" },
        ].map(item => (
          <div key={item.label}
            className={`glass-card p-5 border bg-gradient-to-br ${item.color.split(" ").slice(0, 2).join(" ")} to-transparent`}>
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] font-bold uppercase tracking-widest text-white/40">{item.label}</span>
              <item.icon className={`w-3.5 h-3.5 ${item.color.split(" ").pop()}`} />
            </div>
            <div className="text-3xl font-bold text-white tabular-nums">{item.value}</div>
          </div>
        ))}
      </div>

      {/* Charts row 1 */}
      <div className="grid xl:grid-cols-2 gap-5">

        {/* Simulation Trend */}
        <div className="glass-card p-5">
          <div className="flex items-center gap-2 mb-4">
            <Activity className="w-3.5 h-3.5 text-violet-400" />
            <h2 className="text-[10px] font-bold uppercase tracking-widest text-white/40">Simulation Trend</h2>
          </div>
          {trendData.length === 0 ? (
            <div className="h-[220px] flex items-center justify-center text-sm text-white/25">No data yet</div>
          ) : (
            <div className="h-[220px]">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trendData} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="gradSim" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeOpacity={0.05} vertical={false} />
                  <XAxis dataKey="day" tick={{ fontSize: 10, fill: "rgba(255,255,255,0.3)" }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fontSize: 10, fill: "rgba(255,255,255,0.3)" }} axisLine={false} tickLine={false} allowDecimals={false} />
                  <Tooltip content={<CustomTooltip />} />
                  <Area type="monotone" dataKey="count" name="Simulations"
                    stroke="#8b5cf6" strokeWidth={2}
                    fill="url(#gradSim)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        {/* Execution Distribution */}
        <div className="glass-card p-5">
          <h2 className="text-[10px] font-bold uppercase tracking-widest text-white/40 mb-4">Execution Distribution</h2>
          {pieData.length === 0 ? (
            <div className="h-[220px] flex items-center justify-center text-sm text-white/25">No data yet</div>
          ) : (
            <div className="h-[220px]">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={pieData} dataKey="value" cx="50%" cy="50%"
                    innerRadius={55} outerRadius={85}
                    paddingAngle={3} strokeWidth={0}>
                    {pieData.map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip content={<CustomTooltip />} />
                  <Legend content={<CustomLegend />} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </div>

      {/* Charts row 2 */}
      <div className="grid xl:grid-cols-2 gap-5">

        {/* Findings Severity */}
        <div className="glass-card p-5">
          <h2 className="text-[10px] font-bold uppercase tracking-widest text-white/40 mb-4">Findings by Severity</h2>
          {severityData.length === 0 ? (
            <div className="h-[220px] flex items-center justify-center text-sm text-white/25">No findings yet</div>
          ) : (
            <div className="h-[220px]">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={severityData} dataKey="value" cx="50%" cy="50%"
                    innerRadius={55} outerRadius={85}
                    paddingAngle={3} strokeWidth={0}>
                    {severityData.map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip content={<CustomTooltip />} />
                  <Legend content={<CustomLegend />} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        {/* Module Usage */}
        <div className="glass-card p-5">
          <h2 className="text-[10px] font-bold uppercase tracking-widest text-white/40 mb-4">Module Usage Frequency</h2>
          {moduleData.length === 0 ? (
            <div className="h-[220px] flex items-center justify-center text-sm text-white/25">No modules run yet</div>
          ) : (
            <div className="h-[220px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={moduleData} layout="vertical" margin={{ top: 0, right: 10, left: 20, bottom: 0 }}>
                  <CartesianGrid strokeOpacity={0.05} horizontal={false} />
                  <XAxis type="number" tick={{ fontSize: 10, fill: "rgba(255,255,255,0.3)" }} axisLine={false} tickLine={false} allowDecimals={false} />
                  <YAxis dataKey="name" type="category" tick={{ fontSize: 10, fill: "rgba(255,255,255,0.5)", fontFamily: "monospace" }}
                    axisLine={false} tickLine={false} width={90} />
                  <Tooltip content={<CustomTooltip />} cursor={{ fill: "rgba(255,255,255,0.02)" }} />
                  <Bar dataKey="count" name="Runs" fill="#8b5cf6" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </div>

      {/* Simulation history table */}
      {simulations.length > 0 && (
        <div className="glass-card p-5">
          <h2 className="text-[10px] font-bold uppercase tracking-widest text-white/40 mb-4">Simulation History</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-white/[0.06]">
                  {["Name", "Target", "Modules", "Findings", "Status", "Created"].map(h => (
                    <th key={h} className="text-left text-[10px] font-bold uppercase tracking-widest text-white/30 pb-3 pr-4">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {[...simulations]
                  .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
                  .slice(0, 20)
                  .map(sim => {
                    const findingCount = sim.module_results?.flatMap((r: any) => r.findings || []).length ?? 0;
                    const critCount = sim.module_results?.flatMap((r: any) => r.findings || [])
                      .filter((f: any) => f.severity === "critical").length ?? 0;
                    const statusColors: Record<string, string> = {
                      completed: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
                      running:   "text-violet-400 bg-violet-500/10 border-violet-500/20",
                      failed:    "text-red-400 bg-red-500/10 border-red-500/20",
                      queued:    "text-amber-400 bg-amber-500/10 border-amber-500/20",
                    };
                    const sc = statusColors[sim.status] || "text-white/40 bg-white/5 border-white/10";
                    return (
                      <tr key={sim.id} className="border-b border-white/[0.04] hover:bg-white/[0.015] transition-colors">
                        <td className="py-3 pr-4 font-medium text-white">{sim.name}</td>
                        <td className="py-3 pr-4 font-mono text-xs text-white/50">{sim.target}</td>
                        <td className="py-3 pr-4 text-xs text-white/50">{sim.modules?.join(", ") || "—"}</td>
                        <td className="py-3 pr-4">
                          <span className="text-sm font-semibold text-white tabular-nums">{findingCount}</span>
                          {critCount > 0 && (
                            <span className="ml-1 text-[10px] text-red-400">({critCount} crit)</span>
                          )}
                        </td>
                        <td className="py-3 pr-4">
                          <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${sc}`}>
                            {sim.status}
                          </span>
                        </td>
                        <td className="py-3 pr-4 text-xs text-white/35 font-mono">
                          {new Date(sim.created_at).toLocaleDateString("en-US", {
                            month: "short", day: "numeric",
                            hour: "2-digit", minute: "2-digit", hour12: false, timeZone: "Asia/Kolkata",
                          })}
                        </td>
                      </tr>
                    );
                  })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}