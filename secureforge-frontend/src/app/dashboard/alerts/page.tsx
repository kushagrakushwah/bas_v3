"use client";

import { useEffect, useState, useCallback } from "react";
import DOMPurify from "dompurify";
import {
  Bell, Webhook, Mail, Plus, AlertCircle,
  CheckCircle2, Trash2, X, FileText, FileDown,
  ShieldAlert, Info, AlertTriangle,
} from "lucide-react";
import { api } from "@/lib/api";
import { generateMarkdownReport, generatePDFReport } from "@/lib/reports";

// ── Helpers ──────────────────────────────────────────────────────────────────

function formatTs(ts: string | null | undefined): string {
  if (!ts) return "Not started";
  const s = ts.endsWith("Z") ? ts : ts + "Z";
  return new Date(s).toLocaleString("en-US", {
    timeZone: "Asia/Kolkata",
    month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit", hour12: false,
  });
}

const typeToIcon: Record<string, any> = {
  Webhook, SMTP: Mail, API: Bell,
};

// ── Page ─────────────────────────────────────────────────────────────────────

export default function AlertsPage() {
  const [simulations, setSimulations] = useState<any[]>([]);
  const [integrations, setIntegrations] = useState<any[]>([]);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [newInt, setNewInt] = useState({ name: "", type: "Webhook", target: "" });
  const [selectedSims, setSelectedSims] = useState<string[]>([]);
  const [selectAll, setSelectAll] = useState(false);

  const loadData = useCallback(async () => {
    try {
      const [sims, ints] = await Promise.all([
        api.getSimulations(),
        api.getIntegrations(),
      ]);
      setSimulations(sims);
      setIntegrations(ints);
    } catch (err) {
      console.error(err);
    }
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  // ── Handlers ──────────────────────────────────────────────────────────────

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    try {
      const created = await api.createIntegration(newInt);
      setIntegrations(prev => [...prev, created]);
      setIsModalOpen(false);
      setNewInt({ name: "", type: "Webhook", target: "" });
    } catch (err) {
      console.error(err);
    }
  }

  async function handleDelete(id: string) {
    try {
      await api.deleteIntegration(id);
      setIntegrations(prev => prev.filter(i => i.id !== id));
    } catch (err) {
      console.error(err);
    }
  }

  const handleDownloadMarkdown = async () => {
    const simsToExport = selectAll
      ? simulations
      : simulations.filter(s => selectedSims.includes(s.id));
    if (simsToExport.length === 1) {
      try {
        const token = localStorage.getItem("token") || "";
        const res = await fetch(`/api/proxy/api/v1/reports/${simsToExport[0].id}/markdown`, {
          headers: { "Authorization": `Bearer ${token}` },
        });
        if (!res.ok) throw new Error("Backend report failed");
        const md = await res.text();
        const blob = new Blob([md], { type: "text/markdown" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `SecureForge_Report_${simsToExport[0].name}.md`;
        a.click();
        URL.revokeObjectURL(url);
        return;
      } catch (err) {
        console.error("Falling back to frontend report generation.", err);
      }
    }
    const md = generateMarkdownReport(simsToExport);
    const blob = new Blob([md], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "SecureForge_Report.md";
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadPDF = () => {
    const simsToExport = selectAll
      ? simulations
      : simulations.filter(s => selectedSims.includes(s.id));
    generatePDFReport(simsToExport);
  };

  // ── Generated alerts (correct schema) ─────────────────────────────────────
  // Reads from the new detection_validation structure:
  //   .detection_simulation.blind_spots_tactics
  //   .attack_surface.exposure_score
  //   findings from module_results[].findings

  const generatedAlerts = simulations.flatMap((sim: any) => {
    const alerts: any[] = [];
    const dv = sim?.metadata?.detection_validation;
    if (!dv) {
      if (sim.status === "failed") {
        alerts.push({ severity: "critical", title: "Simulation Failed", description: sim.name, ts: sim.updated_at });
      }
      return alerts;
    }

    const exposureScore = dv?.attack_surface?.exposure_score ?? 0;
    if (exposureScore > 60) {
      alerts.push({
        severity: "critical",
        title: "High Exposure Score Detected",
        description: `${sim.name} scored ${exposureScore.toFixed(0)} on the attacker exposure index (threshold: 60).`,
        ts: sim.finished_at,
        sim: sim.name,
      });
    }

    const blindSpots: string[] = dv?.detection_simulation?.blind_spots_tactics ?? [];
    if (blindSpots.length >= 7) {
      alerts.push({
        severity: "high",
        title: "Critical Coverage Gap",
        description: `${sim.name} has ${blindSpots.length} undetected ATT&CK tactics: ${blindSpots.slice(0, 3).join(", ")}${blindSpots.length > 3 ? " +" + (blindSpots.length - 3) + " more" : ""}.`,
        ts: sim.finished_at,
        sim: sim.name,
      });
    }

    const findings = sim.module_results?.flatMap((r: any) => r.findings || []) ?? [];
    findings.forEach((f: any) => {
      if (f.severity === "critical" || f.severity === "high") {
        alerts.push({
          severity: f.severity,
          title: f.title,
          description: f.description,
          ts: f.timestamp,
          sim: sim.name,
        });
      }
    });

    if (sim.status === "failed") {
      alerts.push({
        severity: "critical",
        title: "Simulation Failed",
        description: sim.name,
        ts: sim.updated_at,
        sim: sim.name,
      });
    }

    return alerts;
  });

  // Group by severity
  const criticalAlerts = generatedAlerts.filter(a => a.severity === "critical");
  const highAlerts     = generatedAlerts.filter(a => a.severity === "high");
  const otherAlerts    = generatedAlerts.filter(a => a.severity !== "critical" && a.severity !== "high");

  const simsToExport = selectAll
    ? simulations
    : simulations.filter(s => selectedSims.includes(s.id));
  const canExport = simsToExport.length > 0;

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Reports & Alerts</h1>
          <p className="text-sm text-white/40 mt-0.5">Notification pipelines, active alerts, and report export</p>
        </div>
        <button
          onClick={() => setIsModalOpen(true)}
          className="flex items-center gap-2 px-4 py-2 rounded-xl border border-violet-500/25 bg-violet-500/10 text-violet-300 hover:bg-violet-500/20 hover:border-violet-500/40 transition-all text-sm font-semibold"
        >
          <Plus className="w-4 h-4" />
          New Integration
        </button>
      </div>

      {/* Alert Summary */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: "Critical Alerts", value: criticalAlerts.length, color: "border-red-500/20 from-red-500/[0.06] text-red-400" },
          { label: "High Alerts",     value: highAlerts.length,     color: "border-orange-500/20 from-orange-500/[0.06] text-orange-400" },
          { label: "Other",           value: otherAlerts.length,    color: "border-white/10 from-white/[0.03] text-white/50" },
        ].map(item => (
          <div key={item.label}
            className={`glass-card p-4 border bg-gradient-to-br ${item.color.split(" ").slice(0, 2).join(" ")} to-transparent`}>
            <div className="text-[10px] font-bold uppercase tracking-widest text-white/40 mb-2">{item.label}</div>
            <div className={`text-2xl font-bold tabular-nums ${item.color.split(" ").pop()}`}>{item.value}</div>
          </div>
        ))}
      </div>

      {/* Split: Alerts + Integrations */}
      <div className="grid xl:grid-cols-2 gap-5">

        {/* Active Alerts */}
        <div className="glass-card p-5">
          <h2 className="text-[10px] font-bold uppercase tracking-widest text-white/40 mb-4">Active Security Alerts</h2>
          {generatedAlerts.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-10 text-center">
              <CheckCircle2 className="w-8 h-8 text-white/15 mb-3" />
              <p className="text-sm text-white/30">No active alerts</p>
              <p className="text-xs text-white/20 mt-1">Run a simulation to generate alerts</p>
            </div>
          ) : (
            <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
              {[...criticalAlerts, ...highAlerts, ...otherAlerts].map((alert, idx) => {
                const sevConfig: Record<string, { icon: any; color: string; bg: string; border: string }> = {
                  critical: { icon: ShieldAlert,    color: "text-red-400",    bg: "bg-red-500/[0.05]",    border: "border-red-500/20" },
                  high:     { icon: AlertTriangle,  color: "text-orange-400", bg: "bg-orange-500/[0.05]", border: "border-orange-500/20" },
                  warning:  { icon: AlertTriangle,  color: "text-amber-400",  bg: "bg-amber-500/[0.05]",  border: "border-amber-500/20" },
                  info:     { icon: Info,            color: "text-blue-400",   bg: "bg-blue-500/[0.05]",   border: "border-blue-500/20" },
                };
                const c = sevConfig[alert.severity] || sevConfig.info;
                const Icon = c.icon;
                return (
                  <div key={idx}
                    className={`rounded-xl border ${c.border} ${c.bg} px-4 py-3`}>
                    <div className="flex items-start gap-3">
                      <Icon className={`w-4 h-4 mt-0.5 flex-shrink-0 ${c.color}`} />
                      <div className="min-w-0 flex-1">
                        <div className="text-sm font-semibold text-white">{alert.title}</div>
                        {alert.sim && (
                          <div className="text-[10px] text-white/30 font-mono mt-0.5">{alert.sim}</div>
                        )}
                        <p className="text-xs text-white/50 mt-1 line-clamp-2"
                          dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(alert.description || "") }} />
                      </div>
                      <div className="text-[10px] text-white/25 whitespace-nowrap">{formatTs(alert.ts)}</div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Integrations */}
        <div className="glass-card p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-[10px] font-bold uppercase tracking-widest text-white/40">Configured Endpoints</h2>
            <span className="text-xs text-white/25">{integrations.length} configured</span>
          </div>
          {integrations.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-8 text-center">
              <Bell className="w-7 h-7 text-white/15 mb-3" />
              <p className="text-sm text-white/30">No integrations configured</p>
              <p className="text-xs text-white/20 mt-1">Add a Webhook or SMTP endpoint above</p>
            </div>
          ) : (
            <div className="space-y-2">
              {integrations.map((integration: any, idx: number) => {
                const Icon = typeToIcon[integration.type] || Bell;
                const active = integration.status === "Active";
                return (
                  <div key={idx}
                    className="flex items-center justify-between rounded-xl border border-white/[0.06] bg-white/[0.02] px-4 py-3">
                    <div className="flex items-center gap-3 min-w-0">
                      <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${
                        active ? "bg-emerald-500/10" : "bg-red-500/10"
                      }`}>
                        <Icon className={`w-4 h-4 ${active ? "text-emerald-400" : "text-red-400"}`} />
                      </div>
                      <div className="min-w-0">
                        <div className="text-sm font-medium text-white truncate">{integration.name}</div>
                        <div className="text-[10px] text-white/30 font-mono truncate w-40">{integration.target}</div>
                      </div>
                    </div>
                    <div className="flex items-center gap-3 flex-shrink-0">
                      <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${
                        active
                          ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/20"
                          : "text-red-400 bg-red-500/10 border-red-500/20"
                      }`}>
                        {active ? "Active" : "Failed"}
                      </span>
                      <button
                        onClick={() => handleDelete(integration.id)}
                        className="p-1.5 text-white/20 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-all"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* Routing Policies */}
          <div className="mt-4 border-t border-white/[0.06] pt-4 space-y-2">
            <h3 className="text-[10px] font-bold uppercase tracking-widest text-white/30 mb-2">Routing Policies</h3>
            {[
              { title: "Critical Finding Detected", desc: "Route High/Critical findings to Slack & PagerDuty." },
              { title: "Simulation Failed",         desc: "Route BAS engine failures to executive email." },
            ].map(p => (
              <div key={p.title} className="rounded-xl border border-white/[0.05] bg-white/[0.015] px-3 py-2.5">
                <div className="text-xs font-semibold text-white/70">{p.title}</div>
                <div className="text-[10px] text-white/35 mt-0.5">{p.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Report Generation */}
      <div className="glass-card p-5">
        <h2 className="text-[10px] font-bold uppercase tracking-widest text-white/40 mb-4">Simulation Reports</h2>
        <div className="flex flex-col gap-4">
          {/* Select All */}
          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="selectAll"
              checked={selectAll}
              onChange={e => {
                setSelectAll(e.target.checked);
                setSelectedSims(e.target.checked ? simulations.map(s => s.id) : []);
              }}
              className="w-4 h-4 rounded accent-violet-500"
            />
            <label htmlFor="selectAll" className="text-sm font-medium text-white/70">
              Select All Simulations
            </label>
          </div>

          {/* Per-sim selection */}
          {!selectAll && (
            <div className="flex flex-col gap-1 max-h-40 overflow-y-auto rounded-xl border border-white/[0.06] bg-black/30 p-3">
              {simulations.length === 0 ? (
                <span className="text-sm text-white/30">No simulations available</span>
              ) : simulations.map(sim => (
                <label key={sim.id} className="flex items-center gap-2 text-sm text-white/60 hover:text-white cursor-pointer py-1">
                  <input
                    type="checkbox"
                    checked={selectedSims.includes(sim.id)}
                    onChange={e => {
                      setSelectedSims(prev =>
                        e.target.checked ? [...prev, sim.id] : prev.filter(id => id !== sim.id)
                      );
                    }}
                    className="w-3.5 h-3.5 rounded accent-violet-500"
                  />
                  <span className="font-medium">{sim.name}</span>
                  <span className="text-xs text-white/30 font-mono ml-auto">
                    {/* BUG FIX: Guard against null started_at */}
                    {formatTs(sim.started_at)}
                  </span>
                </label>
              ))}
            </div>
          )}

          {/* Export buttons */}
          <div className="flex gap-3">
            <button
              onClick={handleDownloadPDF}
              disabled={!canExport}
              className="flex items-center gap-2 px-4 py-2 rounded-xl border border-violet-500/25 bg-violet-500/10 text-violet-300 hover:bg-violet-500/20 text-sm font-semibold transition-all disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <FileDown className="w-4 h-4" />
              Export PDF
            </button>
            <button
              onClick={handleDownloadMarkdown}
              disabled={!canExport}
              className="flex items-center gap-2 px-4 py-2 rounded-xl border border-white/10 bg-white/[0.03] text-white/60 hover:bg-white/[0.06] text-sm font-semibold transition-all disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <FileText className="w-4 h-4" />
              Export Markdown
            </button>
          </div>
        </div>
      </div>

      {/* New Integration Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-zinc-950 border border-white/10 rounded-2xl w-full max-w-md p-6 shadow-2xl">
            <div className="flex justify-between items-center mb-5">
              <h2 className="text-lg font-bold text-white">New Integration</h2>
              <button onClick={() => setIsModalOpen(false)}
                className="text-white/30 hover:text-white p-1.5 rounded-lg hover:bg-white/5 transition-all">
                <X className="w-4 h-4" />
              </button>
            </div>
            <form onSubmit={handleCreate} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-white/40 uppercase tracking-wider mb-1.5">Name</label>
                <input
                  type="text" required
                  value={newInt.name}
                  onChange={e => setNewInt({ ...newInt, name: e.target.value })}
                  className="w-full bg-black/50 border border-white/10 rounded-xl px-3 py-2.5 text-sm text-white focus:outline-none focus:border-violet-500/50"
                  placeholder="e.g. Security Slack Channel"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-white/40 uppercase tracking-wider mb-1.5">Type</label>
                <select
                  value={newInt.type}
                  onChange={e => setNewInt({ ...newInt, type: e.target.value })}
                  className="w-full bg-black/50 border border-white/10 rounded-xl px-3 py-2.5 text-sm text-white focus:outline-none focus:border-violet-500/50"
                >
                  <option value="Webhook">Webhook (Slack / Teams)</option>
                  <option value="SMTP">Email (SMTP)</option>
                </select>
              </div>
              <div>
                <label className="block text-xs font-semibold text-white/40 uppercase tracking-wider mb-1.5">
                  Target {newInt.type === "SMTP" ? "Email" : "URL"}
                </label>
                <input
                  type="text" required
                  value={newInt.target}
                  onChange={e => setNewInt({ ...newInt, target: e.target.value })}
                  className="w-full bg-black/50 border border-white/10 rounded-xl px-3 py-2.5 text-sm text-white focus:outline-none focus:border-violet-500/50 font-mono"
                  placeholder={newInt.type === "SMTP" ? "security@company.com" : "https://hooks.slack.com/..."}
                />
              </div>
              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-4 py-2 text-sm text-white/50 hover:text-white transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl bg-violet-600 hover:bg-violet-700 text-white text-sm font-semibold transition-colors"
                >
                  Save Integration
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}