"use client";

import { useEffect, useState } from "react";
import DOMPurify from "dompurify";
import {
  Bell,
  Webhook,
  Mail,
  Plus,
  AlertCircle,
  CheckCircle2,
  Trash2,
  X
} from "lucide-react";

import { api } from "@/lib/api";
import { useEvents } from "@/hooks/useEvents";
const mockIntegrations = [
  {
    name: "SOC Slack Channel",
    type: "Webhook",
    status: "Active",
    target:
      "https://hooks.slack.com/services/T000...",
    icon: Webhook,
  },
  {
    name: "Executive Email Alert",
    type: "SMTP",
    status: "Active",
    target:
      "security-leadership@company.com",
    icon: Mail,
  },
  {
    name: "PagerDuty Trigger",
    type: "API",
    status: "Error",
    target:
      "api.pagerduty.com/v2/enqueue",
    icon: Bell,
  },
];

const typeToIcon = {
  Webhook: Webhook,
  SMTP: Mail,
  API: Bell,
} as Record<string, any>;

export default function AlertsPage() {
  const [simulations, setSimulations] =
    useState<any[]>([]);
  const [integrations, setIntegrations] =
    useState<any[]>([]);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [newInt, setNewInt] = useState({ name: "", type: "Webhook", target: "" });
  const events = useEvents();

  useEffect(() => {
    loadData();
  }, []);

  async function loadData() {
    try {
      const data =
        await api.getSimulations();

      setSimulations(data);

      const integrationsData =
        await api.getIntegrations();

      setIntegrations(integrationsData);
    } catch (err) {
      console.error(err);
    }
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    try {
      const created = await api.createIntegration(newInt);
      setIntegrations([...integrations, created]);
      setIsModalOpen(false);
      setNewInt({ name: "", type: "Webhook", target: "" });
    } catch (err) {
      console.error(err);
    }
  }

  async function handleDelete(id: string) {
    try {
      await api.deleteIntegration(id);
      setIntegrations(integrations.filter((i) => i.id !== id));
    } catch (err) {
      console.error(err);
    }
  }

  const generatedAlerts =
    simulations.flatMap(
      (simulation: any) => {
        const alerts: any[] = [];

        const validation =
          simulation?.metadata
            ?.detection_validation;

        if (!validation)
          return alerts;

        const risk =
          validation?.blindspots
            ?.risk_level;

        if (risk === "High") {
          alerts.push({
            severity: "critical",
            title:
              "High Risk Assessment",
            description: `${simulation.name} produced a HIGH risk rating.`,
          });
        }

        const tactics =
          validation?.blindspots
            ?.detected_tactics || [];

        tactics.forEach(
          (tactic: string) => {
            alerts.push({
              severity: "warning",
              title: `${tactic} Detected`,
              description: `${simulation.name} detected ATT&CK tactic: ${tactic}`,
            });
          }
        );

        const findings =
          simulation.module_results?.flatMap(
            (result: any) =>
              result.findings || []
          ) || [];

        findings.forEach(
          (finding: any) => {
            if (
              finding.severity ===
                "critical" ||
              finding.severity ===
                "high"
            ) {
              alerts.push({
                severity:
                  finding.severity,
                title:
                  finding.title,
                description:
                  finding.description,
              });
            }
          }
        );

        if (
          simulation.status ===
          "failed"
        ) {
          alerts.push({
            severity: "critical",
            title:
              "Simulation Failed",
            description:
              simulation.name,
          });
        }

        return alerts;
      }
    );

  return (
    <div className="space-y-8">
      <div className="flex justify-between items-end">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white flex items-center gap-3">
            <Bell className="w-8 h-8 text-amber-500" />
            Alerting & Webhooks
          </h1>

          <p className="text-sm text-zinc-400 mt-1">
            Manage notification
            pipelines and external
            SIEM/SOAR integrations.
          </p>
        </div>

        <button 
          onClick={() => setIsModalOpen(true)}
          className="flex items-center gap-2 px-4 py-2 bg-amber-600 hover:bg-amber-700 text-white rounded-md text-sm font-semibold transition-colors"
        >
          <Plus className="w-4 h-4" />
          New Integration
        </button>
      </div>

      {/* Real Security Alerts */}

      <div className="glass-card p-8">
        <h2 className="text-2xl font-bold mb-6">
          Active Security Alerts
        </h2>

        {generatedAlerts.length ===
        0 ? (
          <div className="text-white/50">
            No active alerts.
          </div>
        ) : (
          <div className="space-y-4">
            {generatedAlerts.map(
              (alert, idx) => (
                <div
                  key={idx}
                  className={`
                    rounded-xl
                    border
                    p-4
                    ${
                      alert.severity ===
                      "critical"
                        ? "border-red-500/20 bg-red-500/10"
                        : "border-amber-500/20 bg-amber-500/10"
                    }
                  `}
                >
                  <div className="font-semibold">
                    {alert.title}
                  </div>

                  <div className="text-sm text-white/60 mt-2">
                    <span dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(alert.description) }} />
                  </div>
                </div>
              )
            )}
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Active Integrations */}

        <div className="space-y-4">
          <h2 className="text-sm font-semibold text-white border-b border-border pb-2">
            Configured Endpoints
          </h2>

          {integrations.map(
            (
              integration,
              idx
            ) => {
              const Icon =
                typeToIcon[integration.type] || Bell;

              return (
                <div
                  key={idx}
                  className="p-4 bg-black border border-border rounded-xl flex items-center justify-between"
                >
                  <div className="flex items-center gap-4">
                    <div
                      className={`p-2 rounded-lg ${
                        integration.status ===
                        "Active"
                          ? "bg-emerald-950/30 text-emerald-400"
                          : "bg-red-950/30 text-red-400"
                      }`}
                    >
                      <Icon className="w-5 h-5" />
                    </div>

                    <div>
                      <h3 className="text-sm font-bold text-white">
                        {
                          integration.name
                        }
                      </h3>

                      <p className="text-xs text-zinc-500 font-mono mt-1 truncate w-48">
                        {
                          integration.target
                        }
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-4">
                    {integration.status ===
                    "Active" ? (
                      <span className="flex items-center gap-1 text-xs text-emerald-500 bg-emerald-950/40 px-2 py-1 rounded border border-emerald-900/50">
                        <CheckCircle2 className="w-3 h-3" />
                        Active
                      </span>
                    ) : (
                      <span className="flex items-center gap-1 text-xs text-red-500 bg-red-950/40 px-2 py-1 rounded border border-red-900/50">
                        <AlertCircle className="w-3 h-3" />
                        Failed
                      </span>
                    )}

                    <button 
                      onClick={() => handleDelete(integration.id)}
                      className="p-1.5 text-red-500 hover:bg-red-500/10 rounded-md transition-colors"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              );
            }
          )}
        </div>

        {/* Routing Policies */}

        <div className="space-y-4">
          <h2 className="text-sm font-semibold text-white border-b border-border pb-2">
            Routing Policies
          </h2>

          <div className="p-5 bg-zinc-900/50 border border-border rounded-xl">
            <h3 className="text-sm font-semibold text-white">
              Critical Finding
              Detected
            </h3>

            <p className="text-xs text-zinc-400 mt-2">
              Route High/Critical
              findings to Slack &
              PagerDuty.
            </p>
          </div>

          <div className="p-5 bg-zinc-900/50 border border-border rounded-xl">
            <h3 className="text-sm font-semibold text-white">
              Simulation Failed
            </h3>

            <p className="text-xs text-zinc-400 mt-2">
              Route BAS engine
              failures to executive
              email.
            </p>
          </div>
        </div>
      </div>

      {/* MODAL */}
      {isModalOpen && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4">
          <div className="bg-zinc-950 border border-white/10 rounded-xl w-full max-w-md p-6">
            <div className="flex justify-between items-center mb-6">
              <h2 className="text-xl font-bold text-white">New Integration</h2>
              <button onClick={() => setIsModalOpen(false)} className="text-white/50 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>
            
            <form onSubmit={handleCreate} className="space-y-4">
              <div>
                <label className="block text-sm text-zinc-400 mb-1">Name</label>
                <input 
                  type="text" 
                  required
                  value={newInt.name}
                  onChange={(e) => setNewInt({...newInt, name: e.target.value})}
                  className="w-full bg-black border border-white/10 rounded-md px-3 py-2 text-white focus:outline-none focus:border-amber-500" 
                  placeholder="e.g. Security Slack Channel"
                />
              </div>
              
              <div>
                <label className="block text-sm text-zinc-400 mb-1">Type</label>
                <select 
                  value={newInt.type}
                  onChange={(e) => setNewInt({...newInt, type: e.target.value})}
                  className="w-full bg-black border border-white/10 rounded-md px-3 py-2 text-white focus:outline-none focus:border-amber-500"
                >
                  <option value="Webhook">Webhook (Slack/Teams/etc)</option>
                  <option value="SMTP">Email (SMTP)</option>
                </select>
              </div>

              <div>
                <label className="block text-sm text-zinc-400 mb-1">Target URL / Email</label>
                <input 
                  type="text" 
                  required
                  value={newInt.target}
                  onChange={(e) => setNewInt({...newInt, target: e.target.value})}
                  className="w-full bg-black border border-white/10 rounded-md px-3 py-2 text-white focus:outline-none focus:border-amber-500" 
                  placeholder={newInt.type === "SMTP" ? "security@company.com" : "https://hooks.slack.com/..."}
                />
              </div>

              <div className="pt-4 flex justify-end gap-3">
                <button 
                  type="button" 
                  onClick={() => setIsModalOpen(false)}
                  className="px-4 py-2 text-sm text-white/70 hover:text-white"
                >
                  Cancel
                </button>
                <button 
                  type="submit" 
                  className="px-4 py-2 bg-amber-600 hover:bg-amber-700 text-white rounded-md text-sm font-semibold transition-colors"
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