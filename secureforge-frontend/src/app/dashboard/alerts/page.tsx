"use client";

import { useEffect, useState } from "react";
import {
  Bell,
  Webhook,
  Mail,
  Plus,
  AlertCircle,
  CheckCircle2,
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

export default function AlertsPage() {
  const [simulations, setSimulations] =
    useState<any[]>([]);
  const events = useEvents();

  useEffect(() => {
    loadData();
  }, []);

  async function loadData() {
    try {
      const data =
        await api.getSimulations();

      setSimulations(data);
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

        <button className="flex items-center gap-2 px-4 py-2 bg-amber-600 hover:bg-amber-700 text-white rounded-md text-sm font-semibold transition-colors">
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
                    {
                      alert.description
                    }
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

          {mockIntegrations.map(
            (
              integration,
              idx
            ) => {
              const Icon =
                integration.icon;

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
    </div>
  );
}