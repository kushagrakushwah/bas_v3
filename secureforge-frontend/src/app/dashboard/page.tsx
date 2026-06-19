"use client";

import { useEffect, useState } from "react";
import { Shield, Target, AlertTriangle, Activity } from "lucide-react";
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { useEvents } from "@/hooks/useEvents";
import PageHeader from "@/components/ui/PageHeader";
import MetricCard from "@/components/MetricCard";
import SimulationStatusBadge from "@/components/SimulationStatusBadge";
import SeverityBadge from "@/components/ui/SeverityBadge";
import { api } from "@/lib/api";

export default function DashboardHomePage() {
  const [simulations, setSimulations] = useState<any[]>([]);

  const [summary, setSummary] = useState({
    total: 0,
    completed: 0,
    running: 0,
    failed: 0,
  });
  const events = useEvents();

  useEffect(() => {
    loadData();
  }, []);
  useEffect(() => {

    if (!events.length)
        return;

    loadData();

    }, [events]);

  async function loadData() {
    try {
      const sims = await api.getSimulations();
      const stats = await api.getSimulationSummary();

      setSimulations(sims);
      setSummary(stats);
    } catch (err) {
      console.error(err);
    }
  }

  const totalFindings = simulations.reduce(
    (sum, simulation) =>
      sum +
      (simulation.module_results?.reduce(
        (innerSum: number, result: any) =>
          innerSum + (result.findings?.length || 0),
        0
      ) || 0),
    0
  );

  const avgSocScore =
    simulations.length > 0
      ? Math.round(
          simulations.reduce(
            (sum: number, simulation: any) =>
              sum +
              (simulation.metadata?.detection_validation?.soc_score
                ?.soc_score || 0),
            0
          ) / simulations.length
        )
      : 0;

  const coverage =
    simulations.length > 0
      ? Math.max(
          ...simulations.map(
            (simulation: any) =>
              simulation.metadata?.detection_validation?.blindspots
                ?.coverage_percent || 0
          )
        )
      : 0;

    const findings = simulations
    .flatMap(
        (simulation: any) =>
        simulation.module_results?.flatMap(
            (result: any) =>
            result.findings || []
        ) || []
    )
    .sort(
        (a: any, b: any) =>
        new Date(
            b.timestamp || 0
        ).getTime() -
        new Date(
            a.timestamp || 0
        ).getTime()
    );

  const severityData = [
    {
      name: "Critical",
      value: findings.filter((f: any) => f.severity === "critical").length,
    },
    {
      name: "High",
      value: findings.filter((f: any) => f.severity === "high").length,
    },
    {
      name: "Medium",
      value: findings.filter((f: any) => f.severity === "medium").length,
    },
    {
      name: "Info",
      value: findings.filter((f: any) => f.severity === "info").length,
    },
  ];

  const mitreMap: Record<string, number> = {};

  findings.forEach((finding: any) => {
    const id = finding.mitre_id || "Unknown";
    mitreMap[id] = (mitreMap[id] || 0) + 1;
  });

  const mitreData = Object.entries(mitreMap).map(([name, value]) => ({
    name,
    value,
  }));

  const timeline = simulations
    .flatMap((simulation: any) => [
      {
        time: simulation.started_at,
        text: `${simulation.modules?.join(", ")} Started`,
      },
      {
        time: simulation.finished_at,
        text: `${simulation.modules?.join(", ")} Completed`,
      },
    ])
    .filter((event) => event.time)
    .sort(
      (a, b) => new Date(b.time).getTime() - new Date(a.time).getTime()
    )
    .slice(0, 10);

  return (
    <div className="space-y-8">
      <PageHeader
        title="Command Center"
        description="Executive overview of SecureForge BAS operations."
      />

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        <MetricCard
          title="Total Simulations"
          value={summary.total}
          icon={Shield}
        />

        <MetricCard
          title="SOC Score"
          value={avgSocScore}
          icon={Target}
          color="green"
        />

        <MetricCard
          title="Coverage"
          value={`${coverage}%`}
          icon={Activity}
          color="purple"
        />

        <MetricCard
          title="Open Findings"
          value={totalFindings}
          icon={AlertTriangle}
          color="red"
        />
      </div>

      <div className="grid xl:grid-cols-2 gap-8">
        {/* Recent Simulations */}
        <div className="glass-card p-8">
          <h2 className="text-2xl font-bold mb-6">Recent Assessments</h2>

          <div className="space-y-4">
            {[...simulations]
              .sort(
                (a: any, b: any) =>
                  new Date(b.created_at).getTime() -
                  new Date(a.created_at).getTime()
              )
              .slice(0, 5)
              .map((simulation) => (
                <div
                  key={simulation.id}
                  className="flex items-center justify-between rounded-xl border border-white/10 p-4"
                >
                  <div>
                    <div className="font-medium">{simulation.name}</div>

                    <div className="text-sm text-white/50">
                      {simulation.target}
                    </div>
                  </div>

                  <SimulationStatusBadge status={simulation.status} />
                </div>
              ))}
          </div>
        </div>

        {/* Latest Findings */}
        <div className="glass-card p-8">
          <h2 className="text-2xl font-bold mb-6">Latest Findings</h2>

          <div className="space-y-4">
            {findings.length === 0 ? (
              <div className="text-white/50">No findings available.</div>
            ) : (
              findings.slice(0, 10).map((finding: any, index: number) => (
                <div
                  key={index}
                  className="rounded-xl border border-white/10 p-4"
                >
                  <div className="flex items-center justify-between">
                    <div className="font-medium">{finding.title}</div>

                    <SeverityBadge severity={finding.severity} />
                  </div>

                  <div className="mt-2 text-sm text-white/60">
                    {finding.description}
                  </div>

                  <div className="mt-2 text-xs text-purple-300">
                    {finding.mitre_id}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      <div className="grid xl:grid-cols-3 gap-8">
        {/* Findings Severity */}
        <div className="glass-card p-8">
          <h2 className="text-2xl font-bold mb-6">Findings by Severity</h2>

          <div className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityData}>
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />

                <Bar dataKey="value" fill="#8b5cf6" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* MITRE Coverage */}
        <div className="glass-card p-8">
          <h2 className="text-2xl font-bold mb-6">MITRE Coverage</h2>

          <div className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={mitreData} dataKey="value" outerRadius={90}>
                  {mitreData.map((entry, index) => (
                    <Cell
                      key={index}
                      fill={
                        ["#8b5cf6", "#10b981", "#f59e0b", "#ef4444"][
                          index % 4
                        ]
                      }
                    />
                  ))}
                </Pie>

                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Timeline */}
        <div className="glass-card p-8">
          <h2 className="text-2xl font-bold mb-6">Recent Attack Timeline</h2>

          <div className="space-y-4">
            {timeline.map((event, index) => (
              <div key={index} className="border-l border-purple-500 pl-4">
                <div className="text-xs text-white/40">
                  {new Date(event.time.endsWith('Z') ? event.time : event.time + 'Z').toLocaleString('en-US', { timeZone: 'Asia/Kolkata' })}
                </div>

                <div className="mt-1">{event.text}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}