"use client";

import { useEffect, useState } from "react";
import {
  AreaChart,
  Area,
  ResponsiveContainer,
  CartesianGrid,
  Tooltip,
  XAxis,
  YAxis,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import { useEvents } from "@/hooks/useEvents";
import PageHeader from "@/components/ui/PageHeader";
import MetricCard from "@/components/MetricCard";
import {
  Shield,
  CheckCircle2,
  XCircle,
  Clock,
} from "lucide-react";
import { api } from "@/lib/api";

export default function AnalyticsPage() {
  const [summary, setSummary] = useState({
    total: 0,
    queued: 0,
    running: 0,
    completed: 0,
    failed: 0,
  });

  const [simulations, setSimulations] =
    useState<any[]>([]);
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
      const [
        summaryData,
        simulationData,
      ] = await Promise.all([
        api.getSimulationSummary(),
        api.getSimulations(),
      ]);

      setSummary(summaryData);
      setSimulations(simulationData);
    } catch (err) {
      console.error(err);
    }
  }

  const pieData = [
    {
      name: "Completed",
      value: summary.completed,
      color: "#10b981",
    },
    {
      name: "Running",
      value: summary.running,
      color: "#8b5cf6",
    },
    {
      name: "Queued",
      value: summary.queued,
      color: "#f59e0b",
    },
    {
      name: "Failed",
      value: summary.failed,
      color: "#ef4444",
    },
  ];

  const grouped =
    simulations.reduce(
      (
        acc: Record<string, number>,
        simulation: any
      ) => {
        const date = new Date(
          simulation.created_at
        ).toLocaleDateString(
          "en-US",
          {
            month: "short",
            day: "numeric",
          }
        );

        acc[date] =
          (acc[date] || 0) + 1;

        return acc;
      },
      {}
    );

  const trendData =
    Object.entries(grouped).map(
      ([day, value]) => ({
        day,
        value,
      })
    );

  const findings =
    simulations.flatMap(
      (simulation: any) =>
        simulation.module_results?.flatMap(
          (result: any) =>
            result.findings || []
        ) || []
    );

  const severityData = [
    {
      name: "Critical",
      value:
        findings.filter(
          (f: any) =>
            f.severity ===
            "critical"
        ).length,
      color: "#ef4444",
    },
    {
      name: "High",
      value:
        findings.filter(
          (f: any) =>
            f.severity === "high"
        ).length,
      color: "#f97316",
    },
    {
      name: "Medium",
      value:
        findings.filter(
          (f: any) =>
            f.severity ===
            "medium"
        ).length,
      color: "#facc15",
    },
    {
      name: "Info",
      value:
        findings.filter(
          (f: any) =>
            f.severity === "info"
        ).length,
      color: "#3b82f6",
    },
  ];

  return (
    <div className="space-y-8">
      <PageHeader
        title="Analytics"
        description="Executive overview of BAS execution activity."
      />

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        <MetricCard
          title="Total"
          value={summary.total}
          icon={Shield}
        />

        <MetricCard
          title="Completed"
          value={summary.completed}
          icon={CheckCircle2}
          color="green"
        />

        <MetricCard
          title="Running"
          value={summary.running}
          icon={Clock}
          color="amber"
        />

        <MetricCard
          title="Failed"
          value={summary.failed}
          icon={XCircle}
          color="red"
        />
      </div>

      <div className="grid xl:grid-cols-2 gap-8">
        <div className="glass-card p-8">
          <h2 className="text-2xl font-bold mb-6">
            Simulation Trend
          </h2>

          <div className="h-[350px]">
            <ResponsiveContainer
              width="100%"
              height="100%"
            >
              <AreaChart
                data={trendData}
              >
                <CartesianGrid strokeOpacity={0.1} />

                <XAxis dataKey="day" />

                <YAxis />

                <Tooltip />

                <Area
                  type="monotone"
                  dataKey="value"
                  stroke="#8b5cf6"
                  fill="#8b5cf6"
                  fillOpacity={0.25}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="glass-card p-8">
          <h2 className="text-2xl font-bold mb-6">
            Execution Distribution
          </h2>

          <div className="h-[350px]">
            <ResponsiveContainer
              width="100%"
              height="100%"
            >
              <PieChart>
                <Pie
                  data={pieData}
                  dataKey="value"
                  outerRadius={120}
                >
                  {pieData.map(
                    (
                      entry,
                      idx
                    ) => (
                      <Cell
                        key={idx}
                        fill={
                          entry.color
                        }
                      />
                    )
                  )}
                </Pie>

                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="glass-card p-8">
        <h2 className="text-2xl font-bold mb-6">
          Findings Distribution
        </h2>

        <div className="h-[350px]">
          <ResponsiveContainer
            width="100%"
            height="100%"
          >
            <PieChart>
              <Pie
                data={severityData}
                dataKey="value"
                outerRadius={120}
              >
                {severityData.map(
                  (
                    entry,
                    idx
                  ) => (
                    <Cell
                      key={idx}
                      fill={
                        entry.color
                      }
                    />
                  )
                )}
              </Pie>

              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}