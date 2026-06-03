"use client";

import { useEffect, useState } from "react";
import {
  Server,
  Activity,
  Box,
  CheckCircle2,
} from "lucide-react";

import PageHeader from "@/components/ui/PageHeader";
import MetricCard from "@/components/MetricCard";
import { api } from "@/lib/api";

export default function InfrastructurePage() {
  const [pods, setPods] =
    useState<any[]>([]);

  const [total, setTotal] =
    useState<number>(0);

  const [isLoading, setIsLoading] =
    useState(true);

  const [metrics, setMetrics] =
    useState({
      cpu_percent: 0,
      memory_percent: 0,
      node_count: 0,
    });

  useEffect(() => {
    loadInfrastructure();

    const interval = setInterval(() => {
      loadInfrastructure();
    }, 10000); // every 10 seconds

    return () => {
      clearInterval(interval);
    };
  }, []);

  async function loadInfrastructure() {
    try {
      const [
        infra,
        metricData,
      ] = await Promise.all([
        api.getInfrastructure(),
        api.getMetrics(),
      ]);

      setPods(
        infra.pods || []
      );

      setTotal(
        infra.total || 0
      );

      setMetrics(
        metricData
      );
    } catch (err) {
      console.error(
        "Failed to load infrastructure data:",
        err
      );
    } finally {
      setIsLoading(false);
    }
  }

  const runningPods =
    pods.filter(
      (pod) =>
        pod.status?.toLowerCase() ===
        "running"
    ).length;

  return (
    <div className="space-y-8">
      <PageHeader
        title="Infrastructure"
        description="Live Kubernetes cluster monitoring and pod status."
      />

      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <MetricCard
          title="Total Pods"
          value={
            isLoading
              ? "-"
              : total
          }
          icon={Box}
        />

        <MetricCard
          title="Running Pods"
          value={
            isLoading
              ? "-"
              : runningPods
          }
          icon={CheckCircle2}
          color="green"
        />

        <MetricCard
          title="CPU Usage"
          value={
            isLoading
              ? "-"
              : `${metrics.cpu_percent}%`
          }
          icon={Activity}
          color="amber"
        />

        <MetricCard
          title="Memory Usage"
          value={
            isLoading
              ? "-"
              : `${metrics.memory_percent}%`
          }
          icon={Server}
          color="purple"
        />

        <MetricCard
          title="Nodes"
          value={
            isLoading
              ? "-"
              : metrics.node_count
          }
          icon={Box}
          color="blue"
        />
      </div>

      <div className="glass-card p-8">
        <h2 className="text-2xl font-bold mb-6">
          Cluster Pods
        </h2>

        {isLoading ? (
          <div className="text-white/50 py-4">
            Fetching live Kubernetes
            data...
          </div>
        ) : pods.length === 0 ? (
          <div className="text-white/50 py-4">
            No pods found in the
            cluster.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-white/10 text-white/50 text-sm">
                  <th className="pb-3 font-medium">
                    Pod Name
                  </th>

                  <th className="pb-3 font-medium">
                    Namespace
                  </th>

                  <th className="pb-3 font-medium text-right">
                    Status
                  </th>
                </tr>
              </thead>

              <tbody className="divide-y divide-white/10">
                {pods.map(
                  (
                    pod,
                    index
                  ) => (
                    <tr
                      key={index}
                      className="text-sm"
                    >
                      <td className="py-4 font-mono text-purple-300">
                        {pod.name}
                      </td>

                      <td className="py-4">
                        <span className="bg-white/5 px-2.5 py-1 rounded-md text-white/70">
                          {
                            pod.namespace
                          }
                        </span>
                      </td>

                      <td className="py-4 text-right">
                        <span
                          className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium border ${
                            pod.status ===
                            "Running"
                              ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                              : pod.status ===
                                "Pending"
                              ? "bg-amber-500/10 text-amber-400 border-amber-500/20"
                              : "bg-red-500/10 text-red-400 border-red-500/20"
                          }`}
                        >
                          {pod.status ===
                            "Running" && (
                            <CheckCircle2 className="w-3 h-3" />
                          )}

                          {
                            pod.status
                          }
                        </span>
                      </td>
                    </tr>
                  )
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}