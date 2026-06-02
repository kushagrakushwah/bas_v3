"use client";

import { useEffect, useState } from "react";
import PageHeader from "@/components/ui/PageHeader";
import { api } from "@/lib/api";

export default function MitrePage() {
  const [simulations, setSimulations] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

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
    } finally {
      setLoading(false);
    }
  }

  const tacticCounts =
    simulations.reduce(
      (
        acc: Record<string, number>,
        simulation: any
      ) => {
        const detected =
          simulation?.metadata
            ?.detection_validation
            ?.blindspots
            ?.detected_tactics || [];

        detected.forEach(
          (tactic: string) => {
            acc[tactic] =
              (acc[tactic] || 0) + 1;
          }
        );

        return acc;
      },
      {}
    );

  const mitreData =
    Object.entries(
      tacticCounts
    ).map(
      ([name, count]) => ({
        name,
        count,
      })
    );

  const totalDetections =
    mitreData.reduce(
      (
        total,
        item
      ) => total + item.count,
      0
    );

  return (
    <div className="space-y-8">
      <PageHeader
        title="MITRE ATT&CK Coverage"
        description="Coverage generated from completed BAS assessments."
      />

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="glass-card p-6">
          <div className="text-white/50 text-sm uppercase tracking-wider">
            Simulations
          </div>

          <div className="text-5xl font-bold mt-3">
            {simulations.length}
          </div>
        </div>

        <div className="glass-card p-6">
          <div className="text-white/50 text-sm uppercase tracking-wider">
            Tactics Covered
          </div>

          <div className="text-5xl font-bold mt-3 text-green-400">
            {mitreData.length}
          </div>
        </div>

        <div className="glass-card p-6">
          <div className="text-white/50 text-sm uppercase tracking-wider">
            Total Detections
          </div>

          <div className="text-5xl font-bold mt-3 text-purple-400">
            {totalDetections}
          </div>
        </div>
      </div>

      <div className="glass-card p-8">
        <h2 className="text-2xl font-bold mb-6">
          ATT&CK Tactic Coverage
        </h2>

        {loading ? (
          <div className="text-white/50">
            Loading...
          </div>
        ) : mitreData.length === 0 ? (
          <div className="text-white/50">
            No completed assessments found.
          </div>
        ) : (
          <div className="grid md:grid-cols-2 xl:grid-cols-3 gap-4">
            {mitreData.map(
              (item) => (
                <div
                  key={item.name}
                  className="
                    rounded-2xl
                    border
                    border-white/10
                    bg-black/20
                    p-6
                  "
                >
                  <div className="text-sm text-white/50 uppercase tracking-wider">
                    ATT&CK Tactic
                  </div>

                  <div className="text-xl font-bold mt-3">
                    {item.name}
                  </div>

                  <div className="mt-4 h-2 rounded-full bg-white/5 overflow-hidden">
                    <div
                      className="
                        h-full
                        rounded-full
                        bg-gradient-to-r
                        from-purple-500
                        to-blue-500
                      "
                      style={{
                        width: `${Math.min(
                          item.count * 25,
                          100
                        )}%`,
                      }}
                    />
                  </div>

                  <div className="mt-4 text-purple-300 font-medium">
                    Seen in {item.count} simulation
                    {item.count !== 1
                      ? "s"
                      : ""}
                  </div>
                </div>
              )
            )}
          </div>
        )}
      </div>

      <div className="glass-card p-8">
        <h2 className="text-2xl font-bold mb-6">
          Coverage Summary
        </h2>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-white/10">
                <th className="p-4 text-left">
                  Tactic
                </th>

                <th className="p-4 text-left">
                  Coverage Count
                </th>

                <th className="p-4 text-left">
                  Status
                </th>
              </tr>
            </thead>

            <tbody>
              {mitreData.map(
                (item) => (
                  <tr
                    key={item.name}
                    className="border-b border-white/5"
                  >
                    <td className="p-4">
                      {item.name}
                    </td>

                    <td className="p-4">
                      {item.count}
                    </td>

                    <td className="p-4">
                      <span
                        className="
                          rounded-full
                          border
                          border-green-500/30
                          bg-green-500/10
                          px-3
                          py-1
                          text-sm
                          text-green-400
                        "
                      >
                        Detected
                      </span>
                    </td>
                  </tr>
                )
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}