"use client";

import { useEffect, useState } from "react";
import {
  Shield,
  AlertTriangle,
  CheckCircle2,
  Radar,
} from "lucide-react";

import MetricCard from "@/components/MetricCard";
import PageHeader from "@/components/ui/PageHeader";
import { api } from "@/lib/api";

export default function SocPage() {
  const [simulation, setSimulation] =
    useState<any>(null);

  useEffect(() => {
    loadLatest();
  }, []);

  async function loadLatest() {
    try {
      const simulations =
        await api.getSimulations();

      if (
        simulations &&
        simulations.length > 0
      ) {
        const latest =
          [...simulations].sort(
            (a, b) =>
              new Date(
                b.created_at
              ).getTime() -
              new Date(
                a.created_at
              ).getTime()
          )[0];

        setSimulation(
          latest
        );
      }
    } catch (error) {
      console.error(error);
    }
  }

  const soc =
    simulation?.metadata
      ?.detection_validation
      ?.soc_score || {};

  const blindspots =
    simulation?.metadata
      ?.detection_validation
      ?.blindspots || {};

  const coverage =
    simulation?.metadata
      ?.detection_validation
      ?.coverage || {};

  return (
    <div className="space-y-8">
      <PageHeader
        title="SOC Validation"
        description="Detection engineering validation and ATT&CK coverage analysis."
      />

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        <MetricCard
          title="SOC Score"
          value={
            soc.soc_score ??
            "N/A"
          }
          icon={Shield}
          color="purple"
        />

        <MetricCard
          title="Rating"
          value={
            soc.rating ??
            "N/A"
          }
          icon={CheckCircle2}
          color="green"
        />

        <MetricCard
          title="Blind Spots"
          value={
            blindspots.blind_spot_count ??
            0
          }
          icon={AlertTriangle}
          color="red"
        />

        <MetricCard
          title="Risk"
          value={
            blindspots.risk_level ??
            "Unknown"
          }
          icon={Radar}
          color="amber"
        />
      </div>

      <div className="grid xl:grid-cols-2 gap-8">
        <div className="glass-card p-8">
          <h2 className="text-2xl font-bold mb-6">
            Detected ATT&CK Tactics
          </h2>

          <div className="space-y-3">
            {blindspots
              ?.detected_tactics
              ?.length ? (
              blindspots.detected_tactics.map(
                (
                  tactic: string
                ) => (
                  <div
                    key={tactic}
                    className="
                      flex
                      items-center
                      justify-between
                      rounded-xl
                      border
                      border-green-500/20
                      bg-green-500/5
                      px-4
                      py-3
                    "
                  >
                    <span>
                      {tactic}
                    </span>

                    <CheckCircle2 className="w-4 h-4 text-green-400" />
                  </div>
                )
              )
            ) : (
              <div className="text-white/40">
                No detected tactics.
              </div>
            )}
          </div>
        </div>

        <div className="glass-card p-8">
          <h2 className="text-2xl font-bold mb-6">
            Detection Blind Spots
          </h2>

          <div className="space-y-3">
            {blindspots
              ?.blind_spots
              ?.length ? (
              blindspots.blind_spots.map(
                (
                  tactic: string
                ) => (
                  <div
                    key={tactic}
                    className="
                      flex
                      items-center
                      justify-between
                      rounded-xl
                      border
                      border-red-500/20
                      bg-red-500/5
                      px-4
                      py-3
                    "
                  >
                    <span>
                      {tactic}
                    </span>

                    <AlertTriangle className="w-4 h-4 text-red-400" />
                  </div>
                )
              )
            ) : (
              <div className="text-white/40">
                No blind spots.
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="glass-card p-8">
        <h2 className="text-2xl font-bold mb-6">
          Coverage Analysis
        </h2>

        {coverage.coverage ? (
          <div className="space-y-4">
            {Object.entries(
              coverage.coverage
            ).map(
              (
                [tactic, value]
              ) => (
                <div
                  key={tactic}
                >
                  <div className="flex justify-between mb-2">
                    <span>
                      {tactic}
                    </span>

                    <span>
                      {Number(
                        value
                      ).toFixed(
                        0
                      )}
                      %
                    </span>
                  </div>

                  <div className="h-3 rounded-full bg-white/10 overflow-hidden">
                    <div
                      className="
                        h-full
                        bg-gradient-to-r
                        from-purple-500
                        to-blue-500
                      "
                      style={{
                        width: `${value}%`,
                      }}
                    />
                  </div>
                </div>
              )
            )}
          </div>
        ) : (
          <div className="text-white/40">
            No coverage data available.
          </div>
        )}
      </div>
    </div>
  );
}