"use client";

import { useEffect, useState } from "react";
import {
  Rocket,
  Shield,
  AlertTriangle,
  Play,
  Loader2,
  CheckCircle2,
} from "lucide-react";
import SimulationStatusBadge from "@/components/SimulationStatusBadge";
import MetricCard from "@/components/MetricCard";
import PageHeader from "@/components/ui/PageHeader";
import { api } from "@/lib/api";

interface AttackModule {
  id: string;
  description: string;
  tactic: string;
  mitre_ids: string[];
}

export default function LaunchPage() {
  const [target, setTarget] = useState("");

  const [jobLabel, setJobLabel] = useState(
    `Simulation-${Date.now().toString().slice(-6)}`
  );

  const [parallel, setParallel] = useState(true);

  const [liveMode, setLiveMode] = useState(false);
  const [scanProfile, setScanProfile] = useState("standard");
  const [portRange, setPortRange] = useState("1-1000");
  const [timingProfile, setTimingProfile] = useState("T4");
  const [subnetDiscovery, setSubnetDiscovery] = useState(false);

  const [modules, setModules] = useState<AttackModule[]>([]);
  const [selectedModules, setSelectedModules] = useState<string[]>([]);
  const [loadingModules, setLoadingModules] = useState(true);
  const [simulations, setSimulations] = useState<any[]>([]);
  const [launching, setLaunching] = useState(false);
  const [message, setMessage] = useState("");

  useEffect(() => {
    loadModules();
    loadSimulations();
  }, []);

  async function loadModules() {
    try {
      const data = await api.getModules();
      setModules(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingModules(false);
    }
  }

  function toggleModule(id: string) {
    setSelectedModules((prev) =>
      prev.includes(id)
        ? prev.filter((item) => item !== id)
        : [...prev, id]
    );
  }

  async function loadSimulations() {
    try {
      const data = await api.getSimulations();
      setSimulations(data);
    } catch (err) {
      console.error(err);
    }
  }

  async function handleLaunch() {
    if (!target) {
      setMessage("Target is required.");
      return;
    }

    if (selectedModules.length === 0) {
      setMessage("Select at least one module.");
      return;
    }

    try {
      setLaunching(true);
      setMessage("");

      const payload = {
        name: jobLabel,
        target,
        modules: selectedModules,
        parallel,
        metadata: {
          live_mode: liveMode,
        },
        options: {
          nmap_scan: {
            profile: scanProfile,
            ports: portRange,
            timing: timingProfile,
            subnet_scan: subnetDiscovery,
          },
        },
      };

      const result = await api.launchSimulation(payload);
      console.log(result);

      setMessage("Simulation launched successfully.");
      loadSimulations();
    } catch (error) {
      console.error(error);
      setMessage("Failed to launch simulation.");
    } finally {
      setLaunching(false);
    }
  }

  return (
    <div className="space-y-8">
      <PageHeader
        title="Launch Center"
        description="Configure and dispatch BAS attack simulations."
      />

      <div className="grid grid-cols-1 md:grid-cols-3 xl:grid-cols-5 gap-4">
        <MetricCard
          title="Modules"
          value={modules.length}
          icon={Shield}
        />

        <MetricCard
          title="Selected"
          value={selectedModules.length}
          icon={Rocket}
          color="purple"
        />

        <MetricCard
          title="Mode"
          value={liveMode ? "LIVE" : "SAFE"}
          icon={liveMode ? AlertTriangle : CheckCircle2}
          color={liveMode ? "red" : "green"}
        />

        <MetricCard
          title="Parallel"
          value={parallel ? "ON" : "OFF"}
          icon={Rocket}
        />

        <MetricCard
          title="Status"
          value={launching ? "RUNNING" : "READY"}
          icon={launching ? Loader2 : CheckCircle2}
          color={launching ? "amber" : "green"}
        />
      </div>

      <div className="glass-card p-8">
        <h2 className="text-2xl font-bold mb-8">
          Simulation Configuration
        </h2>

        <div className="grid md:grid-cols-2 gap-6">
          <div>
            <label className="text-sm text-white/50">
              Simulation Name
            </label>
            <input
              value={jobLabel}
              onChange={(e) => setJobLabel(e.target.value)}
              className="mt-2 w-full rounded-2xl border border-white/10 bg-black/30 p-4"
            />
          </div>

          <div>
            <label className="text-sm text-white/50">Target</label>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://example.com"
              className="mt-2 w-full rounded-2xl border border-white/10 bg-black/30 p-4"
            />
          </div>
        </div>

        {selectedModules.includes("nmap_scan") && (
          <div className="mt-8">
            <h3 className="text-lg font-semibold mb-4">
              Nmap Scan Configuration
            </h3>

            <div className="grid md:grid-cols-2 gap-6">
              <div>
                <label className="text-sm text-white/50">Scan Profile</label>
                <select
                  value={scanProfile}
                  onChange={(e) => setScanProfile(e.target.value)}
                  className="mt-2 w-full rounded-2xl border border-white/10 bg-black/30 p-4"
                >
                  <option value="quick">Quick</option>
                  <option value="standard">Standard</option>
                  <option value="full">Full</option>
                  <option value="web">Web</option>
                  <option value="db">Database</option>
                  <option value="devops">DevOps</option>
                </select>
              </div>

              <div>
                <label className="text-sm text-white/50">Port Range</label>
                <input
                  value={portRange}
                  onChange={(e) => setPortRange(e.target.value)}
                  placeholder="1-1000"
                  className="mt-2 w-full rounded-2xl border border-white/10 bg-black/30 p-4"
                />
              </div>

              <div>
                <label className="text-sm text-white/50">Timing Profile</label>
                <select
                  value={timingProfile}
                  onChange={(e) => setTimingProfile(e.target.value)}
                  className="mt-2 w-full rounded-2xl border border-white/10 bg-black/30 p-4"
                >
                  <option value="T2">T2</option>
                  <option value="T3">T3</option>
                  <option value="T4">T4</option>
                  <option value="T5">T5</option>
                </select>
              </div>

              <div className="flex items-end">
                <label className="flex items-center gap-3">
                  <input
                    type="checkbox"
                    checked={subnetDiscovery}
                    onChange={() => setSubnetDiscovery(!subnetDiscovery)}
                  />
                  Enable Subnet Discovery
                </label>
              </div>
            </div>
          </div>
        )}

        <div className="mt-8">
          <h3 className="text-lg font-semibold mb-4">Attack Modules</h3>

          {loadingModules ? (
            <div className="text-white/50">Loading modules...</div>
          ) : (
            <div className="grid md:grid-cols-2 xl:grid-cols-3 gap-4">
              {modules.map((module) => {
                const active = selectedModules.includes(module.id);

                return (
                  <button
                    key={module.id}
                    onClick={() => toggleModule(module.id)}
                    className={`
                      text-left
                      rounded-2xl
                      border
                      p-5
                      transition-all
                      ${
                        active
                          ? "border-purple-500 bg-purple-500/10"
                          : "border-white/10 bg-black/20"
                      }
                    `}
                  >
                    <div className="font-semibold">{module.id}</div>

                    <div className="mt-2 text-sm text-white/60">
                      {module.description}
                    </div>

                    <div className="mt-3 text-xs text-purple-300">
                      {module.tactic}
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        <div className="mt-8 flex gap-6">
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={parallel}
              onChange={() => setParallel(!parallel)}
            />
            Parallel
          </label>

          <label className="flex items-center gap-2 text-red-400">
            <input
              type="checkbox"
              checked={liveMode}
              onChange={() => setLiveMode(!liveMode)}
            />
            Live Mode
          </label>
        </div>

        {message && (
          <div className="mt-6 rounded-xl border border-white/10 bg-black/30 p-4">
            {message}
          </div>
        )}

        <button
          onClick={handleLaunch}
          disabled={launching}
          className="
            mt-8
            w-full
            rounded-2xl
            bg-gradient-to-r
            from-purple-600
            to-blue-600
            py-5
            font-bold
            transition-all
          "
        >
          <div className="flex items-center justify-center gap-3">
            {launching ? (
              <Loader2 className="w-5 h-5 animate-spin" />
            ) : (
              <Play className="w-5 h-5" />
            )}

            {launching ? "Launching..." : "Dispatch Simulation"}
          </div>
        </button>
      </div>

      {/* Active Simulations */}
      <div className="glass-card p-8">
        <h2 className="text-2xl font-bold mb-6">Active Simulations</h2>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-white/10">
                <th className="p-4 text-left">Name</th>
                <th className="p-4 text-left">Target</th>
                <th className="p-4 text-left">Modules</th>
                <th className="p-4 text-left">Status</th>
              </tr>
            </thead>

            <tbody>
              {simulations.map((simulation) => (
                <tr
                  key={simulation.id}
                  className="
                    border-b
                    border-white/5
                    hover:bg-white/[0.03]
                  "
                >
                  <td className="p-4">{simulation.name}</td>
                  <td className="p-4">{simulation.target}</td>
                  <td className="p-4">
                    {simulation.modules?.join(", ")}
                  </td>
                  <td className="p-4">
                    <SimulationStatusBadge status={simulation.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}