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
import type { AttackModule, Simulation, SimulationRequest } from "@/types/index";

export default function LaunchPage() {
  const [target, setTarget] = useState("");

  const [jobLabel, setJobLabel] = useState(
    `Simulation-${Date.now().toString().slice(-6)}`
  );

  const [parallel, setParallel] = useState(true);
  const [detailedEnumeration, setDetailedEnumeration] = useState(false);

  // ── Nmap options ────────────────────────────────────────────
  const [scanProfile, setScanProfile] = useState("standard");
  const [portRange, setPortRange] = useState("1-1000");
  const [timingProfile, setTimingProfile] = useState("T4");
  const [subnetDiscovery, setSubnetDiscovery] = useState(false);

  // ── Impact sim options ──────────────────────────────────────
  const [requestCount, setRequestCount] = useState(500);
  const [concurrency, setConcurrency] = useState(50);

  // ── SSH / Webmail brute force options ───────────────────────
  const [sshAuthType, setSshAuthType] = useState<"ssh" | "webmail">("ssh");
  const [webmailLoginUrl, setWebmailLoginUrl] = useState("");

  // ── Custom HTTP options ──────────────────────────────────────
  const [customMethod, setCustomMethod] = useState("GET");
  const [customUrl, setCustomUrl] = useState("");
  const [customHeaders, setCustomHeaders] = useState("{}");
  const [customBody, setCustomBody] = useState("");
  const [customTimeout, setCustomTimeout] = useState(10);

  // ── Module state ────────────────────────────────────────────
  const [modules, setModules] = useState<AttackModule[]>([]);
  const [selectedModules, setSelectedModules] = useState<string[]>([]);
  const [loadingModules, setLoadingModules] = useState(true);
  const [simulations, setSimulations] = useState<Simulation[]>([]);
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
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
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

      const options: SimulationRequest["options"] = {};

      if (selectedModules.includes("nmap_scan")) {
        options.nmap_scan = {
          profile: scanProfile,
          ports: portRange,
          timing: timingProfile,
          subnet_scan: subnetDiscovery,
        };
      }

      if (selectedModules.includes("impact_sim")) {
        options.impact_sim = {
          request_count: requestCount,
          concurrency: concurrency,
        };
      }

      if (selectedModules.includes("ssh_bruteforce")) {
        options.ssh_bruteforce = {
          auth_type: sshAuthType,
          ...(sshAuthType === "webmail" && webmailLoginUrl
            ? { webmail_login_url: webmailLoginUrl }
            : {}),
        };
      }

      // ── Custom HTTP options ──────────────────────────────
      if (selectedModules.includes("custom_http")) {
        try {
          options.custom_http = {
            method: customMethod,
            url: customUrl || target, // fallback to simulation target
            headers: JSON.parse(customHeaders),
            body: customBody,
            timeout: customTimeout,
          };
        } catch (e) {
          setMessage("Invalid JSON in custom headers.");
          setLaunching(false);
          return;
        }
      }

      const payload: SimulationRequest = {
        name: jobLabel,
        target,
        modules: selectedModules,
        parallel,
        detailed_enumeration: detailedEnumeration,
        options,
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

      {/* ── Metric strip ──────────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-3 xl:grid-cols-5 gap-4">
        <MetricCard title="Modules" value={modules.length} icon={Shield} />

        <MetricCard
          title="Selected"
          value={selectedModules.length}
          icon={Rocket}
          color="purple"
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

      {/* ── Main config card ──────────────────────────────── */}
      <div className="glass-card p-8">
        <h2 className="text-2xl font-bold mb-8">Simulation Configuration</h2>

        {/* Name + Target */}
        <div className="grid md:grid-cols-2 gap-6">
          <div>
            <label className="text-sm text-white/50">Simulation Name</label>
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

        {/* ── Nmap options ─────────────────────────────────── */}
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

        {/* ── Impact sim options ───────────────────────────── */}
        {selectedModules.includes("impact_sim") && (
          <div className="mt-8">
            <h3 className="text-lg font-semibold mb-4">
              Impact Simulation Configuration
            </h3>

            <div className="grid md:grid-cols-2 gap-6">
              <div>
                <label className="text-sm text-white/50">Request Count</label>
                <input
                  type="number"
                  value={requestCount}
                  onChange={(e) => setRequestCount(Number(e.target.value))}
                  className="mt-2 w-full rounded-2xl border border-white/10 bg-black/30 p-4"
                />
              </div>

              <div>
                <label className="text-sm text-white/50">Concurrency</label>
                <input
                  type="number"
                  value={concurrency}
                  onChange={(e) => setConcurrency(Number(e.target.value))}
                  className="mt-2 w-full rounded-2xl border border-white/10 bg-black/30 p-4"
                />
              </div>
            </div>
          </div>
        )}

        {/* ── SSH / Webmail brute force options ────────────── */}
        {selectedModules.includes("ssh_bruteforce") && (
          <div className="mt-8 rounded-2xl border border-white/10 bg-white/[0.03] p-6">
            <h3 className="text-lg font-semibold mb-1">
              Credential Attack Configuration
            </h3>
            <p className="text-sm text-white/40 mb-6">
              Choose the authentication protocol to brute force.
            </p>

            {/* Radio toggle */}
            <div className="flex gap-6 mb-6">
              {(["ssh", "webmail"] as const).map((type) => (
                <label
                  key={type}
                  className="flex items-center gap-3 cursor-pointer"
                  onClick={() => setSshAuthType(type)}
                >
                  <div
                    className={`
                      w-5 h-5 rounded-full border-2 flex items-center justify-center transition-all
                      ${
                        sshAuthType === type
                          ? "border-purple-500 bg-purple-500"
                          : "border-white/30 bg-transparent"
                      }
                    `}
                  >
                    {sshAuthType === type && (
                      <div className="w-2 h-2 rounded-full bg-white" />
                    )}
                  </div>
                  <span
                    className={`text-sm font-medium ${
                      sshAuthType === type ? "text-white" : "text-white/50"
                    }`}
                  >
                    {type === "ssh" ? "SSH" : "Webmail / Roundcube"}
                  </span>
                </label>
              ))}
            </div>

            {/* SSH info pill */}
            {sshAuthType === "ssh" && (
              <div className="rounded-xl border border-blue-500/20 bg-blue-500/10 px-4 py-3 text-sm text-blue-300">
                Attempts SSH password auth against port 22 (or custom
                ssh_port). Uses asyncssh with adaptive concurrency and
                fail2ban awareness.
              </div>
            )}

            {/* Webmail extra fields */}
            {sshAuthType === "webmail" && (
              <div className="space-y-4">
                <div className="rounded-xl border border-amber-500/20 bg-amber-500/10 px-4 py-3 text-sm text-amber-300">
                  Performs HTTP POST brute force against a Roundcube / webmail
                  login page. Leave the URL blank to auto-derive from Target +{" "}
                  <code className="font-mono">/roundcube/</code>.
                </div>

                <div>
                  <label className="text-sm text-white/50">
                    Webmail Login URL{" "}
                    <span className="text-white/30">(optional override)</span>
                  </label>
                  <input
                    value={webmailLoginUrl}
                    onChange={(e) => setWebmailLoginUrl(e.target.value)}
                    placeholder="https://mail.example.com/roundcube/"
                    className="mt-2 w-full rounded-2xl border border-white/10 bg-black/30 p-4 text-sm"
                  />
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── Custom HTTP options ───────────────────────────── */}
        {selectedModules.includes("custom_http") && (
          <div className="mt-8 rounded-2xl border border-white/10 bg-white/[0.03] p-6">
            <h3 className="text-lg font-semibold mb-4">Custom HTTP Request</h3>
            <div className="grid md:grid-cols-2 gap-6">
              <div>
                <label className="text-sm text-white/50">Method</label>
                <select
                  value={customMethod}
                  onChange={(e) => setCustomMethod(e.target.value)}
                  className="mt-2 w-full rounded-2xl border border-white/10 bg-black/30 p-4"
                >
                  <option value="GET">GET</option>
                  <option value="POST">POST</option>
                  <option value="PUT">PUT</option>
                  <option value="DELETE">DELETE</option>
                  <option value="PATCH">PATCH</option>
                </select>
              </div>
              <div>
                <label className="text-sm text-white/50">URL (override)</label>
                <input
                  value={customUrl}
                  onChange={(e) => setCustomUrl(e.target.value)}
                  placeholder="Leave empty to use simulation target"
                  className="mt-2 w-full rounded-2xl border border-white/10 bg-black/30 p-4"
                />
              </div>
              <div className="md:col-span-2">
                <label className="text-sm text-white/50">Headers (JSON)</label>
                <input
                  value={customHeaders}
                  onChange={(e) => setCustomHeaders(e.target.value)}
                  placeholder='{"Content-Type": "application/json"}'
                  className="mt-2 w-full rounded-2xl border border-white/10 bg-black/30 p-4"
                />
              </div>
              <div className="md:col-span-2">
                <label className="text-sm text-white/50">Body (string)</label>
                <textarea
                  value={customBody}
                  onChange={(e) => setCustomBody(e.target.value)}
                  placeholder='{"key": "value"} or plain text'
                  rows={4}
                  className="mt-2 w-full rounded-2xl border border-white/10 bg-black/30 p-4"
                />
              </div>
              <div>
                <label className="text-sm text-white/50">Timeout (sec)</label>
                <input
                  type="number"
                  value={customTimeout}
                  onChange={(e) => setCustomTimeout(Number(e.target.value))}
                  className="mt-2 w-full rounded-2xl border border-white/10 bg-black/30 p-4"
                />
              </div>
            </div>
          </div>
        )}

        {/* ── Module grid ──────────────────────────────────── */}
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
                      text-left rounded-2xl border p-5 transition-all
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

                    {/* Auth type badge — only on ssh_bruteforce when active */}
                    {module.id === "ssh_bruteforce" && active && (
                      <div className="mt-3">
                        <span
                          className={`
                            inline-block rounded-full px-2 py-0.5 text-xs font-medium
                            ${
                              sshAuthType === "ssh"
                                ? "bg-blue-500/20 text-blue-300"
                                : "bg-amber-500/20 text-amber-300"
                            }
                          `}
                        >
                          {sshAuthType === "ssh" ? "SSH" : "Webmail"}
                        </span>
                      </div>
                    )}
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* ── Flags row ────────────────────────────────────── */}
        <div className="mt-8 flex gap-6">
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={parallel}
              onChange={() => setParallel(!parallel)}
            />
            Parallel
          </label>

          <label className="flex items-center gap-2 text-red-500 font-semibold">
            <input
              type="checkbox"
              checked={detailedEnumeration}
              onChange={() => setDetailedEnumeration(!detailedEnumeration)}
            />
            Danger
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
            mt-8 w-full rounded-2xl
            bg-gradient-to-r from-purple-600 to-blue-600
            py-5 font-bold transition-all
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

      {/* ── Active Simulations ───────────────────────────── */}
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
                  key={simulation.id ?? simulation.simulation_id}
                  className="border-b border-white/5 hover:bg-white/[0.03]"
                >
                  <td className="p-4">{simulation.name ?? "—"}</td>
                  <td className="p-4">{simulation.target}</td>
                  <td className="p-4">
                    {simulation.modules?.join(", ") ?? "—"}
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