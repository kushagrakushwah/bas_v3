"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Clock,
  RefreshCw,
  Terminal,
  Wifi,
  CheckCircle2,
} from "lucide-react";

import { useWebSocket } from "@/hooks/useWebSocket";

type EventItem = {
  id?: string;
  type?: string;
  timestamp?: string;
  payload?: Record<string, any>;
  severity?: string;
  source?: string;
};

import { api, API_BASE } from "@/lib/api";

function normalizeEvent(event: any): EventItem {
  if (!event) return {};

  if (event.payload && typeof event.payload === "object") {
    return {
      id: event.id,
      type: event.type || event.event_type || "event",
      timestamp: event.timestamp || event.created_at || new Date().toISOString(),
      payload: event.payload,
      severity: event.severity,
      source: event.source,
    };
  }

  if (event.data && typeof event.data === "object") {
    return {
      id: event.id,
      type: event.type || event.data.type || "event",
      timestamp: event.timestamp || event.created_at || new Date().toISOString(),
      payload: event.data,
      severity: event.severity,
      source: event.source,
    };
  }

  return {
    id: event.id,
    type: event.type || "event",
    timestamp: event.timestamp || event.created_at || new Date().toISOString(),
    payload: event.payload || event.data || event,
    severity: event.severity,
    source: event.source,
  };
}

function dedupeEvents(events: EventItem[]) {
  const seen = new Set<string>();
  const result: EventItem[] = [];

  for (const event of events) {
    const key =
      event.id ||
      `${event.timestamp || ""}-${event.type || ""}-${JSON.stringify(event.payload || {})}`;

    if (seen.has(key)) continue;
    seen.add(key);
    result.push(event);
  }

  return result;
}

function EventPayloadRenderer({ event }: { event: EventItem }) {
  const payload = (event.payload || event) as any;
  
  if (event.type === "raw_event") {
    const rawType = payload.event_type || "INFO";
    const msg = payload.message || "";
    const meta = payload.metadata || {};
    
    return (
      <div className="mt-4 space-y-3">
        <div className="bg-black/40 rounded-xl p-4 border border-white/5 font-mono text-sm">
          <div className="flex items-center gap-2 mb-2 text-purple-400">
            <span className="font-bold">[{rawType}]</span>
          </div>
          <p className="text-white/90 whitespace-pre-wrap leading-relaxed">{msg}</p>
        </div>
        
        {Object.keys(meta).length > 0 && (
          <div className="flex flex-wrap gap-2 mt-3">
            {Object.entries(meta).map(([k, v]) => (
              <div key={k} className="bg-white/[0.05] border border-white/10 rounded-md px-3 py-1.5 text-xs flex gap-2 items-center">
                <span className="text-white/40 uppercase tracking-wider">{k}:</span>
                <span className="text-white/80 font-mono">{String(v)}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    );
  }
  
  if (event.type === "module.completed" || event.type === "module.started") {
    return (
      <div className="mt-4 flex flex-wrap gap-3">
        <div className="bg-white/[0.03] border border-white/10 rounded-lg p-3 min-w-[140px]">
          <div className="text-[10px] uppercase tracking-widest text-white/40 mb-1">Module</div>
          <div className="font-mono text-sm text-purple-300">{payload.module || "Unknown"}</div>
        </div>
        {payload.findings_count !== undefined && (
          <div className="bg-white/[0.03] border border-white/10 rounded-lg p-3 min-w-[140px]">
            <div className="text-[10px] uppercase tracking-widest text-white/40 mb-1">Findings</div>
            <div className="font-mono text-sm text-amber-300">{payload.findings_count}</div>
          </div>
        )}
      </div>
    );
  }
  
  if (event.type === "vulnerability.found") {
    const details = payload.finding_details || {};
    return (
      <div className="mt-4 bg-red-500/5 border border-red-500/20 rounded-xl p-4 space-y-3">
        <div className="flex items-start justify-between">
          <div>
            <h4 className="text-red-400 font-bold text-sm">{details.title || "Unknown Vulnerability"}</h4>
            <p className="text-white/70 text-xs mt-1">{details.description}</p>
          </div>
          <span className="bg-red-500/20 text-red-300 text-[10px] px-2 py-1 rounded uppercase tracking-wider font-bold">
            {details.severity || "Critical"}
          </span>
        </div>
        
        <div className="grid grid-cols-2 gap-3 mt-3">
          <div className="bg-black/30 rounded p-2 text-xs">
            <span className="text-white/40 block mb-1">MITRE ID</span>
            <span className="font-mono text-white/80">{details.mitre_id || "N/A"}</span>
          </div>
          <div className="bg-black/30 rounded p-2 text-xs">
            <span className="text-white/40 block mb-1">Target</span>
            <span className="font-mono text-white/80">{payload.target || "N/A"}</span>
          </div>
        </div>
        
        {details.remediation && (
          <div className="mt-3 bg-green-500/10 border border-green-500/20 rounded p-3 text-xs">
            <span className="text-green-400 font-bold block mb-1">Remediation</span>
            <span className="text-white/80">{details.remediation}</span>
          </div>
        )}
      </div>
    );
  }
  
  if (event.type === "simulation.completed" || event.type === "simulation.started" || event.type === "simulation.queued") {
    return (
      <div className="mt-4 bg-white/[0.03] border border-white/10 rounded-xl p-4 flex gap-4 items-center">
        <div className="w-10 h-10 rounded-full bg-purple-500/20 flex items-center justify-center">
          <Activity className="w-5 h-5 text-purple-400" />
        </div>
        <div>
          <h4 className="text-white font-medium text-sm">Simulation {event.type.split('.')[1]}</h4>
          <p className="text-white/50 text-xs font-mono mt-1">ID: {payload.id || payload.sim_id || "Unknown"}</p>
        </div>
      </div>
    );
  }

  // Fallback for unknown events
  return (
    <pre className="mt-4 overflow-x-auto rounded-xl border border-white/10 bg-black/40 p-4 text-[11px] text-white/60 font-mono leading-relaxed whitespace-pre-wrap">
      {JSON.stringify(payload, null, 2)}
    </pre>
  );
}

export default function RealtimeOperations() {
  const terminalRef = useRef<HTMLDivElement | null>(null);

  const [recentEvents, setRecentEvents] = useState<EventItem[]>([]);
  const [loadingReplay, setLoadingReplay] = useState(true);

  // This hook can return { connected, messages } in the current version.
  // Using "any" here keeps the page resilient if the hook shape changes slightly.
  const socketState = useWebSocket(api.getWebSocketUrl()) as any;

  const connected = Boolean(socketState?.connected);
  const liveMessages: EventItem[] = Array.isArray(socketState?.messages)
    ? socketState.messages.map(normalizeEvent)
    : Array.isArray(socketState)
      ? socketState.map(normalizeEvent)
      : [];

  useEffect(() => {
    let mounted = true;

    async function loadRecentEvents() {
      try {
        setLoadingReplay(true);

        const response = await fetch(`${API_BASE}/api/v1/replay/recent/events`, {
          method: "GET",
          cache: "no-store",
        });

        if (!response.ok) {
          throw new Error(`Failed to load recent events: ${response.status}`);
        }

        const data = await response.json();

        const items: any[] = Array.isArray(data)
          ? data
          : Array.isArray(data?.events)
            ? data.events
            : Array.isArray(data?.items)
              ? data.items
              : [];

        if (!mounted) return;

        setRecentEvents(items.map(normalizeEvent));
      } catch (error) {
        console.error(error);
        if (mounted) setRecentEvents([]);
      } finally {
        if (mounted) setLoadingReplay(false);
      }
    }

    loadRecentEvents();

    return () => {
      mounted = false;
    };
  }, []);

  const allEvents = useMemo(() => {
    return dedupeEvents([...recentEvents, ...liveMessages]).sort((a, b) => {
      const at = new Date(a.timestamp || 0).getTime();
      const bt = new Date(b.timestamp || 0).getTime();
      return at - bt;
    });
  }, [recentEvents, liveMessages]);

  useEffect(() => {
    terminalRef.current?.scrollTo({
      top: terminalRef.current.scrollHeight,
      behavior: "smooth",
    });
  }, [allEvents.length]);

  const recentCount = recentEvents.length;
  const liveCount = liveMessages.length;
  const statusText = connected ? "CONNECTED" : "DISCONNECTED";
  const statusDot = connected ? "bg-green-500" : "bg-red-500";
  const statusColor = connected ? "text-green-400" : "text-red-400";

  const latestEvent =
    allEvents.length > 0 ? allEvents[allEvents.length - 1] : null;

  return (
    <div className="space-y-8">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-4xl font-bold tracking-tight text-white flex items-center gap-3">
            <Activity className="w-9 h-9 text-purple-400 animate-pulse" />
            Live Operations
          </h1>
          <p className="mt-2 text-white/60">
            Real-time BAS telemetry stream with recent replay history.
          </p>
        </div>

        <div className="glass-card px-5 py-3 flex items-center gap-3">
          <span className={`w-2.5 h-2.5 rounded-full ${statusDot} animate-pulse`} />
          <span className={`font-medium ${statusColor}`}>{statusText}</span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="glass-card p-6">
          <p className="text-xs uppercase tracking-[0.2em] text-white/40">
            Stream Status
          </p>
          <div className="mt-4 flex items-center gap-3">
            <Wifi className="w-5 h-5 text-purple-400" />
            <span className="text-2xl font-bold">
              {connected ? "Live" : "Offline"}
            </span>
          </div>
        </div>

        <div className="glass-card p-6">
          <p className="text-xs uppercase tracking-[0.2em] text-white/40">
            Recent Events
          </p>
          <div className="mt-4 flex items-center gap-3">
            <CheckCircle2 className="w-5 h-5 text-green-400" />
            <span className="text-2xl font-bold">{recentCount}</span>
          </div>
        </div>

        <div className="glass-card p-6">
          <p className="text-xs uppercase tracking-[0.2em] text-white/40">
            Live Events
          </p>
          <div className="mt-4 flex items-center gap-3">
            <CheckCircle2 className="w-5 h-5 text-purple-400" />
            <span className="text-2xl font-bold">{liveCount}</span>
          </div>
        </div>

        <div className="glass-card p-6">
          <p className="text-xs uppercase tracking-[0.2em] text-white/40">
            Endpoint
          </p>
          <div className="mt-4 flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 text-amber-400" />
            <span className="text-sm font-mono">/ws/events</span>
          </div>
        </div>
      </div>

      <div className="glass-card overflow-hidden">
        <div className="border-b border-white/10 px-6 py-4 flex items-center justify-between gap-4 bg-white/[0.02]">
          <div className="flex items-center gap-3">
            <Terminal className="w-5 h-5 text-purple-400" />
            <h2 className="font-semibold text-white">Event Stream</h2>
          </div>

          <button
            onClick={async () => {
              try {
                setLoadingReplay(true);

                const response = await fetch(
                  `${API_BASE}/api/v1/replay/recent/events`,
                  {
                    method: "GET",
                    cache: "no-store",
                  }
                );

                const data = await response.json();
                const items: any[] = Array.isArray(data)
                  ? data
                  : Array.isArray(data?.events)
                    ? data.events
                    : Array.isArray(data?.items)
                      ? data.items
                      : [];

                setRecentEvents(items.map(normalizeEvent));
              } catch (error) {
                console.error(error);
              } finally {
                setLoadingReplay(false);
              }
            }}
            className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-black/30 px-4 py-2 text-sm text-white/70 hover:bg-white/[0.04] transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loadingReplay ? "animate-spin" : ""}`} />
            Refresh replay
          </button>
        </div>

        <div
          ref={terminalRef}
          className="h-[700px] overflow-y-auto p-6 space-y-4 font-mono"
        >
          {loadingReplay && allEvents.length === 0 ? (
            <div className="h-full min-h-[560px] flex flex-col items-center justify-center text-center text-white/40">
              <div className="w-14 h-14 rounded-full bg-purple-500/10 border border-purple-500/20 flex items-center justify-center mb-4">
                <Clock className="w-6 h-6 text-purple-400 animate-pulse" />
              </div>
              <p className="text-lg font-medium text-white/70">
                Loading recent events
              </p>
              <p className="text-sm mt-2 max-w-md">
                Pulling replay history first, then listening for live telemetry.
              </p>
            </div>
          ) : allEvents.length === 0 ? (
            <div className="h-full min-h-[560px] flex flex-col items-center justify-center text-center text-white/40">
              <div className="w-14 h-14 rounded-full bg-purple-500/10 border border-purple-500/20 flex items-center justify-center mb-4">
                <Terminal className="w-6 h-6 text-purple-400" />
              </div>
              <p className="text-lg font-medium text-white/70">
                No events available yet
              </p>
              <p className="text-sm mt-2 max-w-md">
                Launch a simulation to generate replay or live activity.
              </p>
            </div>
          ) : (
            allEvents.map((event: EventItem, index: number) => {
              const timestamp = event.timestamp
                ? new Date(event.timestamp.endsWith('Z') ? event.timestamp : event.timestamp + 'Z').toLocaleString('en-US', { timeZone: 'Asia/Kolkata' })
                : "No timestamp";

              const badgeColor =
                event.severity === "critical"
                  ? "bg-red-500/10 border-red-500/20 text-red-400"
                  : event.severity === "high"
                    ? "bg-orange-500/10 border-orange-500/20 text-orange-400"
                    : event.severity === "medium"
                      ? "bg-amber-500/10 border-amber-500/20 text-amber-400"
                      : event.severity === "low"
                        ? "bg-green-500/10 border-green-500/20 text-green-400"
                        : "bg-purple-500/10 border-purple-500/20 text-purple-300";

              return (
                <div
                  key={event.id || `${event.timestamp || "event"}-${index}`}
                  className="rounded-2xl border border-white/10 bg-black/30 p-4 hover:border-purple-500/30 transition-colors"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex items-center gap-3 flex-wrap">
                      <span className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-semibold ${badgeColor}`}>
                        {event.type || "event"}
                      </span>
                      {event.source ? (
                        <span className="text-xs text-white/35">
                          {event.source}
                        </span>
                      ) : null}
                    </div>

                    <span className="text-xs text-white/40 flex items-center gap-1.5 whitespace-nowrap">
                      <Clock className="w-3.5 h-3.5" />
                      {timestamp}
                    </span>
                  </div>

                  <EventPayloadRenderer event={event} />
                </div>
              );
            })
          )}
        </div>
      </div>

      {latestEvent && (
        <div className="glass-card p-6">
          <h3 className="text-lg font-semibold text-white mb-3">
            Latest Event Snapshot
          </h3>
          <div className="text-sm text-white/60">
            {latestEvent.type || "event"} at{" "}
            {latestEvent.timestamp
              ? new Date(latestEvent.timestamp.endsWith('Z') ? latestEvent.timestamp : latestEvent.timestamp + 'Z').toLocaleString('en-US', { timeZone: 'Asia/Kolkata' })
              : "No timestamp"}
          </div>
        </div>
      )}
    </div>
  );
}