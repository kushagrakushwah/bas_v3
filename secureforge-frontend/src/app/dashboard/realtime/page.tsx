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
      <div className="mt-4">
        <div className="bg-zinc-950/50 rounded-lg p-3 border border-white/[0.05] flex gap-3 items-start">
          <div className={`mt-0.5 text-[10px] px-2 py-0.5 rounded font-bold uppercase tracking-wider whitespace-nowrap
            ${rawType.includes('ERROR') || rawType.includes('FAIL') ? 'bg-red-500/20 text-red-400' : 
              rawType.includes('WARN') ? 'bg-amber-500/20 text-amber-400' : 
              rawType.includes('SUCCESS') ? 'bg-emerald-500/20 text-emerald-400' : 
              'bg-blue-500/20 text-blue-400'}`}>
            {rawType}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-white/80 font-mono text-xs whitespace-pre-wrap leading-relaxed">{msg}</p>
            {Object.keys(meta).length > 0 && (
              <div className="flex flex-wrap gap-2 mt-2">
                {Object.entries(meta).map(([k, v]) => (
                  <div key={k} className="bg-black/50 border border-white/5 rounded px-2 py-1 text-[10px] flex gap-1.5 items-center">
                    <span className="text-white/40">{k}:</span>
                    <span className="text-white/70 font-mono truncate max-w-[200px]">{String(v)}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
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
      <div className="mt-4 bg-zinc-950/80 border border-red-500/30 rounded-xl overflow-hidden shadow-[0_0_15px_rgba(239,68,68,0.1)]">
        {/* Header */}
        <div className="bg-red-500/10 px-4 py-3 border-b border-red-500/20 flex items-start justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded bg-red-500/20 flex items-center justify-center">
              <AlertTriangle className="w-4 h-4 text-red-500" />
            </div>
            <div>
              <h4 className="text-red-400 font-bold text-sm tracking-wide">{details.title || "Unknown Vulnerability"}</h4>
              <div className="flex items-center gap-2 mt-1">
                <span className="text-xs text-white/50 font-mono">{payload.module || "Unknown Module"}</span>
                <span className="text-xs text-white/30">•</span>
                <span className="text-xs text-white/50 font-mono">{payload.target || "N/A"}</span>
              </div>
            </div>
          </div>
          <span className="bg-red-500 text-white text-[10px] px-2.5 py-1 rounded-sm uppercase tracking-widest font-bold shadow-sm shadow-red-500/50">
            {details.severity || "Critical"}
          </span>
        </div>
        
        <div className="p-4 space-y-4">
          {/* Payload Evidence - The most important part */}
          {details.evidence ? (
            <div className="bg-black rounded-lg border border-zinc-800 p-3">
              <div className="text-[10px] uppercase tracking-widest text-emerald-500/70 mb-2 font-bold flex items-center gap-2">
                <Terminal className="w-3 h-3" />
                Payload Triggered
              </div>
              <pre className="font-mono text-xs text-emerald-400 whitespace-pre-wrap leading-relaxed break-all">
                {details.evidence}
              </pre>
            </div>
          ) : (
            <div className="bg-black rounded-lg border border-zinc-800 p-3">
              <div className="text-[10px] uppercase tracking-widest text-emerald-500/70 mb-2 font-bold flex items-center gap-2">
                <Terminal className="w-3 h-3" />
                Payload Triggered
              </div>
              <pre className="font-mono text-xs text-zinc-500 italic">No explicit payload extracted.</pre>
            </div>
          )}

          {/* Description */}
          <p className="text-white/70 text-xs leading-relaxed">
            {details.description}
          </p>

          {/* Info Grid */}
          <div className="grid grid-cols-2 gap-3">
            <div className="bg-white/[0.02] border border-white/5 rounded-lg p-3">
              <span className="text-[10px] uppercase tracking-widest text-white/40 block mb-1">MITRE ID</span>
              <span className="font-mono text-sm text-white/90">{details.mitre_id || "N/A"}</span>
            </div>
            {details.remediation && (
              <div className="bg-emerald-500/5 border border-emerald-500/10 rounded-lg p-3">
                <span className="text-[10px] uppercase tracking-widest text-emerald-500/70 block mb-1">Remediation</span>
                <span className="text-xs text-emerald-100/70 line-clamp-2" title={details.remediation}>
                  {details.remediation}
                </span>
              </div>
            )}
          </div>
        </div>
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
  const [wsUrl, setWsUrl] = useState<string>("");

  useEffect(() => {
    let mounted = true;
    api.getWebSocketTicket().then(res => {
      if (mounted && res?.ticket) {
        setWsUrl(api.getWebSocketUrl(res.ticket));
      }
    }).catch(err => console.error("Failed to fetch WS ticket:", err));
    return () => { mounted = false; };
  }, []);

  // This hook can return { connected, messages } in the current version.
  // Using "any" here keeps the page resilient if the hook shape changes slightly.
  const socketState = useWebSocket(wsUrl) as any;

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

        const data = await api.getRecentReplayEvents();

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
      return bt - at; // Newest first
    });
  }, [recentEvents, liveMessages]);

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

                const data = await api.getRecentReplayEvents();
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