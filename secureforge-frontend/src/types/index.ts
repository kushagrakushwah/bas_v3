// ─────────────────────────────────────────────────────────────
// Shared types for SecureForge frontend
// ─────────────────────────────────────────────────────────────

// Matches the shape returned by GET /api/v1/modules/
export interface AttackModule {
  id: string;
  description: string;
  tactic: string;
  mitre_ids: string[];
}

// ── Per-module option shapes ──────────────────────────────────

export interface SSHBruteForceOptions {
  auth_type?: "ssh" | "webmail";
  webmail_login_url?: string;
  webmail_user_field?: string;
  webmail_pass_field?: string;
  webmail_success_marker?: string;
  ssh_port?: number;
  concurrency?: number;
  timeout?: number;
}

export interface NmapScanOptions {
  profile?: string;
  ports?: string;
  timing?: string;
  subnet_scan?: boolean;
}

export interface ImpactSimOptions {
  request_count?: number;
  concurrency?: number;
}

// Named module options — strongly typed
interface KnownModuleOptions {
  ssh_bruteforce?: SSHBruteForceOptions;
  nmap_scan?: NmapScanOptions;
  impact_sim?: ImpactSimOptions;
  ssh_user?: string;
  ssh_pass?: string;
}

// Extra module option bags (unknown modules) use a plain record
type ExtraModuleOptions = {
  [key: string]: Record<string, unknown> | undefined;
};

// Intersection: known keys are typed; any other string key is a plain record
export type SimulationOptions = KnownModuleOptions & ExtraModuleOptions;

// ── Simulation request ────────────────────────────────────────
// Matches the exact payload the Launch page POSTs to the backend.
// live_mode lives inside metadata — NOT at the top level.
export interface SimulationRequest {
  name?: string;
  target: string;
  modules: string[];
  parallel: boolean;
  autonomous?: boolean;
  detailed_enumeration?: boolean;
  metadata?: Record<string, unknown>;
  options?: SimulationOptions;
}

// ── Simulation record (list / status responses) ───────────────
export interface Simulation {
  id?: string;
  simulation_id?: string;
  name?: string;
  target: string;
  modules?: string[];
  status: string;
  risk_score?: number;
  created_at?: string;
}

// ── Event stream item ─────────────────────────────────────────
export interface EventItem {
  timestamp: string;
  type: string;
  payload?: Record<string, unknown>;
}