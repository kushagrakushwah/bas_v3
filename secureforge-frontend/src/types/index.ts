export interface AttackModule {
  name: string;
  description?: string;
}

export interface SimulationRequest {
  target: string;
  modules: string[];
  parallel: boolean;
  live_mode: boolean;
}

export interface Simulation {
  simulation_id: string;
  target: string;
  status: string;
  risk_score?: number;
}

export interface EventItem {
  timestamp: string;
  type: string;
  payload?: Record<string, any>;
}