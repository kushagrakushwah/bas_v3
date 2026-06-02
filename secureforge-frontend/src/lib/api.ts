const API_BASE =
  process.env.NEXT_PUBLIC_API_URL ||
  "http://localhost:8000";

async function request<T>(
  endpoint: string,
  options?: RequestInit
): Promise<T> {
  const response = await fetch(
    `${API_BASE}${endpoint}`,
    {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...(options?.headers || {}),
      },
    }
  );

  if (!response.ok) {
    throw new Error(
      `API Error ${response.status}`
    );
  }

  return response.json();
}

export const api = {
  getModules() {
    return request<any[]>(
      "/api/v1/modules/"
    );
  },

  getSimulations() {
    return request<any[]>(
      "/api/v1/simulations/"
    );
  },

  getWebSocketUrl() {
    return (
      API_BASE.replace("http", "ws") +
      "/ws/events"
    );
  },
  getMetrics() {
    return request<any>(
      "/api/v1/metrics/"
    );
  },
  getSimulationSummary() {
    return request<any>(
      "/api/v1/simulations/summary"
    );
  },

  getSimulationResult(
    simId: string
  ) {
    return request<any>(
      `/api/v1/results/${simId}`
    );
  },

  getEvents() {
    return request<any[]>(
      "/api/v1/events/"
    );
  },
  getInfrastructure() {
    return request<any>(
      "/api/v1/infrastructure/"
    );
  },
  getReplay(
    simId: string
  ) {
    return request<any>(
      `/api/v1/replay/${simId}`
    );
  },

  getRecentReplayEvents() {
    return request<any[]>(
      "/api/v1/replay/recent/events"
    );
  },

  discoverTarget(
    target: string
  ) {
    return request<any>(
      `/api/v1/recon/discover?target=${encodeURIComponent(
        target
      )}`
    );
  },

  launchSimulation(
    payload: any
  ) {
    return request<any>(
      "/api/v1/simulations/",
      {
        method: "POST",
        body: JSON.stringify(payload),
      }
    );
  },
};