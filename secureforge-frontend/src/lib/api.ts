export const API_BASE = "/api/proxy/api/v1";

async function request<T>(
  endpoint: string,
  options?: RequestInit
): Promise<T> {
  // L6 fix: add 30-second timeout to all API requests
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 30000);

  try {
    const response = await fetch(
      `${API_BASE}${endpoint}`,
      {
        ...options,
        signal: controller.signal,
        headers: {
          "Content-Type": "application/json",
          ...(options?.headers || {}),
        },
      }
    );

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(
        `API Error ${response.status}`
      );
    }

    return response.json();
  } catch (err: any) {
    clearTimeout(timeoutId);
    if (err?.name === "AbortError") {
      throw new Error("Request timed out after 30s");
    }
    throw err;
  }
}

export const api = {
  getModules() {
    return request<any[]>(
      "/modules/"
    );
  },

  getSimulations() {
    return request<any[]>(
      "/simulations/"
    );
  },

  getWebSocketUrl() {
    // H3 fix: derive WebSocket URL dynamically from the current window host
    // Use wss:// when the page is served over https://, ws:// otherwise
    if (typeof window === "undefined") {
      return "ws://localhost:8000/ws/events";
    }
    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    const host = window.location.host;
    // Connect via the Next.js proxy WebSocket path if available,
    // otherwise fall back to direct backend URL
    return `${proto}://${host.replace("3001", "8000")}/ws/events`;
  },
  getMetrics() {
    return request<any>(
      "/metrics/"
    );
  },
  getSimulationSummary() {
    return request<any>(
      "/simulations/summary"
    );
  },

  getSimulationResult(
    simId: string
  ) {
    return request<any>(
      `/results/${simId}`
    );
  },

  getEvents() {
    return request<any[]>(
      "/events/"
    );
  },
  getInfrastructure() {
    return request<any>(
      "/infrastructure/"
    );
  },
  getReplay(
    simId: string
  ) {
    return request<any>(
      `/replay/${simId}`
    );
  },

  getRecentReplayEvents() {
    return request<any>(
      "/replay/recent/events"
    );
  },

  discoverTarget(
    target: string
  ) {
    return request<any>(
      `/recon/discover?target=${encodeURIComponent(
        target
      )}`
    );
  },

  launchSimulation(
    payload: any
  ) {
    return request<any>(
      "/simulations/",
      {
        method: "POST",
        body: JSON.stringify(payload),
      }
    );
  },

  getIntegrations() {
    return request<any[]>(
      "/integrations/"
    );
  },

  createIntegration(data: { name: string; type: string; target: string }) {
    return request<any>(
      "/integrations/",
      {
        method: "POST",
        body: JSON.stringify(data),
      }
    );
  },

  deleteIntegration(id: string) {
    return request<any>(
      `/integrations/${id}`,
      {
        method: "DELETE",
      }
    );
  },
};