"use client";

import { useEffect, useState } from "react";

import { api } from "@/lib/api";

export function useEvents() {
  const [events, setEvents] = useState<any[]>([]);

  useEffect(() => {
    let ws: WebSocket;
    let mounted = true;

    api.getWebSocketTicket().then(res => {
      if (!mounted || !res?.ticket) return;
      
      ws = new WebSocket(api.getWebSocketUrl(res.ticket));
      
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          setEvents((prev) => [data, ...prev]);
        } catch(e) {}
      };
    }).catch(console.error);

    return () => {
      mounted = false;
      if (ws) ws.close();
    };
  }, []);

  return events;
}