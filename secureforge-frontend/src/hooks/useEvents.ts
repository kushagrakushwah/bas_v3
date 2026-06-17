"use client";

import { useEffect, useState } from "react";

import { api } from "@/lib/api";

const WS_URL = api.getWebSocketUrl();

export function useEvents() {

  const [events, setEvents] =
    useState<any[]>([]);

  useEffect(() => {

    const ws = new WebSocket(
      WS_URL
    );

    ws.onmessage = (event) => {

      const data = JSON.parse(
        event.data
      );

      setEvents((prev) => [
        data,
        ...prev,
      ]);
    };

    return () => {

      ws.close();
    };

  }, []);

  return events;
}