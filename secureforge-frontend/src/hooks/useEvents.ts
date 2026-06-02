"use client";

import { useEffect, useState } from "react";

const WS_URL =
  (
    process.env.NEXT_PUBLIC_API_URL ||
    "http://localhost:8000"
  )
    .replace("http", "ws") +
  "/ws/events";

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