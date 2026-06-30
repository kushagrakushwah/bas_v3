"use client";

import { useEffect, useRef, useState, useCallback } from "react";

export function useWebSocket(url: string) {
  const [messages, setMessages] = useState<any[]>([]);
  const [connected, setConnected] = useState(false);

  const socketRef = useRef<WebSocket | null>(null);
  const retryDelay = useRef<number>(1000);
  const retryTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const unmounted = useRef(false);

  const connect = useCallback(() => {
    if (!url || unmounted.current) return;

    try {
      const socket = new WebSocket(url);
      socketRef.current = socket;

      socket.onopen = () => {
        if (unmounted.current) return;
        console.log("[SecureForge] WebSocket Connected");
        setConnected(true);
        retryDelay.current = 1000; // reset backoff on successful connect
      };

      socket.onmessage = (event) => {
        if (unmounted.current) return;
        try {
          const payload = JSON.parse(event.data);
          if (payload.type === "ping") return;
          setMessages((prev) => [...prev, payload]);
        } catch {
          setMessages((prev) => [
            ...prev,
            {
              type: "raw_event",
              payload: event.data,
              timestamp: new Date().toISOString(),
            },
          ]);
        }
      };

      socket.onerror = (error) => {
        console.error("[SecureForge] WebSocket Error", error);
      };

      socket.onclose = () => {
        if (unmounted.current) return;
        console.log(`[SecureForge] WebSocket Closed — retrying in ${retryDelay.current}ms`);
        setConnected(false);

        // Exponential backoff: 1s → 2s → 4s → 8s → 16s → max 30s
        retryTimer.current = setTimeout(() => {
          if (!unmounted.current) {
            retryDelay.current = Math.min(retryDelay.current * 2, 30000);
            connect();
          }
        }, retryDelay.current);
      };
    } catch (err) {
      console.error("[SecureForge] WebSocket failed to construct:", err);
    }
  }, [url]);

  useEffect(() => {
    unmounted.current = false;
    connect();

    return () => {
      unmounted.current = true;
      if (retryTimer.current) clearTimeout(retryTimer.current);
      socketRef.current?.close();
    };
  }, [connect]);

  return { connected, messages };
}