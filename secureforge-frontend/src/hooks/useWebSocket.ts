"use client";

import { useEffect, useRef, useState } from "react";

export function useWebSocket(url: string) {
  const [messages, setMessages] = useState<any[]>([]);
  const [connected, setConnected] = useState(false);

  const socketRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    let socket: WebSocket;

    try {
      socket = new WebSocket(url);

      socketRef.current = socket;

      socket.onopen = () => {
        console.log(
          "[SecureForge] WebSocket Connected"
        );

        setConnected(true);
      };

      socket.onmessage = (event) => {
        try {
          const payload = JSON.parse(
            event.data
          );

          setMessages((prev) => [
            ...prev,
            payload,
          ]);
        } catch {
          setMessages((prev) => [
            ...prev,
            {
              type: "raw_event",
              payload: event.data,
              timestamp:
                new Date().toISOString(),
            },
          ]);
        }
      };

      socket.onerror = (error) => {
        console.error(
          "[SecureForge] WebSocket Error",
          error
        );
      };

      socket.onclose = () => {
        console.log(
          "[SecureForge] WebSocket Closed"
        );

        setConnected(false);
      };
    } catch (err) {
      console.error(err);
    }

    return () => {
      socket?.close();
    };
  }, [url]);

  return {
    connected,
    messages,
  };
}