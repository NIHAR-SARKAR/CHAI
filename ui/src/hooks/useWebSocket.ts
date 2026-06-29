import { useEffect, useRef, useState, useCallback } from 'react';

export function useWebSocket(sessionId: string | null) {
  const ws = useRef<WebSocket | null>(null);
  const [connected, setConnected] = useState(false);
  const [messages, setMessages] = useState<string[]>([]);
  const [lastMessage, setLastMessage] = useState<Record<string, unknown> | null>(null);

  const send = useCallback((data: unknown) => {
    if (ws.current?.readyState === WebSocket.OPEN) {
      ws.current.send(JSON.stringify(data));
    }
  }, []);

  const clearMessages = useCallback(() => {
    setMessages([]);
    setLastMessage(null);
  }, []);

  useEffect(() => {
    if (!sessionId) {
      setConnected(false);
      setMessages([]);
      return;
    }
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const base = import.meta.env.VITE_WS_URL || `${proto}//${window.location.host}`;
    const url = `${base}/ws/scan/${sessionId}`;
    const socket = new WebSocket(url);
    ws.current = socket;

    socket.onopen = () => setConnected(true);
    socket.onclose = () => setConnected(false);
    socket.onerror = () => setConnected(false);
    socket.onmessage = (ev) => {
      const data = JSON.parse(ev.data);
      setLastMessage(data);
      if (data.type === 'log') {
        setMessages((prev) => [...prev, data.message]);
      }
    };

    return () => {
      socket.close();
    };
  }, [sessionId]);

  return { connected, messages, lastMessage, send, clearMessages };
}
