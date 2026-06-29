import { useEffect, useRef, useState } from 'react';
import { Terminal, Trash2, Wifi, WifiOff } from 'lucide-react';
import { useWebSocket } from '../hooks/useWebSocket';
import { apiClient } from '../lib/api';
import type { LogEntry } from '../types';

interface LogLine extends LogEntry {
  id: number;
  raw: string;
}

interface LiveConsoleProps {
  sessionId: string;
  running: boolean;
  title?: string;
  maxHeight?: string;
}

const LEVEL_COLORS: Record<string, string> = {
  DEBUG: 'text-text3',
  INFO: 'text-green-400',
  WARNING: 'text-yellow-400',
  WARN: 'text-yellow-400',
  ERROR: 'text-red-400',
  CRITICAL: 'text-red-500',
};

export default function LiveConsole({
  sessionId,
  running,
  title = 'Live Console',
  maxHeight = '320px',
}: LiveConsoleProps) {
  const { connected, lastMessage, clearMessages } = useWebSocket(
    running ? sessionId : null
  );
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [loaded, setLoaded] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const lastProcessedRef = useRef<string | null>(null);
  const nextIdRef = useRef(1);
  const prevRunningRef = useRef(running);

  // Load persisted historical logs once when the component mounts. This keeps
  // previous console output available even after navigating away and back.
  useEffect(() => {
    let cancelled = false;
    async function load() {
      // Reset displayed logs for the new session before loading persisted history
      setLogs([]);
      nextIdRef.current = 1;
      lastProcessedRef.current = null;
      try {
        const { logs: entries } = await apiClient.getConsoleLogs(sessionId);
        if (cancelled) return;
        setLogs((prev) => {
          const existing = new Set(prev.map((l) => l.raw));
          const fresh = (entries || [])
            .filter((entry: LogEntry & { raw?: string }) => !existing.has(entry.raw || entry.message))
            .map((entry: LogEntry & { raw?: string }) => ({
              id: nextIdRef.current++,
              raw: entry.raw || entry.message,
              timestamp: entry.timestamp,
              level: entry.level,
              source: entry.source,
              message: entry.message,
            }));
          return [...prev, ...fresh];
        });
      } catch {
        // Historical logs are best-effort; live logs still work via WebSocket.
      } finally {
        setLoaded(true);
      }
    }
    load();
    return () => {
      cancelled = true;
    };
  }, [sessionId]);

  // Reset the displayed console only when a new run starts (running transitions
  // from false to true). On initial mount or revisit we keep persisted history
  // so logs survive page navigation.
  useEffect(() => {
    if (running && !prevRunningRef.current) {
      setLogs([]);
      nextIdRef.current = 1;
      lastProcessedRef.current = null;
      clearMessages();
    }
    prevRunningRef.current = running;
  }, [running, sessionId, clearMessages]);

  useEffect(() => {
    if (!lastMessage || lastMessage.type !== 'log') return;
    const raw = (lastMessage.raw as string) || (lastMessage.message as string) || '';
    if (!raw || raw === lastProcessedRef.current) return;
    lastProcessedRef.current = raw;

    const parsed: LogEntry = {
      timestamp: (lastMessage.timestamp as string) || '',
      level: (lastMessage.level as string) || 'INFO',
      source: (lastMessage.source as string) || '',
      message: (lastMessage.message as string) || raw,
    };

    setLogs((prev) => {
      const existing = new Set(prev.map((l) => l.raw));
      if (existing.has(raw)) return prev;
      return [...prev, { id: nextIdRef.current++, raw, ...parsed }];
    });
  }, [lastMessage]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  function clear() {
    setLogs([]);
    nextIdRef.current = 1;
    lastProcessedRef.current = null;
    clearMessages();
  }

  return (
    <div className="rounded-lg border border-border overflow-hidden bg-black font-mono text-xs">
      <div className="flex items-center justify-between px-3 py-2 bg-surface border-b border-border">
        <div className="flex items-center gap-2 text-text">
          <Terminal size={14} className="text-accent" />
          <span className="font-semibold">{title}</span>
        </div>
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1 text-[10px] uppercase tracking-wider">
            {connected ? (
              <>
                <Wifi size={10} className="text-green-400" /> Connected
              </>
            ) : running ? (
              <>
                <WifiOff size={10} className="text-yellow-400" /> Reconnecting
              </>
            ) : (
              <>
                <WifiOff size={10} className="text-text3" /> Offline
              </>
            )}
          </span>
          <button
            onClick={clear}
            title="Clear console"
            className="p-1 rounded hover:bg-surface2 text-text3 hover:text-danger transition-colors"
          >
            <Trash2 size={12} />
          </button>
        </div>
      </div>

      <div
        className="p-3 space-y-1 overflow-y-auto scrollbar-thin"
        style={{ maxHeight }}
      >
        {!loaded && logs.length === 0 ? (
          <div className="text-text3 italic">
            <span className="text-green-400">chai@scan:~$</span> loading history...
          </div>
        ) : logs.length === 0 ? (
          <div className="text-text3 italic">
            <span className="text-green-400">chai@scan:~$</span> waiting for activity...
          </div>
        ) : (
          logs.map((log) => (
            <div key={log.id} className="break-words leading-relaxed">
              <span className="text-text3 mr-2">chai@scan:~$</span>
              {log.timestamp && (
                <span className="text-text3 mr-2">[{log.timestamp}]</span>
              )}
              {log.level && (
                <span className={`${LEVEL_COLORS[log.level] || 'text-text2'} mr-2 font-bold`}>
                  {log.level}
                </span>
              )}
              {log.source && (
                <span className="text-accent/70 mr-2">[{log.source}]</span>
              )}
              <span className="text-text2">{log.message}</span>
            </div>
          ))
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
