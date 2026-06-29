const API_BASE = import.meta.env.VITE_API_URL || '';

async function api<T>(path: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `${res.status}: ${res.statusText}`);
  }
  return res.json() as Promise<T>;
}

export const apiClient = {
  health: () => api<{ status: string; version: string }>('/api/health'),
  sessions: () => api<{ sessions: import('../types').Session[] }>('/api/sessions'),
  createSession: (body: { target: string; test_type?: string; scope?: string[]; metadata?: Record<string, unknown> }) =>
    api<{ session_id: string; target: string; status: string }>('/api/sessions', { method: 'POST', body: JSON.stringify(body) }),
  getSession: (id: string) => api<import('../types').SessionDetail>(`/api/sessions/${id}`),
  stopSession: (id: string) => api<{ status: string }>(`/api/sessions/${id}/stop`, { method: 'POST' }),
  deleteSession: (id: string) => api<{ status: string; session_id: string }>(`/api/sessions/${id}`, { method: 'DELETE' }),
  getFindings: (id: string, severity?: string) =>
    api<{ findings: import('../types').Finding[] }>(`/api/sessions/${id}/findings${severity ? `?severity=${severity}` : ''}`),
  allFindings: (severity?: string) =>
    api<{ findings: import('../types').Finding[] }>(`/api/findings${severity ? `?severity=${severity}` : ''}`),
  startScan: (body: { session_id: string; max_phases?: number; stop_on_critical?: boolean; generate_report?: boolean }) =>
    api<import('../types').ScanProgress['result']>('/api/scan/autonomous', { method: 'POST', body: JSON.stringify(body) }),
  runTool: (body: { session_id: string; target: string; tool_name: string; tool_type?: string }) =>
    api<Record<string, unknown>>('/api/tools/run', { method: 'POST', body: JSON.stringify(body) }),
  runCommand: (body: { session_id: string; command: string; timeout?: number }) =>
    api<Record<string, unknown>>('/api/tools/command', { method: 'POST', body: JSON.stringify(body) }),
  generateReport: (id: string) =>
    api<{ report_path: string }>(`/api/sessions/${id}/report`, { method: 'POST' }),
  getReport: (id: string) =>
    api<{ content: string; format: string }>(`/api/sessions/${id}/report/content`),
  downloadReport: (id: string) => {
    const url = `${API_BASE}/api/sessions/${id}/report/download`;
    const a = document.createElement('a');
    a.href = url;
    a.download = `report-${id}.md`;
    document.body.appendChild(a);
    a.click();
    a.remove();
  },
  listPlugins: () => api<{ plugins: import('../types').Plugin[] }>('/api/plugins'),
  listTools: () => api<{ tools: { name: string; type: string; class: string }[]; plugins: import('../types').Plugin[] }>('/api/tools/list'),
  getConfig: () => api<import('../types').ServerConfig>('/api/config'),
  getLogs: (id: string) => api<{ logs: import('../types').LogEntry[] }>(`/api/sessions/${id}/logs`),
  getConsoleLogs: (id: string) => api<{ logs: import('../types').LogEntry[] }>(`/api/sessions/${id}/console-logs`),
  getAuditLog: () => api<{ entries: { timestamp: string; action: string; session_id: string; details: string }[] }>('/api/audit-log'),
};
