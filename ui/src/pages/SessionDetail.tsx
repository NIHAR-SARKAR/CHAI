import { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Play, StopCircle, FileText, Activity, AlertTriangle, Brain, Clock, Terminal, Filter, Download } from 'lucide-react';
import { apiClient } from '../lib/api';
import { useWebSocket } from '../hooks/useWebSocket';
import type { SessionDetail, Finding } from '../types';
import { useToast } from '../components/Toaster';
import LiveConsole from '../components/LiveConsole';

export default function SessionDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const toast = useToast();
  const [detail, setDetail] = useState<SessionDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<'overview' | 'findings' | 'logs' | 'ai'>('overview');
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [severityFilter, setSeverityFilter] = useState('');
  const isRunning = scanning || detail?.session.status === 'running';
  const { lastMessage } = useWebSocket(isRunning ? id || null : null);

  const loadDetail = useCallback(async () => {
    if (!id) return;
    try {
      const d = await apiClient.getSession(id);
      setDetail(d);
    } catch (e) {
      toast((e as Error).message, 'error');
    }
  }, [id, toast]);

  useEffect(() => {
    if (!id) return;
    setLoading(true);
    loadDetail().finally(() => setLoading(false));
  }, [id, loadDetail]);

  useEffect(() => {
    if (!lastMessage) return;
    if (lastMessage.type === 'progress') {
      const count = (lastMessage.findings_count as number) || 0;
      setScanProgress(Math.min(100, count * 10));
    } else if (lastMessage.type === 'complete') {
      setScanning(false);
      setScanProgress(100);
      toast('Scan complete!', 'success');
      loadDetail();
    } else if (lastMessage.type === 'error') {
      setScanning(false);
      toast((lastMessage.message as string) || 'Scan error', 'error');
      loadDetail();
    }
  }, [lastMessage, loadDetail, toast]);

  useEffect(() => {
    if (!id || !isRunning) return;
    const interval = setInterval(() => loadDetail(), 8000);
    return () => clearInterval(interval);
  }, [id, isRunning, loadDetail]);

  async function startScan() {
    if (!id) return;
    setScanning(true);
    setScanProgress(0);
    try {
      await apiClient.startScan({ session_id: id, max_phases: 4, stop_on_critical: true, generate_report: true });
    } catch (e) {
      setScanning(false);
      toast((e as Error).message, 'error');
    }
  }

  async function stopScan() {
    if (!id) return;
    try {
      await apiClient.stopSession(id);
      setScanning(false);
      toast('Scan stopped', 'success');
      loadDetail();
    } catch (e) {
      toast((e as Error).message, 'error');
    }
  }

  async function generateReport() {
    if (!id) return;
    try {
      await apiClient.generateReport(id);
      toast('Report generated', 'success');
    } catch (e) {
      toast((e as Error).message, 'error');
    }
  }

  function downloadReport() {
    if (!id) return;
    apiClient.downloadReport(id);
    toast('Download started', 'success');
  }

  if (loading) return <div className="py-12 text-center text-text3">Loading session...</div>;
  if (!detail) return <div className="py-12 text-center text-text3">Session not found</div>;

  const s = detail.session;
  const findings = detail.findings || [];
  const decisions = detail.ai_decisions || [];
  const filteredFindings = severityFilter
    ? findings.filter((f) => f.severity === severityFilter)
    : findings;

  return (
    <div>
      <button onClick={() => navigate(-1)} className="flex items-center gap-2 text-text2 hover:text-text text-sm mb-4 transition-colors">
        <ArrowLeft size={16} /> Back
      </button>

      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-xl font-bold">Session <span className="text-accent font-mono text-base">{s.session_id.slice(0, 20)}...</span></h2>
          <p className="text-text3 text-sm mt-1">{s.target} · {s.test_type}</p>
        </div>
        <div className="flex gap-2">
          {!scanning && s.status !== 'running' && (
            <button onClick={startScan} className="btn-primary text-sm px-4 py-2 rounded-lg flex items-center gap-2">
              <Play size={14} /> Start Scan
            </button>
          )}
          {(scanning || s.status === 'running') && (
            <button onClick={stopScan} className="btn-danger text-sm px-4 py-2 rounded-lg flex items-center gap-2">
              <StopCircle size={14} /> Stop
            </button>
          )}
          <button onClick={generateReport} className="btn text-sm px-4 py-2 rounded-lg flex items-center gap-2">
            <FileText size={14} /> Report
          </button>
          <button onClick={downloadReport} className="btn text-sm px-4 py-2 rounded-lg flex items-center gap-2">
            <Download size={14} /> Download
          </button>
        </div>
      </div>

      {isRunning && (
        <div className="card mb-4 border-accent/30">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2 text-accent text-sm font-medium">
              <Activity size={16} className="animate-pulse" /> Scan in progress...
            </div>
          </div>
          <div className="h-1.5 bg-surface2 rounded-full overflow-hidden mb-3">
            <div className="h-full bg-gradient-to-r from-accent to-accent2 rounded-full transition-all duration-500" style={{ width: `${scanProgress}%` }} />
          </div>
          <LiveConsole sessionId={id!} running={isRunning} maxHeight="240px" title="Scan Activity" />
        </div>
      )}

      <div className="flex gap-1 mb-4 bg-surface rounded-lg p-1 w-fit">
        {(['overview', 'findings', 'logs', 'ai'] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-3 py-1.5 rounded text-xs font-medium transition-all capitalize ${
              tab === t ? 'bg-accent/15 text-accent' : 'text-text2 hover:text-text'
            }`}
          >
            {t === 'ai' ? 'AI Decisions' : t}
          </button>
        ))}
      </div>

      {tab === 'overview' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="card space-y-3">
            <h3 className="text-sm font-semibold">Session Info</h3>
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div><span className="text-text3 text-xs block">Target</span>{s.target}</div>
              <div><span className="text-text3 text-xs block">Type</span>{s.test_type}</div>
              <div><span className="text-text3 text-xs block">Status</span>{statusBadge(s.status)}</div>
              <div><span className="text-text3 text-xs block">Findings</span>{findings.length}</div>
              <div className="col-span-2"><span className="text-text3 text-xs block">Scope</span>{(s.scope || []).join(', ') || '-'}</div>
              <div><span className="text-text3 text-xs block">Created</span><span className="flex items-center gap-1 text-text2"><Clock size={12} />{new Date(s.created_at).toLocaleString()}</span></div>
            </div>
          </div>
          <div className="card space-y-3">
            <h3 className="text-sm font-semibold">Findings Summary</h3>
            {findings.length === 0 ? (
              <div className="text-text3 text-sm py-4 text-center">No findings yet</div>
            ) : (
              <div className="space-y-2">
                {(['critical', 'high', 'medium', 'low', 'info'] as const).map((sev) => {
                  const count = findings.filter(f => f.severity === sev).length;
                  if (count === 0) return null;
                  return (
                    <div key={sev} className="flex items-center justify-between text-sm">
                      <span className="flex items-center gap-2">{severityBadge(sev)}</span>
                      <span className="font-mono">{count}</span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
          <ServerInfoCard info={s.metadata?.server_info as Record<string, unknown> | undefined} />
          <TokenUsageCard usage={detail.token_usage} />
        </div>
      )}

      {tab === 'findings' && (
        <div className="card">
          <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
            <h3 className="text-sm font-semibold flex items-center gap-2"><AlertTriangle size={14} /> Findings ({filteredFindings.length})</h3>
            <div className="flex items-center gap-2">
              <Filter size={14} className="text-text3" />
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="bg-surface2 border border-border rounded-lg px-3 py-1.5 text-xs text-text focus:border-accent focus:outline-none"
              >
                <option value="">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </div>
          </div>
          {filteredFindings.length === 0 ? (
            <div className="text-text3 text-sm py-8 text-center">
              {findings.length === 0 ? 'No findings for this session yet' : 'No findings match the selected severity'}
            </div>
          ) : (
            <div className="space-y-3 max-h-[600px] overflow-y-auto">
              {filteredFindings.map((f, i) => (
                <FindingCard key={i} finding={f} />
              ))}
            </div>
          )}
        </div>
      )}

      {tab === 'logs' && (
        <div className="card">
          <h3 className="text-sm font-semibold mb-4 flex items-center gap-2"><Terminal size={14} /> Session Logs</h3>
          <LiveConsole sessionId={id!} running={isRunning} maxHeight="500px" />
        </div>
      )}

      {tab === 'ai' && (
        <div className="card">
          <h3 className="text-sm font-semibold mb-4 flex items-center gap-2"><Brain size={14} /> AI Decisions ({decisions.length})</h3>
          {decisions.length === 0 ? (
            <div className="text-text3 text-sm py-8 text-center">No AI decisions recorded yet</div>
          ) : (
            <div className="space-y-2 max-h-[600px] overflow-y-auto">
              {decisions.map((d, i) => (
                <div key={i} className="bg-surface2 rounded-lg p-3 text-xs">
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-semibold text-accent">{d.decision_type}</span>
                    <span className="text-text3"><Clock size={10} className="inline mr-1" />{timeAgo(d.created_at)}</span>
                  </div>
                  <div className="text-text2 mb-1">Provider: {d.provider} · Tokens: {d.tokens_used} · Latency: {d.latency_ms}ms</div>
                  <pre className="text-[10px] text-text3 overflow-x-auto">{JSON.stringify(JSON.parse(d.decision_json || '{}'), null, 2).slice(0, 500)}...</pre>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ServerInfoCard({ info }: { info?: Record<string, unknown> }) {
  if (!info) {
    return (
      <div className="card space-y-3">
        <h3 className="text-sm font-semibold">Server Info</h3>
        <div className="text-text3 text-sm">Gathering server details...</div>
      </div>
    );
  }
  const dns = (info.dns as Record<string, string[]>) || {};
  const whois = (info.whois as Record<string, string>) || {};
  const headers = (info.headers as Record<string, string>) || {};
  const ssl = (info.ssl as Record<string, unknown>) || {};
  const technologies = (info.technologies as string[]) || [];
  const ipv4 = dns.ipv4 || [];
  const aliases = dns.aliases || [];

  return (
    <div className="card space-y-3 lg:col-span-2">
      <h3 className="text-sm font-semibold">Server Info</h3>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
        <div className="space-y-2">
          <div className="grid grid-cols-2 gap-2">
            <div><span className="text-text3 block">Hostname</span>{(info.hostname as string) || '-'}</div>
            <div><span className="text-text3 block">Primary IP</span>{(info.ip as string) || '-'}</div>
            <div><span className="text-text3 block">Server Header</span>{(info.server_header as string) || '-'}</div>
            <div><span className="text-text3 block">X-Powered-By</span>{(info.powered_by as string) || '-'}</div>
          </div>
          {ipv4.length > 0 && (
            <div>
              <span className="text-text3 block mb-1">IPv4 Addresses</span>
              <div className="font-mono text-text2">{ipv4.join(', ')}</div>
            </div>
          )}
          {aliases.length > 0 && (
            <div>
              <span className="text-text3 block mb-1">Aliases</span>
              <div className="font-mono text-text2">{aliases.join(', ')}</div>
            </div>
          )}
          {Boolean(ssl.has_ssl) && (
            <div>
              <span className="text-text3 block mb-1">SSL Certificate</span>
              <div className="bg-surface2 rounded p-2 space-y-0.5 font-mono">
                <div><span className="text-text3">Issuer:</span> {formatSSLName(ssl.issuer)}</div>
                <div><span className="text-text3">Subject:</span> {formatSSLName(ssl.subject)}</div>
                <div><span className="text-text3">Expires:</span> {(ssl.not_after as string) || '-'}</div>
                <div><span className="text-text3">Cipher:</span> {(ssl.cipher as string) || '-'}</div>
              </div>
            </div>
          )}
        </div>
        <div className="space-y-2">
          {Object.keys(whois).length > 0 && (
            <div>
              <span className="text-text3 block mb-1">WHOIS</span>
              <div className="bg-surface2 rounded p-2 space-y-0.5 font-mono max-h-32 overflow-auto">
                {Object.entries(whois).map(([k, v]) => (
                  <div key={k}><span className="text-text3">{k}:</span> {v}</div>
                ))}
              </div>
            </div>
          )}
          {Object.keys(headers).length > 0 && (
            <div>
              <span className="text-text3 block mb-1">HTTP Headers</span>
              <div className="bg-surface2 rounded p-2 space-y-0.5 font-mono max-h-32 overflow-auto">
                {Object.entries(headers).map(([k, v]) => (
                  <div key={k}><span className="text-text3">{k}:</span> {v}</div>
                ))}
              </div>
            </div>
          )}
          {technologies.length > 0 && (
            <div>
              <span className="text-text3 block mb-1">Technologies</span>
              <div className="flex flex-wrap gap-1">
                {technologies.map((t, i) => (
                  <span key={i} className="px-1.5 py-0.5 rounded bg-surface2 text-text2 text-[10px]">{t}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function formatSSLName(name: unknown): string {
  if (!name) return '-';
  if (typeof name === 'string') return name;
  // ssl.getpeercert returns tuples of tuples like ((('commonName', 'example.com'),), ...)
  try {
    const parts: string[] = [];
    const tuples = name as Array<Array<[string, string]>>;
    for (const group of tuples) {
      for (const [key, value] of group) {
        parts.push(`${key}=${value}`);
      }
    }
    return parts.join(', ') || '-';
  } catch {
    return String(name);
  }
}

function TokenUsageCard({ usage }: { usage?: import('../types').TokenUsage }) {
  if (!usage || usage.total_tokens === 0) {
    return (
      <div className="card space-y-3">
        <h3 className="text-sm font-semibold">Token Usage</h3>
        <div className="text-text3 text-sm">No LLM calls recorded yet.</div>
      </div>
    );
  }
  return (
    <div className="card space-y-3">
      <h3 className="text-sm font-semibold">Token Usage</h3>
      <div className="grid grid-cols-3 gap-3 text-center text-sm">
        <div className="bg-surface2 rounded-lg p-2">
          <div className="text-text3 text-[10px] uppercase">Input</div>
          <div className="font-mono text-accent">{usage.input_tokens.toLocaleString()}</div>
        </div>
        <div className="bg-surface2 rounded-lg p-2">
          <div className="text-text3 text-[10px] uppercase">Output</div>
          <div className="font-mono text-accent2">{usage.output_tokens.toLocaleString()}</div>
        </div>
        <div className="bg-surface2 rounded-lg p-2">
          <div className="text-text3 text-[10px] uppercase">Total</div>
          <div className="font-mono text-text">{usage.total_tokens.toLocaleString()}</div>
        </div>
      </div>
    </div>
  );
}

function FindingCard({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div className="bg-surface2 rounded-lg p-4 border border-border/50 hover:border-accent/30 transition-colors">
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            {severityBadge(finding.severity)}
            <span className="text-xs font-semibold text-text">{finding.attack_type}</span>
            <span className="text-text3 text-xs">{finding.endpoint || '-'}</span>
          </div>
          <div className="text-text2 text-xs">CVSS: {finding.cvss_score || '-'} · Confidence: {((finding.confidence || 0) * 100).toFixed(0)}%</div>
        </div>
        <button onClick={() => setExpanded(!expanded)} className="text-text3 hover:text-accent text-xs shrink-0">
          {expanded ? 'Collapse' : 'Details'}
        </button>
      </div>
      {expanded && (
        <div className="mt-3 pt-3 border-t border-border/50 space-y-2 text-xs">
          <div><span className="text-text3">Evidence:</span> <span className="text-text2 font-mono">{finding.evidence || '-'}</span></div>
          {finding.remediation && <div><span className="text-text3">Remediation:</span> <span className="text-success">{finding.remediation}</span></div>}
          {finding.parameter && <div><span className="text-text3">Parameter:</span> {finding.parameter}</div>}
        </div>
      )}
    </div>
  );
}

function statusBadge(status: string) {
  const map: Record<string, string> = {
    initialized: 'bg-accent2/15 text-accent2',
    running: 'bg-accent/15 text-accent',
    complete: 'bg-success/15 text-success',
    stopped: 'bg-danger/15 text-danger',
    error: 'bg-danger/15 text-danger',
  };
  return <span className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${map[status] || 'bg-text3/15 text-text3'}`}>{status}</span>;
}

function severityBadge(sev?: string) {
  const map: Record<string, string> = {
    critical: 'bg-danger/15 text-danger',
    high: 'bg-warn/15 text-warn',
    medium: 'bg-accent/15 text-accent',
    low: 'bg-success/15 text-success',
    info: 'bg-text3/15 text-text3',
  };
  return <span className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${map[sev || 'info'] || 'bg-text3/15 text-text3'}`}>{(sev || 'info').toUpperCase()}</span>;
}

function timeAgo(ts: string) {
  if (!ts) return '--';
  const d = new Date(ts).getTime();
  const diff = Date.now() - d;
  if (diff < 60000) return 'just now';
  if (diff < 3600000) return Math.floor(diff / 60000) + 'm ago';
  if (diff < 86400000) return Math.floor(diff / 3600000) + 'h ago';
  return new Date(ts).toLocaleDateString();
}
