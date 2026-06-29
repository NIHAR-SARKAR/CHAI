import { useEffect, useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { Filter, ChevronLeft, ChevronRight, Shield, AlertTriangle, FileText, Activity, Eye, Clock } from 'lucide-react';
import { apiClient } from '../lib/api';
import type { Finding, Session } from '../types';
import { useToast } from '../components/Toaster';

const PAGE_SIZES = [10, 25, 50];

export default function Findings() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState('');
  const [sessionFilter, setSessionFilter] = useState('');
  const [pageSize, setPageSize] = useState(25);
  const [currentPage, setCurrentPage] = useState(1);
  const toast = useToast();

  useEffect(() => { load(); }, [severityFilter, sessionFilter]);

  // Reset to page 1 when filters or page size change
  useEffect(() => { setCurrentPage(1); }, [severityFilter, sessionFilter, pageSize]);

  async function load() {
    setLoading(true);
    try {
      const { sessions: s } = await apiClient.sessions();
      setSessions(s);
      let all: Finding[] = [];
      const sessionsToCheck = sessionFilter ? [sessionFilter] : s.map(x => x.session_id);
      for (const sid of sessionsToCheck) {
        try {
          const { findings: f } = await apiClient.getFindings(sid, severityFilter || undefined);
          all = all.concat(f.map(x => ({ ...x, session_id: sid })));
        } catch {}
      }
      const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      all.sort((a, b) => (order[a.severity || 'info'] ?? 5) - (order[b.severity || 'info'] ?? 5));
      setFindings(all);
    } catch (e) {
      toast((e as Error).message, 'error');
    } finally {
      setLoading(false);
    }
  }

  const totalPages = Math.max(1, Math.ceil(findings.length / pageSize));
  const safePage = Math.min(currentPage, totalPages);
  const paginatedFindings = useMemo(() => {
    const start = (safePage - 1) * pageSize;
    return findings.slice(start, start + pageSize);
  }, [findings, safePage, pageSize]);

  const stats = useMemo(() => {
    const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => { counts[f.severity || 'info'] = (counts[f.severity || 'info'] || 0) + 1; });
    return counts;
  }, [findings]);

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <h2 className="text-xl font-bold">Security <span className="text-accent">Findings</span></h2>
          <span className="px-2 py-0.5 rounded-full bg-accent/10 text-accent text-[10px] font-semibold uppercase tracking-wider">{findings.length} Total</span>
        </div>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mb-6">
        {(['critical', 'high', 'medium', 'low', 'info'] as const).map((sev) => (
          <div key={sev} className="card relative overflow-hidden cursor-pointer" onClick={() => setSeverityFilter(sev === severityFilter ? '' : sev)}>
            <div className={`absolute top-0 left-0 right-0 h-0.5 ${severityGradient(sev)}`} />
            <div className="text-[11px] text-text3 uppercase tracking-wider flex items-center gap-1"><AlertTriangle size={12} /> {sev}</div>
            <div className="text-2xl font-bold mt-1" style={{ color: severityColor(sev) }}>{stats[sev] || 0}</div>
            {severityFilter === sev && <div className="absolute top-2 right-2 w-2 h-2 rounded-full bg-accent animate-pulse" />}
          </div>
        ))}
      </div>

      <div className="card mb-4">
        <div className="flex flex-wrap gap-3 items-center justify-between">
          <div className="flex flex-wrap gap-3 items-center">
            <div className="flex items-center gap-2 text-text3 text-xs">
              <Filter size={14} /> Filters:
            </div>
            <select
              value={sessionFilter}
              onChange={(e) => setSessionFilter(e.target.value)}
              className="bg-surface2 border border-border rounded-lg px-3 py-1.5 text-xs text-text focus:border-accent focus:outline-none"
            >
              <option value="">All Sessions</option>
              {sessions.map(s => <option key={s.session_id} value={s.session_id}>{s.session_id.slice(0, 16)}... — {s.target}</option>)}
            </select>
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
            <button onClick={load} className="btn text-xs px-3 py-1.5 flex items-center gap-1"><Activity size={12} /> Refresh</button>
          </div>
          <div className="flex items-center gap-2 text-xs text-text3">
            <span>Show:</span>
            <select
              value={pageSize}
              onChange={(e) => setPageSize(Number(e.target.value))}
              className="bg-surface2 border border-border rounded-lg px-2 py-1 text-xs text-text focus:border-accent focus:outline-none"
            >
              {PAGE_SIZES.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
            <span>per page</span>
          </div>
        </div>
      </div>

      <div className="card">
        {loading ? (
          <div className="py-12 text-center text-text3 flex items-center justify-center gap-2">
            <Activity size={16} className="animate-spin" /> Loading findings...
          </div>
        ) : findings.length === 0 ? (
          <div className="py-12 text-center text-text3 flex flex-col items-center gap-2">
            <Shield size={24} className="opacity-30" />
            <span>No findings found</span>
          </div>
        ) : (
          <div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-text3 text-[11px] uppercase tracking-wider border-b border-border">
                    <th className="py-3 px-4"><span className="flex items-center gap-1"><AlertTriangle size={12} /> Severity</span></th>
                    <th className="py-3 px-4"><span className="flex items-center gap-1"><FileText size={12} /> Type</span></th>
                    <th className="py-3 px-4"><span className="flex items-center gap-1"><Activity size={12} /> Endpoint</span></th>
                    <th className="py-3 px-4"><span className="flex items-center gap-1"><Shield size={12} /> CVSS</span></th>
                    <th className="py-3 px-4"><span className="flex items-center gap-1"><Eye size={12} /> Confidence</span></th>
                    <th className="py-3 px-4"><span className="flex items-center gap-1"><Clock size={12} /> Session</span></th>
                    <th className="py-3 px-4"><span className="flex items-center gap-1"><FileText size={12} /> Evidence</span></th>
                  </tr>
                </thead>
                <tbody>
                  {paginatedFindings.map((f, i) => (
                    <tr key={i} className="border-b border-border/50 hover:bg-accent/5 transition-colors">
                      <td className="py-3 px-4">{severityBadge(f.severity)}</td>
                      <td className="py-3 px-4 text-xs">{f.attack_type}</td>
                      <td className="py-3 px-4 text-xs max-w-[200px] truncate" title={f.endpoint}>{f.endpoint || '-'}</td>
                      <td className="py-3 px-4 text-xs">{f.cvss_score || '-'}</td>
                      <td className="py-3 px-4 text-xs">{((f.confidence || 0) * 100).toFixed(0)}%</td>
                      <td className="py-3 px-4">
                        <Link to={`/sessions/${f.session_id}`} className="text-accent hover:underline text-xs font-mono flex items-center gap-1">
                          <Shield size={10} /> {f.session_id?.slice(0, 12)}...
                        </Link>
                      </td>
                      <td className="py-3 px-4 text-xs max-w-[250px] truncate text-text2" title={f.evidence}>{(f.evidence || '-').slice(0, 80)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {totalPages > 1 && (
              <div className="flex items-center justify-between mt-4 px-4 py-3 border-t border-border/50">
                <div className="text-xs text-text3">
                  Showing <span className="text-text font-medium">{(safePage - 1) * pageSize + 1}</span> - <span className="text-text font-medium">{Math.min(safePage * pageSize, findings.length)}</span> of <span className="text-text font-medium">{findings.length}</span> findings
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                    disabled={safePage <= 1}
                    className="p-1.5 rounded hover:bg-surface2 text-text2 hover:text-accent transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
                  >
                    <ChevronLeft size={16} />
                  </button>
                  <div className="flex gap-1">
                    {Array.from({ length: totalPages }, (_, i) => i + 1).map(page => (
                      <button
                        key={page}
                        onClick={() => setCurrentPage(page)}
                        className={`min-w-[28px] h-7 rounded text-xs font-medium transition-colors ${
                          page === safePage
                            ? 'bg-accent text-black'
                            : 'hover:bg-surface2 text-text2'
                        }`}
                      >
                        {page}
                      </button>
                    ))}
                  </div>
                  <button
                    onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                    disabled={safePage >= totalPages}
                    className="p-1.5 rounded hover:bg-surface2 text-text2 hover:text-accent transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
                  >
                    <ChevronRight size={16} />
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
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

function severityColor(sev: string): string {
  const map: Record<string, string> = {
    critical: '#ef4444',
    high: '#f59e0b',
    medium: '#00d4ff',
    low: '#10b981',
    info: '#6b7280',
  };
  return map[sev] || '#6b7280';
}

function severityGradient(sev: string): string {
  const map: Record<string, string> = {
    critical: 'from-danger to-warn',
    high: 'from-warn to-accent',
    medium: 'from-accent to-accent2',
    low: 'from-success to-accent',
    info: 'from-text3 to-text2',
  };
  return `bg-gradient-to-r ${map[sev] || 'from-text3 to-text2'}`;
}
