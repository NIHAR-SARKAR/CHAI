import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Plus, StopCircle, Eye, Clock, Trash2, AlertTriangle, X, Shield, Activity, FileText } from 'lucide-react';
import { apiClient } from '../lib/api';
import type { Session } from '../types';
import { useToast } from '../components/Toaster';

export default function Sessions() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [loading, setLoading] = useState(true);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const toast = useToast();

  useEffect(() => { load(); }, []);

  async function load() {
    setLoading(true);
    try {
      const { sessions: s } = await apiClient.sessions();
      setSessions(s);
    } catch (e) {
      toast((e as Error).message, 'error');
    } finally {
      setLoading(false);
    }
  }

  async function stop(id: string) {
    try {
      await apiClient.stopSession(id);
      toast('Session stopped', 'success');
      load();
    } catch (e) {
      toast((e as Error).message, 'error');
    }
  }

  async function remove(id: string) {
    try {
      await apiClient.deleteSession(id);
      toast('Session deleted', 'success');
      setConfirmDelete(null);
      load();
    } catch (e) {
      toast((e as Error).message, 'error');
    }
  }

  const stats = {
    total: sessions.length,
    running: sessions.filter(s => s.status === 'running').length,
    complete: sessions.filter(s => s.status === 'complete').length,
    findings: sessions.reduce((sum, s) => sum + (s.findings_count || 0), 0),
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <h2 className="text-xl font-bold">Pentest <span className="text-accent">Sessions</span></h2>
          <span className="px-2 py-0.5 rounded-full bg-accent/10 text-accent text-[10px] font-semibold uppercase tracking-wider">{stats.total} Total</span>
        </div>
        <Link to="/sessions/new" className="btn-primary text-sm px-4 py-2 rounded-lg flex items-center gap-2">
          <Plus size={16} /> New Session
        </Link>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
        <div className="card relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-accent to-accent2" />
          <div className="text-[11px] text-text3 uppercase tracking-wider flex items-center gap-1"><Activity size={12} /> Total</div>
          <div className="text-2xl font-bold mt-1 text-accent">{stats.total}</div>
        </div>
        <div className="card relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-accent to-success" />
          <div className="text-[11px] text-text3 uppercase tracking-wider flex items-center gap-1"><Shield size={12} /> Running</div>
          <div className="text-2xl font-bold mt-1 text-success">{stats.running}</div>
        </div>
        <div className="card relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-warn to-accent2" />
          <div className="text-[11px] text-text3 uppercase tracking-wider flex items-center gap-1"><FileText size={12} /> Complete</div>
          <div className="text-2xl font-bold mt-1 text-warn">{stats.complete}</div>
        </div>
        <div className="card relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-danger to-warn" />
          <div className="text-[11px] text-text3 uppercase tracking-wider flex items-center gap-1"><AlertTriangle size={12} /> Findings</div>
          <div className="text-2xl font-bold mt-1 text-danger">{stats.findings}</div>
        </div>
      </div>

      <div className="card">
        {loading ? (
          <div className="py-12 text-center text-text3 flex items-center justify-center gap-2">
            <Activity size={16} className="animate-spin" /> Loading sessions...
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-text3 text-[11px] uppercase tracking-wider border-b border-border">
                  <th className="py-3 px-4"><span className="flex items-center gap-1"><Shield size={12} /> Session ID</span></th>
                  <th className="py-3 px-4"><span className="flex items-center gap-1"><Activity size={12} /> Target</span></th>
                  <th className="py-3 px-4"><span className="flex items-center gap-1"><FileText size={12} /> Type</span></th>
                  <th className="py-3 px-4"><span className="flex items-center gap-1"><Shield size={12} /> Status</span></th>
                  <th className="py-3 px-4"><span className="flex items-center gap-1"><AlertTriangle size={12} /> Findings</span></th>
                  <th className="py-3 px-4"><span className="flex items-center gap-1"><Clock size={12} /> Created</span></th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {sessions.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-12 text-center text-text3">
                      <div className="flex flex-col items-center gap-2">
                        <Shield size={24} className="opacity-30" />
                        <span>No sessions yet. <Link to="/sessions/new" className="text-accent hover:underline">Create one</Link>.</span>
                      </div>
                    </td>
                  </tr>
                ) : (
                  sessions.map((s) => (
                    <tr key={s.session_id} className="border-b border-border/50 hover:bg-accent/5 transition-colors">
                      <td className="py-3 px-4">
                        <Link to={`/sessions/${s.session_id}`} className="text-accent hover:underline font-mono text-xs flex items-center gap-1">
                          <Shield size={12} /> {s.session_id}
                        </Link>
                      </td>
                      <td className="py-3 px-4 text-xs">{s.target}</td>
                      <td className="py-3 px-4 text-xs"><span className="px-1.5 py-0.5 rounded bg-surface2 text-text2 text-[10px]">{s.test_type}</span></td>
                      <td className="py-3 px-4">{statusBadge(s.status)}</td>
                      <td className="py-3 px-4 text-xs">{s.findings_count || 0}</td>
                      <td className="py-3 px-4 text-text3 text-xs flex items-center gap-1"><Clock size={12} />{timeAgo(s.created_at)}</td>
                      <td className="py-3 px-4">
                        <div className="flex gap-2 justify-end">
                          <Link to={`/sessions/${s.session_id}`} className="p-1.5 rounded hover:bg-surface2 text-text2 hover:text-accent transition-colors" title="View">
                            <Eye size={14} />
                          </Link>
                          {s.status === 'running' && (
                            <button onClick={() => stop(s.session_id)} className="p-1.5 rounded hover:bg-danger/20 text-text2 hover:text-danger transition-colors" title="Stop">
                              <StopCircle size={14} />
                            </button>
                          )}
                          <button onClick={() => setConfirmDelete(s.session_id)} className="p-1.5 rounded hover:bg-danger/20 text-text2 hover:text-danger transition-colors" title="Delete">
                            <Trash2 size={14} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {confirmDelete && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-xl p-6 max-w-md w-full shadow-2xl">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-full bg-danger/15 flex items-center justify-center">
                <AlertTriangle size={20} className="text-danger" />
              </div>
              <div>
                <h3 className="text-sm font-bold">Delete Session</h3>
                <p className="text-text3 text-xs">This action cannot be undone.</p>
              </div>
            </div>
            <p className="text-sm text-text2 mb-6">
              Are you sure you want to delete session <span className="font-mono text-accent">{confirmDelete}</span>? All findings, AI decisions, logs, and reports associated with this session will be permanently removed.
            </p>
            <div className="flex gap-3 justify-end">
              <button onClick={() => setConfirmDelete(null)} className="btn px-4 py-2 rounded-lg text-sm flex items-center gap-2">
                <X size={14} /> Cancel
              </button>
              <button onClick={() => remove(confirmDelete)} className="btn-danger px-4 py-2 rounded-lg text-sm flex items-center gap-2">
                <Trash2 size={14} /> Delete
              </button>
            </div>
          </div>
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

function timeAgo(ts: string) {
  if (!ts) return '--';
  const d = new Date(ts).getTime();
  const diff = Date.now() - d;
  if (diff < 60000) return 'just now';
  if (diff < 3600000) return Math.floor(diff / 60000) + 'm ago';
  if (diff < 86400000) return Math.floor(diff / 3600000) + 'h ago';
  return new Date(ts).toLocaleDateString();
}
