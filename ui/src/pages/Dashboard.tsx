import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity, Shield, AlertTriangle, FileText, Zap, Clock,
  Server, Brain, Layers, Target,
  ChevronRight, Terminal, Lock, Globe, BarChart3, PieChart as PieChartIcon
} from 'lucide-react';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { apiClient } from '../lib/api';
import type { Session } from '../types';
import { useToast } from '../components/Toaster';

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f59e0b',
  medium: '#00d4ff',
  low: '#10b981',
  info: '#6b7280',
};

export default function Dashboard() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState({ total: 0, running: 0, findings: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 });
  const toast = useToast();

  useEffect(() => {
    loadData();
  }, []);

  async function loadData() {
    try {
      const { sessions: s } = await apiClient.sessions();
      setSessions(s.slice(0, 5));
      const total = s.length;
      const running = s.filter((x) => x.status === 'running').length;
      let findings = 0, critical = 0, high = 0, medium = 0, low = 0, info = 0;
      for (const sess of s) {
        findings += sess.findings_count || 0;
        try {
          const { findings: f } = await apiClient.getFindings(sess.session_id);
          for (const fi of f) {
            if (fi.severity === 'critical') critical++;
            else if (fi.severity === 'high') high++;
            else if (fi.severity === 'medium') medium++;
            else if (fi.severity === 'low') low++;
            else info++;
          }
        } catch {}
      }
      setStats({ total, running, findings, critical, high, medium, low, info });
    } catch (e) {
      toast((e as Error).message, 'error');
    } finally {
      setLoading(false);
    }
  }

  const severityData = [
    { name: 'Critical', value: stats.critical, color: SEVERITY_COLORS.critical },
    { name: 'High', value: stats.high, color: SEVERITY_COLORS.high },
    { name: 'Medium', value: stats.medium, color: SEVERITY_COLORS.medium },
    { name: 'Low', value: stats.low, color: SEVERITY_COLORS.low },
    { name: 'Info', value: stats.info, color: SEVERITY_COLORS.info },
  ].filter((d) => d.value > 0);

  const activityData = sessions.slice().reverse().map((s, i) => ({
    name: `S${i + 1}`,
    findings: s.findings_count || 0,
  }));

  const statCards = [
    { label: 'Total Sessions', value: stats.total, icon: Layers, color: 'text-accent', gradient: 'from-accent to-accent2', desc: 'All-time' },
    { label: 'Active Scans', value: stats.running, icon: Zap, color: 'text-warn', gradient: 'from-warn to-accent', desc: 'Currently running' },
    { label: 'Total Findings', value: stats.findings, icon: FileText, color: 'text-accent', gradient: 'from-accent to-success', desc: 'Across all sessions' },
    { label: 'Critical', value: stats.critical, icon: AlertTriangle, color: 'text-danger', gradient: 'from-danger to-warn', desc: 'Immediate action' },
    { label: 'High', value: stats.high, icon: Shield, color: 'text-warn', gradient: 'from-warn to-accent2', desc: 'High priority' },
    { label: 'Medium', value: stats.medium, icon: Lock, color: 'text-accent', gradient: 'from-accent to-accent2', desc: 'Medium priority' },
  ];

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-xl font-bold flex items-center gap-2">
            <BarChart3 size={20} className="text-accent" />
            Operations <span className="text-accent">Dashboard</span>
          </h2>
          <p className="text-text3 text-xs mt-1">Real-time overview of CHAI security operations</p>
        </div>
        <Link to="/sessions/new" className="btn-primary text-sm px-4 py-2 rounded-lg flex items-center gap-2">
          <Zap size={16} /> New Session
        </Link>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4 mb-6">
        {statCards.map((s) => (
          <div key={s.label} className="card relative overflow-hidden group">
            <div className={`absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r ${s.gradient}`} />
            <div className="text-[11px] text-text3 uppercase tracking-wider flex items-center gap-1">
              <s.icon size={12} /> {s.label}
            </div>
            <div className={`text-2xl font-bold mt-1 ${s.color}`}>{s.value}</div>
            <div className="text-[10px] text-text3 mt-0.5">{s.desc}</div>
            <s.icon size={16} className="absolute top-3 right-3 text-text3 opacity-20 group-hover:opacity-40 transition-opacity" />
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
        <div className="card">
          <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
            <PieChartIcon size={14} className="text-accent" /> Findings by Severity
          </h3>
          <div className="h-56">
            {severityData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={severityData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={70} stroke="none">
                    {severityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ background: '#111827', border: '1px solid #1e3a5f', borderRadius: '8px', fontSize: '12px' }}
                    itemStyle={{ color: '#e5e7eb' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-text3 text-sm flex-col gap-2">
                <Shield size={24} className="opacity-30" /> No findings yet
              </div>
            )}
          </div>
        </div>
        <div className="card">
          <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
            <BarChart3 size={14} className="text-accent" /> Session Activity
          </h3>
          <div className="h-56">
            {activityData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={activityData}>
                  <XAxis dataKey="name" tick={{ fill: '#6b7280', fontSize: 11 }} axisLine={{ stroke: '#1e3a5f' }} tickLine={false} />
                  <YAxis tick={{ fill: '#6b7280', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <Tooltip
                    contentStyle={{ background: '#111827', border: '1px solid #1e3a5f', borderRadius: '8px', fontSize: '12px' }}
                    itemStyle={{ color: '#e5e7eb' }}
                  />
                  <Bar dataKey="findings" fill="#00d4ff" radius={[2, 2, 0, 0]} opacity={0.6} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-text3 text-sm flex-col gap-2">
                <Activity size={24} className="opacity-30" /> No sessions yet
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
        <div className="card lg:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold flex items-center gap-2"><Clock size={14} className="text-accent" /> Recent Sessions</h3>
            <Link to="/sessions" className="text-xs text-accent hover:underline flex items-center gap-1">View All <ChevronRight size={12} /></Link>
          </div>
          {loading ? (
            <div className="text-text3 text-sm py-8 text-center flex items-center justify-center gap-2">
              <Activity size={16} className="animate-spin" /> Loading...
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-text3 text-[11px] uppercase tracking-wider border-b border-border">
                  <th className="py-2 px-3"><span className="flex items-center gap-1"><Shield size={10} /> Session</span></th>
                  <th className="py-2 px-3"><span className="flex items-center gap-1"><Globe size={10} /> Target</span></th>
                  <th className="py-2 px-3"><span className="flex items-center gap-1"><FileText size={10} /> Type</span></th>
                  <th className="py-2 px-3"><span className="flex items-center gap-1"><Activity size={10} /> Status</span></th>
                  <th className="py-2 px-3"><span className="flex items-center gap-1"><AlertTriangle size={10} /> Findings</span></th>
                  <th className="py-2 px-3"><span className="flex items-center gap-1"><Clock size={10} /> Created</span></th>
                </tr>
              </thead>
              <tbody>
                {sessions.length === 0 ? (
                  <tr><td colSpan={6} className="py-8 text-center text-text3 text-sm flex flex-col items-center gap-2">
                    <Shield size={24} className="opacity-30" /> No sessions yet. Create one to get started.
                  </td></tr>
                ) : (
                  sessions.map((s) => (
                    <tr key={s.session_id} className="border-b border-border/50 hover:bg-accent/5 transition-colors">
                      <td className="py-2 px-3">
                        <Link to={`/sessions/${s.session_id}`} className="text-accent hover:underline font-mono text-xs flex items-center gap-1">
                          <Shield size={10} /> {s.session_id.slice(0, 16)}...
                        </Link>
                      </td>
                      <td className="py-2 px-3 text-xs">{s.target}</td>
                      <td className="py-2 px-3 text-xs"><span className="px-1.5 py-0.5 rounded bg-surface2 text-text2 text-[10px]">{s.test_type}</span></td>
                      <td className="py-2 px-3">{statusBadge(s.status)}</td>
                      <td className="py-2 px-3 text-xs">{s.findings_count || 0}</td>
                      <td className="py-2 px-3 text-text3 text-xs flex items-center gap-1"><Clock size={12} />{timeAgo(s.created_at)}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          )}
        </div>

        <div className="card space-y-4">
          <h3 className="text-sm font-semibold flex items-center gap-2"><Terminal size={14} className="text-accent" /> Quick Actions</h3>
          <div className="space-y-2">
            <Link to="/sessions/new" className="flex items-center gap-2 p-2.5 rounded-lg bg-surface2 hover:bg-accent/10 border border-border/50 hover:border-accent/30 transition-colors text-sm">
              <div className="w-8 h-8 rounded-lg bg-accent/15 flex items-center justify-center"><Zap size={14} className="text-accent" /></div>
              <div>
                <div className="font-medium text-xs">New Pentest Session</div>
                <div className="text-text3 text-[10px]">Start a new security assessment</div>
              </div>
            </Link>
            <Link to="/findings" className="flex items-center gap-2 p-2.5 rounded-lg bg-surface2 hover:bg-accent/10 border border-border/50 hover:border-accent/30 transition-colors text-sm">
              <div className="w-8 h-8 rounded-lg bg-warn/15 flex items-center justify-center"><AlertTriangle size={14} className="text-warn" /></div>
              <div>
                <div className="font-medium text-xs">Review Findings</div>
                <div className="text-text3 text-[10px]">Browse discovered vulnerabilities</div>
              </div>
            </Link>
            <Link to="/tools" className="flex items-center gap-2 p-2.5 rounded-lg bg-surface2 hover:bg-accent/10 border border-border/50 hover:border-accent/30 transition-colors text-sm">
              <div className="w-8 h-8 rounded-lg bg-accent2/15 flex items-center justify-center"><Terminal size={14} className="text-accent2" /></div>
              <div>
                <div className="font-medium text-xs">Run Manual Tools</div>
                <div className="text-text3 text-[10px]">Execute security tools manually</div>
              </div>
            </Link>
            <Link to="/reports" className="flex items-center gap-2 p-2.5 rounded-lg bg-surface2 hover:bg-accent/10 border border-border/50 hover:border-accent/30 transition-colors text-sm">
              <div className="w-8 h-8 rounded-lg bg-success/15 flex items-center justify-center"><FileText size={14} className="text-success" /></div>
              <div>
                <div className="font-medium text-xs">Generate Report</div>
                <div className="text-text3 text-[10px]">Export session reports</div>
              </div>
            </Link>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold flex items-center gap-2"><Brain size={14} className="text-accent" /> System Status</h3>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-success/15 flex items-center justify-center"><Server size={14} className="text-success" /></div>
            <div>
              <div className="text-xs font-medium">MCP Server</div>
              <div className="text-[10px] text-success flex items-center gap-1"><div className="w-1.5 h-1.5 rounded-full bg-success animate-pulse" /> Online</div>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-accent/15 flex items-center justify-center"><Brain size={14} className="text-accent" /></div>
            <div>
              <div className="text-xs font-medium">AI Planner</div>
              <div className="text-[10px] text-accent flex items-center gap-1"><div className="w-1.5 h-1.5 rounded-full bg-accent animate-pulse" /> Active</div>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-accent2/15 flex items-center justify-center"><Target size={14} className="text-accent2" /></div>
            <div>
              <div className="text-xs font-medium">WSL Adapter</div>
              <div className="text-[10px] text-accent2 flex items-center gap-1"><div className="w-1.5 h-1.5 rounded-full bg-accent2 animate-pulse" /> Connected</div>
            </div>
          </div>
        </div>
      </div>
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
