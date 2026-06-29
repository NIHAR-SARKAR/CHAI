import { useEffect, useState } from 'react';
import { Wrench, Play, Terminal } from 'lucide-react';
import { apiClient } from '../lib/api';
import type { Session } from '../types';
import { useToast } from '../components/Toaster';
import LiveConsole from '../components/LiveConsole';

const TOOLS = [
  { name: 'recon_passive', label: 'Recon — Passive', type: '' },
  { name: 'recon_active', label: 'Recon — Active', type: '' },
  { name: 'scan_vulnerabilities', label: 'Vulnerability Scan', type: 'nuclei', types: ['nuclei', 'nmap'] },
  { name: 'test_injection', label: 'Injection Test', type: 'sqli', types: ['sqli', 'nosqli', 'command_injection', 'ssti', 'xxe'] },
  { name: 'test_authentication', label: 'Auth Test', type: 'bypass', types: ['bypass', 'jwt', 'brute_force', 'password_reset', 'session_fixation', 'privilege_escalation'] },
  { name: 'test_network', label: 'Network Test', type: 'ssl', types: ['ssl', 'headers', 'port_scan'] },
  { name: 'test_xss', label: 'XSS Test', type: 'reflected', types: ['reflected', 'stored', 'dom', 'header_reflected', 'csp'] },
  { name: 'test_ssrf', label: 'SSRF Test', type: '' },
  { name: 'test_access_control', label: 'Access Control', type: 'idor', types: ['idor', 'bola', 'path_traversal', 'method_tampering', 'forced_browsing'] },
  { name: 'test_api_security', label: 'API Security', type: 'mass_assignment', types: ['mass_assignment', 'api_versioning', 'graphql_introspection'] },
  { name: 'test_misconfig', label: 'Misconfig Test', type: 'cors', types: ['cors', 'verbose_errors', 'debug_endpoints', 'security_headers'] },
  { name: 'test_rate_limit', label: 'Rate Limit', type: 'login', types: ['login', 'api', 'bypass_headers'] },
  { name: 'test_sensitive_data', label: 'Sensitive Data', type: 'js_secrets', types: ['js_secrets', 'api_overexposure', 'http_https', 'git_backup'] },
  { name: 'test_business_logic', label: 'Business Logic', type: 'negative_values', types: ['negative_values', 'coupon_abuse'] },
  { name: 'analyze_findings', label: 'Analyze Findings', type: '' },
];

export default function Tools() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [selectedSession, setSelectedSession] = useState('');
  const [target, setTarget] = useState('');
  const [selectedTool, setSelectedTool] = useState('recon_passive');
  const [subType, setSubType] = useState('');
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<Record<string, unknown> | null>(null);
  const [command, setCommand] = useState('');
  const [cmdResult, setCmdResult] = useState<Record<string, unknown> | null>(null);
  const toast = useToast();

  useEffect(() => {
    apiClient.sessions().then(({ sessions: s }) => { setSessions(s); if (s.length) { setSelectedSession(s[0].session_id); setTarget(s[0].target); } });
  }, []);

  const toolInfo = TOOLS.find(t => t.name === selectedTool);
  const hasSubTypes = !!toolInfo?.types;

  async function runTool() {
    if (!selectedSession || !target) { toast('Session and target required', 'error'); return; }
    setRunning(true); setResult(null);
    try {
      const r = await apiClient.runTool({ session_id: selectedSession, target, tool_name: selectedTool, tool_type: subType || toolInfo?.type });
      setResult(r);
      toast('Tool executed successfully', 'success');
    } catch (e) {
      toast((e as Error).message, 'error');
    } finally {
      setRunning(false);
    }
  }

  async function runCmd() {
    if (!selectedSession || !command) { toast('Session and command required', 'error'); return; }
    setRunning(true); setCmdResult(null);
    try {
      const r = await apiClient.runCommand({ session_id: selectedSession, command });
      setCmdResult(r);
      toast('Command executed', 'success');
    } catch (e) {
      toast((e as Error).message, 'error');
    } finally {
      setRunning(false);
    }
  }

  return (
    <div>
      <h2 className="text-xl font-bold mb-6">Manual <span className="text-accent">Tools</span></h2>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="card space-y-4">
          <h3 className="text-sm font-semibold flex items-center gap-2"><Wrench size={14} /> Run Security Tool</h3>
          <div className="space-y-3">
            <div>
              <label className="text-[11px] text-text3 uppercase tracking-wider mb-1 block">Session</label>
              <select value={selectedSession} onChange={(e) => { setSelectedSession(e.target.value); const s = sessions.find(x => x.session_id === e.target.value); if (s) setTarget(s.target); }} className="w-full bg-surface2 border border-border rounded-lg px-3 py-2 text-sm text-text focus:border-accent focus:outline-none">
                {sessions.map(s => <option key={s.session_id} value={s.session_id}>{s.session_id.slice(0, 16)}... — {s.target}</option>)}
              </select>
            </div>
            <div>
              <label className="text-[11px] text-text3 uppercase tracking-wider mb-1 block">Target</label>
              <input type="text" value={target} onChange={(e) => setTarget(e.target.value)} className="w-full bg-surface2 border border-border rounded-lg px-3 py-2 text-sm text-text focus:border-accent focus:outline-none" />
            </div>
            <div>
              <label className="text-[11px] text-text3 uppercase tracking-wider mb-1 block">Tool</label>
              <select value={selectedTool} onChange={(e) => { setSelectedTool(e.target.value); const t = TOOLS.find(x => x.name === e.target.value); setSubType(t?.type || ''); }} className="w-full bg-surface2 border border-border rounded-lg px-3 py-2 text-sm text-text focus:border-accent focus:outline-none">
                {TOOLS.map(t => <option key={t.name} value={t.name}>{t.label}</option>)}
              </select>
            </div>
            {hasSubTypes && (
              <div>
                <label className="text-[11px] text-text3 uppercase tracking-wider mb-1 block">Sub-type</label>
                <select value={subType} onChange={(e) => setSubType(e.target.value)} className="w-full bg-surface2 border border-border rounded-lg px-3 py-2 text-sm text-text focus:border-accent focus:outline-none">
                  {toolInfo.types?.map(t => <option key={t} value={t}>{t}</option>)}
                </select>
              </div>
            )}
            <button onClick={runTool} disabled={running} className="btn-primary text-sm px-4 py-2 rounded-lg flex items-center gap-2 disabled:opacity-50">
              <Play size={14} /> {running ? 'Running...' : 'Execute Tool'}
            </button>
          </div>
          {result && (
            <div className="bg-surface2 rounded-lg p-3 max-h-64 overflow-auto">
              <pre className="text-xs text-text2 font-mono">{JSON.stringify(result, null, 2)}</pre>
            </div>
          )}
        </div>
        <div className="card space-y-4">
          <h3 className="text-sm font-semibold flex items-center gap-2"><Terminal size={14} /> Custom Command</h3>
          <div className="space-y-3">
            <div>
              <label className="text-[11px] text-text3 uppercase tracking-wider mb-1 block">Session</label>
              <select value={selectedSession} onChange={(e) => setSelectedSession(e.target.value)} className="w-full bg-surface2 border border-border rounded-lg px-3 py-2 text-sm text-text focus:border-accent focus:outline-none">
                {sessions.map(s => <option key={s.session_id} value={s.session_id}>{s.session_id.slice(0, 16)}... — {s.target}</option>)}
              </select>
            </div>
            <div>
              <label className="text-[11px] text-text3 uppercase tracking-wider mb-1 block">Command</label>
              <input type="text" value={command} onChange={(e) => setCommand(e.target.value)} placeholder="nmap -sV target.com" className="w-full bg-surface2 border border-border rounded-lg px-3 py-2 text-sm text-text placeholder:text-text3 focus:border-accent focus:outline-none font-mono" />
            </div>
            <button onClick={runCmd} disabled={running} className="btn text-sm px-4 py-2 rounded-lg flex items-center gap-2 disabled:opacity-50">
              <Terminal size={14} /> {running ? 'Running...' : 'Run Command'}
            </button>
          </div>
          {cmdResult && (
            <div className="bg-surface2 rounded-lg p-3 max-h-64 overflow-auto">
              <pre className="text-xs text-text2 font-mono">{JSON.stringify(cmdResult, null, 2)}</pre>
            </div>
          )}
        </div>
        <div className="card space-y-4 lg:col-span-2">
          <h3 className="text-sm font-semibold flex items-center gap-2"><Terminal size={14} /> Activity Console</h3>
          {selectedSession ? (
            <LiveConsole sessionId={selectedSession} running={running} maxHeight="400px" />
          ) : (
            <div className="text-text3 text-sm">Select a session to see live activity.</div>
          )}
        </div>
      </div>
    </div>
  );
}
