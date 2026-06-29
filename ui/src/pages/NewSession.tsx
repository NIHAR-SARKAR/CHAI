import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft, Target, Globe, Shield } from 'lucide-react';
import { apiClient } from '../lib/api';
import { useToast } from '../components/Toaster';

const TEST_TYPES = [
  { value: 'web_app', label: 'Web Application' },
  { value: 'api', label: 'API' },
  { value: 'network', label: 'Network' },
  { value: 'red_team', label: 'Red Team' },
  { value: 'mobile_app', label: 'Mobile App' },
];

export default function NewSession() {
  const [target, setTarget] = useState('');
  const [testType, setTestType] = useState('web_app');
  const [scope, setScope] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const navigate = useNavigate();
  const toast = useToast();

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!target.trim()) { toast('Target URL is required', 'error'); return; }
    setSubmitting(true);
    try {
      const scopeList = scope.split(',').map(s => s.trim()).filter(Boolean);
      const result = await apiClient.createSession({ target: target.trim(), test_type: testType, scope: scopeList });
      toast(`Session created: ${result.session_id}`, 'success');
      navigate('/sessions');
    } catch (e) {
      toast((e as Error).message, 'error');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="max-w-2xl">
      <button onClick={() => navigate(-1)} className="flex items-center gap-2 text-text2 hover:text-text text-sm mb-4 transition-colors">
        <ArrowLeft size={16} /> Back
      </button>
      <h2 className="text-xl font-bold mb-6">New <span className="text-accent">Session</span></h2>
      <form onSubmit={submit} className="card space-y-4">
        <div>
          <label className="flex items-center gap-2 text-[11px] text-text3 uppercase tracking-wider mb-1.5">
            <Target size={12} /> Target URL
          </label>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="https://target.example.com"
            className="w-full bg-surface2 border border-border rounded-lg px-3 py-2 text-sm text-text placeholder:text-text3 focus:border-accent focus:outline-none transition-colors"
            required
          />
        </div>
        <div>
          <label className="flex items-center gap-2 text-[11px] text-text3 uppercase tracking-wider mb-1.5">
            <Shield size={12} /> Test Type
          </label>
          <select
            value={testType}
            onChange={(e) => setTestType(e.target.value)}
            className="w-full bg-surface2 border border-border rounded-lg px-3 py-2 text-sm text-text focus:border-accent focus:outline-none transition-colors"
          >
            {TEST_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
          </select>
        </div>
        <div>
          <label className="flex items-center gap-2 text-[11px] text-text3 uppercase tracking-wider mb-1.5">
            <Globe size={12} /> Scope (comma-separated domains/IPs)
          </label>
          <input
            type="text"
            value={scope}
            onChange={(e) => setScope(e.target.value)}
            placeholder="target.example.com, api.target.com"
            className="w-full bg-surface2 border border-border rounded-lg px-3 py-2 text-sm text-text placeholder:text-text3 focus:border-accent focus:outline-none transition-colors"
          />
        </div>
        <div className="flex gap-3 pt-2">
          <button type="submit" disabled={submitting} className="btn-primary px-5 py-2 rounded-lg text-sm font-medium disabled:opacity-50">
            {submitting ? 'Creating...' : 'Create Session'}
          </button>
          <button type="button" onClick={() => navigate('/sessions')} className="btn px-5 py-2 rounded-lg text-sm">
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}
