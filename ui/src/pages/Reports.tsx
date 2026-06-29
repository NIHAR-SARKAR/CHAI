import { useEffect, useState } from 'react';
import { FileText, Download, Eye, RefreshCw, ChevronDown, FileCode, Calendar, Clock, BarChart3 } from 'lucide-react';
import { apiClient } from '../lib/api';
import type { Session } from '../types';
import { useToast } from '../components/Toaster';

export default function Reports() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [selected, setSelected] = useState('');
  const [reportContent, setReportContent] = useState('');
  const [generating, setGenerating] = useState(false);
  const [format, setFormat] = useState('markdown');
  const toast = useToast();

  useEffect(() => {
    apiClient.sessions().then(({ sessions: s }) => { setSessions(s); if (s.length) setSelected(s[0].session_id); });
  }, []);

  async function generate() {
    if (!selected) return;
    setGenerating(true);
    try {
      await apiClient.generateReport(selected);
      toast('Report generated', 'success');
      await view();
    } catch (e) {
      toast((e as Error).message, 'error');
    } finally {
      setGenerating(false);
    }
  }

  async function view() {
    if (!selected) return;
    try {
      const { content } = await apiClient.getReport(selected);
      setReportContent(content);
    } catch (e) {
      toast('Report not found. Generate one first.', 'error');
      setReportContent('');
    }
  }

  function download() {
    if (!selected) return;
    apiClient.downloadReport(selected);
    toast('Download started', 'success');
  }

  const selectedSession = sessions.find(s => s.session_id === selected);

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-bold flex items-center gap-2">
          <FileText size={20} className="text-accent" />
          Pentest <span className="text-accent">Reports</span>
        </h2>
      </div>

      {selectedSession && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
          <div className="card relative overflow-hidden">
            <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-accent to-accent2" />
            <div className="text-[11px] text-text3 uppercase tracking-wider flex items-center gap-1"><FileText size={12} /> Session</div>
            <div className="text-xs font-mono mt-1 text-accent truncate">{selectedSession.session_id}</div>
          </div>
          <div className="card relative overflow-hidden">
            <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-accent to-success" />
            <div className="text-[11px] text-text3 uppercase tracking-wider flex items-center gap-1"><Calendar size={12} /> Target</div>
            <div className="text-xs mt-1 text-text truncate">{selectedSession.target}</div>
          </div>
          <div className="card relative overflow-hidden">
            <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-success to-warn" />
            <div className="text-[11px] text-text3 uppercase tracking-wider flex items-center gap-1"><BarChart3 size={12} /> Findings</div>
            <div className="text-xs mt-1 text-warn font-bold">{selectedSession.findings_count || 0}</div>
          </div>
          <div className="card relative overflow-hidden">
            <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-warn to-danger" />
            <div className="text-[11px] text-text3 uppercase tracking-wider flex items-center gap-1"><Clock size={12} /> Status</div>
            <div className="text-xs mt-1 text-success">{selectedSession.status}</div>
          </div>
        </div>
      )}

      <div className="card space-y-4">
        <div className="flex flex-wrap gap-3 items-center">
          <div className="flex items-center gap-2 bg-surface2 border border-border rounded-lg px-3 py-2 min-w-[300px]">
            <FileText size={14} className="text-text3" />
            <select value={selected} onChange={(e) => setSelected(e.target.value)} className="bg-transparent text-sm text-text focus:outline-none flex-1">
              {sessions.map(s => <option key={s.session_id} value={s.session_id}>{s.session_id} — {s.target}</option>)}
            </select>
            <ChevronDown size={14} className="text-text3" />
          </div>
          <select
            value={format}
            onChange={(e) => setFormat(e.target.value)}
            className="bg-surface2 border border-border rounded-lg px-3 py-2 text-sm text-text focus:border-accent focus:outline-none"
          >
            <option value="markdown">Markdown</option>
            <option value="json">JSON</option>
          </select>
          <button onClick={generate} disabled={generating} className="btn-primary text-sm px-4 py-2 rounded-lg flex items-center gap-2 disabled:opacity-50">
            <RefreshCw size={14} className={generating ? 'animate-spin' : ''} /> {generating ? 'Generating...' : 'Generate Report'}
          </button>
          <button onClick={view} className="btn text-sm px-4 py-2 rounded-lg flex items-center gap-2">
            <Eye size={14} /> View
          </button>
          <button onClick={download} className="btn text-sm px-4 py-2 rounded-lg flex items-center gap-2">
            <Download size={14} /> Download
          </button>
        </div>
        {reportContent ? (
          <div className="bg-surface2 border border-border rounded-lg p-4 max-h-[600px] overflow-auto">
            <div className="flex items-center gap-2 mb-3 pb-3 border-b border-border/50">
              <FileCode size={14} className="text-accent" />
              <span className="text-xs font-semibold text-text">Report Preview</span>
              <span className="ml-auto text-[10px] text-text3 px-1.5 py-0.5 rounded bg-surface border border-border">{format.toUpperCase()}</span>
            </div>
            <pre className="text-xs text-text font-mono whitespace-pre-wrap leading-relaxed">{reportContent}</pre>
          </div>
        ) : (
          <div className="py-12 text-center text-text3 flex flex-col items-center gap-2">
            <FileText size={24} className="opacity-30" />
            <span>No report loaded. Select a session and click Generate or View.</span>
          </div>
        )}
      </div>
    </div>
  );
}
