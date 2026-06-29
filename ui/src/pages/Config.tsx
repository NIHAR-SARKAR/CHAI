import { useEffect, useState } from 'react';
import {
  Server, Brain, Shield, Terminal, Wrench, Plug,
  Settings, Cpu, HardDrive, Network, Globe,
  FileCode, Zap, CheckCircle, XCircle
} from 'lucide-react';
import { apiClient } from '../lib/api';
import type { Plugin, ServerConfig } from '../types';
import { useToast } from '../components/Toaster';

export default function Config() {
  const [config, setConfig] = useState<ServerConfig | null>(null);
  const [plugins, setPlugins] = useState<Plugin[]>([]);
  const [tools, setTools] = useState<{ name: string; type: string; class: string }[]>([]);
  const toast = useToast();

  useEffect(() => {
    load();
  }, []);

  async function load() {
    try {
      const cfg = await apiClient.getConfig();
      setConfig(cfg);
    } catch (e) {
      toast((e as Error).message, 'error');
    }
    try {
      const { plugins: p } = await apiClient.listPlugins();
      setPlugins(p);
    } catch {}
    try {
      const { tools: t } = await apiClient.listTools();
      setTools(t);
    } catch {}
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-bold flex items-center gap-2">
          <Settings size={20} className="text-accent" />
          Server <span className="text-accent">Configuration</span>
        </h2>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
        <div className="card space-y-4">
          <h3 className="text-sm font-semibold flex items-center gap-2"><Server size={14} className="text-accent" /> Server</h3>
          {config && (
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div className="flex items-start gap-2">
                <Globe size={12} className="text-text3 mt-0.5 shrink-0" />
                <div>
                  <span className="text-text3 text-xs block">Name</span>
                  <span className="font-medium">{config.server.name}</span>
                </div>
              </div>
              <div className="flex items-start gap-2">
                <FileCode size={12} className="text-text3 mt-0.5 shrink-0" />
                <div>
                  <span className="text-text3 text-xs block">Version</span>
                  <span className="font-medium">{config.server.version}</span>
                </div>
              </div>
              <div className="flex items-start gap-2">
                <Network size={12} className="text-text3 mt-0.5 shrink-0" />
                <div>
                  <span className="text-text3 text-xs block">Transport</span>
                  <span className="font-medium">{config.server.transport}</span>
                </div>
              </div>
            </div>
          )}
        </div>
        <div className="card space-y-4">
          <h3 className="text-sm font-semibold flex items-center gap-2"><Brain size={14} className="text-accent" /> LLM</h3>
          {config && (
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div className="flex items-start gap-2">
                <Cpu size={12} className="text-text3 mt-0.5 shrink-0" />
                <div>
                  <span className="text-text3 text-xs block">Active Provider</span>
                  <span className="font-medium">{config.llm.active_provider}</span>
                </div>
              </div>
              <div className="flex items-start gap-2">
                <Zap size={12} className="text-text3 mt-0.5 shrink-0" />
                <div>
                  <span className="text-text3 text-xs block">Fallback</span>
                  <span className="font-medium">{config.llm.fallback_provider || 'none'}</span>
                </div>
              </div>
            </div>
          )}
        </div>
        <div className="card space-y-4">
          <h3 className="text-sm font-semibold flex items-center gap-2"><Shield size={14} className="text-accent" /> AI Planner</h3>
          {config && (
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div className="flex items-start gap-2">
                <HardDrive size={12} className="text-text3 mt-0.5 shrink-0" />
                <div>
                  <span className="text-text3 text-xs block">Max Phases</span>
                  <span className="font-medium">{config.ai_planner.max_phases}</span>
                </div>
              </div>
              <div className="flex items-start gap-2">
                <CheckCircle size={12} className="text-text3 mt-0.5 shrink-0" />
                <div>
                  <span className="text-text3 text-xs block">Stop on Critical</span>
                  <span className="font-medium">{config.ai_planner.stop_on_critical ? 'Yes' : 'No'}</span>
                </div>
              </div>
            </div>
          )}
        </div>
        <div className="card space-y-4">
          <h3 className="text-sm font-semibold flex items-center gap-2"><Terminal size={14} className="text-accent" /> WSL</h3>
          {config && (
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div className="flex items-start gap-2">
                {config.wsl.enabled ? <CheckCircle size={12} className="text-success mt-0.5 shrink-0" /> : <XCircle size={12} className="text-danger mt-0.5 shrink-0" />}
                <div>
                  <span className="text-text3 text-xs block">Enabled</span>
                  <span className="font-medium">{config.wsl.enabled ? 'Yes' : 'No'}</span>
                </div>
              </div>
              <div className="flex items-start gap-2">
                <Globe size={12} className="text-text3 mt-0.5 shrink-0" />
                <div>
                  <span className="text-text3 text-xs block">Distro</span>
                  <span className="font-medium">{config.wsl.distro_name || 'default'}</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="card mb-4">
        <h3 className="text-sm font-semibold mb-4 flex items-center gap-2"><Plug size={14} className="text-accent" /> Loaded Plugins ({plugins.length})</h3>
        {plugins.length === 0 ? (
          <div className="text-text3 text-sm flex items-center gap-2"><Plug size={16} className="opacity-30" /> No plugins loaded</div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {plugins.map((p) => (
              <div key={p.name} className="bg-surface2 rounded-lg p-3 border border-border/50 hover:border-accent/30 transition-colors">
                <div className="flex items-center gap-2 mb-1">
                  <Plug size={14} className="text-accent" />
                  <div className="font-semibold text-sm">{p.display_name || p.name}</div>
                </div>
                <div className="text-text3 text-xs mt-1">Tier: {p.tier} · v{p.version}</div>
                <div className="text-text2 text-xs mt-1 line-clamp-2">{p.description}</div>
                <div className="flex flex-wrap gap-1 mt-2">
                  {p.tags?.map(t => <span key={t} className="text-[10px] bg-accent/10 text-accent px-1.5 py-0.5 rounded">{t}</span>)}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="card">
        <h3 className="text-sm font-semibold mb-4 flex items-center gap-2"><Wrench size={14} className="text-accent" /> Built-in Tools ({tools.length})</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {tools.map((t) => (
            <div key={t.name} className="bg-surface2 rounded-lg p-3 border border-border/50 text-xs flex items-start gap-2 hover:border-accent/30 transition-colors">
              <Wrench size={14} className="text-text3 shrink-0 mt-0.5" />
              <div>
                <div className="font-semibold">{t.name}</div>
                <div className="text-text3 mt-1">{t.class}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
