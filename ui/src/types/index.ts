export interface Session {
  session_id: string;
  target: string;
  test_type: string;
  status: 'initialized' | 'running' | 'complete' | 'stopped' | 'error';
  scope: string[];
  findings_count: number;
  created_at: string;
  updated_at: string;
  metadata?: Record<string, unknown>;
}

export interface Finding {
  id?: string;
  session_id: string;
  attack_type: string;
  confidence: number;
  endpoint: string;
  parameter?: string;
  evidence: string;
  status: string;
  cvss_score?: number;
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  remediation?: string;
  metadata?: Record<string, unknown>;
  created_at?: string;
}

export interface AIDecision {
  id?: string;
  session_id: string;
  decision_type: 'plan' | 'evaluate' | 'summarize';
  provider: string;
  decision_json: string;
  tokens_used: number;
  input_tokens?: number;
  output_tokens?: number;
  latency_ms: number;
  created_at: string;
}

export interface TokenUsage {
  input_tokens: number;
  output_tokens: number;
  total_tokens: number;
}

export interface SessionDetail {
  session: Session;
  findings: Finding[];
  ai_decisions: AIDecision[];
  token_usage: TokenUsage;
}

export interface Plugin {
  name: string;
  display_name: string;
  version: string;
  description: string;
  tier: string;
  tags: string[];
  enabled: boolean;
}

export interface ServerConfig {
  server: { name: string; version: string; transport: string };
  llm: { active_provider: string; fallback_provider: string };
  ai_planner: { max_phases: number; stop_on_critical: boolean };
  wsl: { enabled: boolean; distro_name: string };
}

export interface ScanProgress {
  type: 'progress' | 'complete' | 'error' | 'status';
  session?: Session;
  findings_count: number;
  ai_decisions_count?: number;
  result?: {
    phases_completed: number;
    total_findings: number;
    critical_count: number;
    high_count: number;
    report_path?: string;
    status: string;
  };
  message?: string;
}

export interface LogEntry {
  timestamp: string;
  level: string;
  message: string;
  source: string;
}
