export interface ClientConfig {
  endpoint: string;
  apiKey?: string;
  timeout?: number;
}

export type Network = 'mainnet-beta' | 'devnet' | 'testnet';
export type AuditDepth = 'shallow' | 'deep';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface TransactionAnalysisRequest {
  signature: string;
  network?: Network;
}

export interface AddressAnalysisRequest {
  address: string;
  network?: Network;
  depth?: number;
}

export interface ContractAuditRequest {
  programId: string;
  network?: Network;
  depth?: AuditDepth;
}

export interface MonitorAddressRequest {
  address: string;
  network?: Network;
  webhookUrl?: string;
  callback?: (alert: SecurityAlert) => void;
}

export interface Exploit {
  exploit_type: string;
  severity: Severity;
  description: string;
  location: string;
  confidence: number;
  remediation?: string;
}

export interface StateChange {
  account: string;
  field: string;
  before: string;
  after: string;
  suspicious: boolean;
}

export interface SimulationResult {
  success: boolean;
  error?: string;
  compute_units_consumed: number;
  logs: string[];
  accounts_accessed: string[];
}

export interface AIAnalysis {
  confidence: number;
  patterns: string[];
  recommendations: string[];
  clusterScore: number;
}

export interface TransactionAnalysisResponse {
  risk_score: number;
  exploits: Exploit[];
  state_changes: StateChange[];
  simulation_result: SimulationResult;
  aiAnalysis: AIAnalysis;
  metadata: {
    timestamp: number;
    analysis_duration_ms: number;
    analyzer_version: string;
    network: string;
  };
}

export interface AddressAnalysisResponse {
  address: string;
  network: string;
  transactionCount: number;
  aggregatedRiskScore: number;
  analyses: TransactionAnalysisResponse[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

export interface Vulnerability {
  vulnerability_type: string;
  severity: Severity;
  description: string;
  affected_instructions: string[];
  confidence: number;
}

export interface CodeQuality {
  score: number;
  metrics: Record<string, number>;
}

export interface AIAuditEnhancement {
  additionalVulnerabilities: Vulnerability[];
  patternMatches: string[];
  riskAssessment: string;
  recommendations: string[];
}

export interface ContractAuditResponse {
  program_id: string;
  risk_score: number;
  vulnerabilities: Vulnerability[];
  code_quality: CodeQuality;
  recommendations: string[];
  aiEnhancement: AIAuditEnhancement;
  metadata: {
    timestamp: number;
    audit_duration_ms: number;
    instructions_analyzed: number;
    depth: string;
  };
}

export interface MonitorAddressResponse {
  monitorId: string;
  address: string;
  network: string;
  status: 'active' | 'inactive';
  startedAt: string;
}

export interface MonitorStatus {
  monitorId: string;
  address: string;
  network: string;
  status: 'active' | 'inactive';
  lastCheck: string | null;
}

export interface SecurityAlert {
  monitorId: string;
  address: string;
  timestamp: string;
  riskScore: number;
  exploits: Exploit[];
  message: string;
}

