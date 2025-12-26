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

export type ExploitType = 
  | 'reentrancy'
  | 'integer_overflow'
  | 'integer_underflow'
  | 'authority_bypass'
  | 'unauthorized_access'
  | 'account_confusion'
  | 'signer_bypass'
  | 'pda_mismatch'
  | 'missing_owner_check'
  | 'missing_signer_check'
  | 'arbitrary_code_execution'
  | 'flash_loan_attack'
  | 'price_manipulation'
  | 'front_running'
  | 'sandwich'
  | 'type_confusion'
  | 'insufficient_rent_exemption'
  | 'oracle_manipulation'
  | 'dos_attack'
  | 'arbitrary_cpi'
  | 'bump_seed_canonical'
  | 'account_data_mismatch'
  | 'missing_rent_check'
  | 'unchecked_account_ownership'
  | 'token_account_validation'
  | 'mint_authority_bypass'
  | 'freeze_authority_bypass'
  | 'duplicate_account_mutable'
  | 'account_reinitialization'
  | 'closed_account_revival'
  | 'unknown';

export interface Exploit {
  exploit_type: ExploitType;
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

