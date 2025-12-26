use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisRequest {
    pub signature: String,
    pub network: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractAuditRequest {
    pub program_id: String,
    pub network: Option<String>,
    pub depth: Option<AuditDepth>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditDepth {
    Shallow,
    Deep,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResponse {
    pub risk_score: f64,
    pub exploits: Vec<Exploit>,
    pub state_changes: Vec<StateChange>,
    pub simulation_result: SimulationResult,
    pub metadata: AnalysisMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Exploit {
    pub exploit_type: ExploitType,
    pub severity: Severity,
    pub description: String,
    pub location: String,
    pub confidence: f64,
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExploitType {
    Reentrancy,
    IntegerOverflow,
    IntegerUnderflow,
    AuthorityBypass,
    UnauthorizedAccess,
    AccountConfusion,
    SignerBypass,
    PdaMismatch,
    MissingOwnerCheck,
    MissingSignerCheck,
    ArbitraryCodeExecution,
    FlashLoanAttack,
    PriceManipulation,
    FrontRunning,
    Sandwich,
    TypeConfusion,
    InsufficientRentExemption,
    OracleManipulation,
    DosAttack,
    ArbitraryCpi,
    BumpSeedCanonical,
    AccountDataMismatch,
    MissingRentCheck,
    UncheckedAccountOwnership,
    TokenAccountValidation,
    MintAuthorityBypass,
    FreezeAuthorityBypass,
    DuplicateAccountMutable,
    AccountReinitialization,
    ClosedAccountRevival,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChange {
    pub account: String,
    pub field: String,
    pub before: String,
    pub after: String,
    pub suspicious: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    pub success: bool,
    pub error: Option<String>,
    pub compute_units_consumed: u64,
    pub logs: Vec<String>,
    pub accounts_accessed: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisMetadata {
    pub timestamp: i64,
    pub analysis_duration_ms: u64,
    pub analyzer_version: String,
    pub network: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractAuditResponse {
    pub program_id: String,
    pub risk_score: f64,
    pub vulnerabilities: Vec<Vulnerability>,
    pub code_quality: CodeQuality,
    pub recommendations: Vec<String>,
    pub metadata: AuditMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub vulnerability_type: String,
    pub severity: Severity,
    pub description: String,
    pub affected_instructions: Vec<String>,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeQuality {
    pub score: f64,
    pub metrics: HashMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditMetadata {
    pub timestamp: i64,
    pub audit_duration_ms: u64,
    pub instructions_analyzed: usize,
    pub depth: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
}

