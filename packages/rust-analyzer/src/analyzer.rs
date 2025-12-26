use crate::detector::ExploitDetector;
use crate::models::*;
use crate::simulator::StateSimulator;
use anyhow::{anyhow, Result};
use chrono::Utc;
use log::{debug, info, warn};
use lru::LruCache;
use solana_client::rpc_client::RpcClient;
use solana_sdk::signature::Signature;
use std::num::NonZeroUsize;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub struct ChainAnalyzer {
    rpc_client: Arc<RpcClient>,
    detector: ExploitDetector,
    simulator: StateSimulator,
    cache: Arc<Mutex<LruCache<String, AnalysisResponse>>>,
}

impl ChainAnalyzer {
    pub fn new(rpc_url: &str) -> Self {
        info!("Initializing ChainAnalyzer with RPC: {}", rpc_url);
        
        Self {
            rpc_client: Arc::new(RpcClient::new(rpc_url.to_string())),
            detector: ExploitDetector::new(),
            simulator: StateSimulator::new(),
            cache: Arc::new(Mutex::new(LruCache::new(NonZeroUsize::new(1000).unwrap()))),
        }
    }

    pub async fn analyze_transaction(&self, request: AnalysisRequest) -> Result<AnalysisResponse> {
        let start_time = Instant::now();
        
        // Check cache
        {
            let mut cache = self.cache.lock().unwrap();
            if let Some(cached_result) = cache.get(&request.signature) {
                debug!("Cache hit for signature: {}", request.signature);
                return Ok(cached_result.clone());
            }
        }

        info!("Analyzing transaction: {}", request.signature);

        // Parse signature
        let signature = Signature::from_str(&request.signature)
            .map_err(|e| anyhow!("Invalid signature: {}", e))?;

        // Fetch transaction from chain
        let transaction = self
            .rpc_client
            .get_transaction(&signature, solana_transaction_status::UiTransactionEncoding::Json)
            .map_err(|e| anyhow!("Failed to fetch transaction: {}", e))?;

        // Simulate transaction execution
        let simulation_result = self.simulator.simulate_transaction(&transaction)?;

        // Detect exploits
        let exploits = self.detector.detect_exploits(&transaction, &simulation_result)?;

        // Analyze state changes
        let state_changes = self.analyze_state_changes(&transaction)?;

        // Calculate risk score
        let risk_score = self.calculate_risk_score(&exploits, &state_changes);

        let analysis_duration = start_time.elapsed().as_millis() as u64;

        let response = AnalysisResponse {
            risk_score,
            exploits,
            state_changes,
            simulation_result,
            metadata: AnalysisMetadata {
                timestamp: Utc::now().timestamp(),
                analysis_duration_ms: analysis_duration,
                analyzer_version: env!("CARGO_PKG_VERSION").to_string(),
                network: request.network.unwrap_or_else(|| "mainnet-beta".to_string()),
            },
        };

        // Cache result
        {
            let mut cache = self.cache.lock().unwrap();
            cache.put(request.signature.clone(), response.clone());
        }

        info!(
            "Analysis complete for {} - Risk Score: {:.2}, Duration: {}ms",
            request.signature, risk_score, analysis_duration
        );

        Ok(response)
    }

    pub async fn audit_contract(&self, request: ContractAuditRequest) -> Result<ContractAuditResponse> {
        let start_time = Instant::now();
        
        info!("Auditing contract: {}", request.program_id);

        // Fetch program account
        let program_pubkey = solana_sdk::pubkey::Pubkey::from_str(&request.program_id)
            .map_err(|e| anyhow!("Invalid program ID: {}", e))?;

        let account = self
            .rpc_client
            .get_account(&program_pubkey)
            .map_err(|e| anyhow!("Failed to fetch program account: {}", e))?;

        if !account.executable {
            return Err(anyhow!("Account is not executable"));
        }

        // Analyze program bytecode
        let vulnerabilities = self.detector.analyze_program_bytecode(&account.data)?;

        // Get program transactions for behavioral analysis
        let signatures = self
            .rpc_client
            .get_signatures_for_address(&program_pubkey)
            .unwrap_or_default();

        let mut instruction_count = 0;
        for sig_info in signatures.iter().take(100) {
            if let Ok(sig) = Signature::from_str(&sig_info.signature) {
                if let Ok(tx) = self.rpc_client.get_transaction(
                    &sig,
                    solana_transaction_status::UiTransactionEncoding::Json,
                ) {
                    instruction_count += tx.transaction.transaction.message().instructions().len();
                }
            }
        }

        // Calculate code quality metrics
        let code_quality = self.calculate_code_quality(&account.data);

        // Calculate risk score
        let risk_score = self.calculate_contract_risk_score(&vulnerabilities);

        // Generate recommendations
        let recommendations = self.generate_recommendations(&vulnerabilities);

        let audit_duration = start_time.elapsed().as_millis() as u64;

        let response = ContractAuditResponse {
            program_id: request.program_id.clone(),
            risk_score,
            vulnerabilities,
            code_quality,
            recommendations,
            metadata: AuditMetadata {
                timestamp: Utc::now().timestamp(),
                audit_duration_ms: audit_duration,
                instructions_analyzed: instruction_count,
                depth: format!("{:?}", request.depth.unwrap_or(AuditDepth::Shallow)),
            },
        };

        info!(
            "Audit complete for {} - Risk Score: {:.2}, Duration: {}ms",
            request.program_id, risk_score, audit_duration
        );

        Ok(response)
    }

    fn analyze_state_changes(&self, transaction: &solana_transaction_status::EncodedConfirmedTransactionWithStatusMeta) -> Result<Vec<StateChange>> {
        let mut changes = Vec::new();

        if let Some(meta) = &transaction.transaction.meta {
            // Analyze pre/post balances
            for (idx, (pre, post)) in meta.pre_balances.iter().zip(meta.post_balances.iter()).enumerate() {
                if pre != post {
                    let suspicious = self.is_suspicious_balance_change(*pre, *post);
                    changes.push(StateChange {
                        account: format!("account_{}", idx),
                        field: "lamports".to_string(),
                        before: pre.to_string(),
                        after: post.to_string(),
                        suspicious,
                    });
                }
            }
        }

        Ok(changes)
    }

    fn is_suspicious_balance_change(&self, pre: u64, post: u64) -> bool {
        // Detect suspicious patterns
        if post == 0 && pre > 0 {
            // Account drained
            return true;
        }
        
        if post > pre {
            let increase_ratio = (post - pre) as f64 / pre.max(1) as f64;
            if increase_ratio > 10.0 {
                // Abnormally large increase
                return true;
            }
        }

        false
    }

    fn calculate_risk_score(&self, exploits: &[Exploit], state_changes: &[StateChange]) -> f64 {
        let mut score = 0.0;

        // Score based on exploits
        for exploit in exploits {
            let severity_weight = match exploit.severity {
                Severity::Critical => 40.0,
                Severity::High => 25.0,
                Severity::Medium => 15.0,
                Severity::Low => 5.0,
                Severity::Info => 1.0,
            };
            score += severity_weight * exploit.confidence;
        }

        // Score based on suspicious state changes
        let suspicious_changes = state_changes.iter().filter(|c| c.suspicious).count();
        score += suspicious_changes as f64 * 5.0;

        // Normalize to 0-100
        score.min(100.0)
    }

    fn calculate_contract_risk_score(&self, vulnerabilities: &[Vulnerability]) -> f64 {
        let mut score = 0.0;

        for vuln in vulnerabilities {
            let severity_weight = match vuln.severity {
                Severity::Critical => 35.0,
                Severity::High => 20.0,
                Severity::Medium => 12.0,
                Severity::Low => 5.0,
                Severity::Info => 1.0,
            };
            score += severity_weight * vuln.confidence;
        }

        score.min(100.0)
    }

    fn calculate_code_quality(&self, _bytecode: &[u8]) -> CodeQuality {
        let mut metrics = std::collections::HashMap::new();
        
        // Simplified metrics for demonstration
        metrics.insert("complexity".to_string(), 0.75);
        metrics.insert("maintainability".to_string(), 0.82);
        metrics.insert("security".to_string(), 0.68);

        let score = metrics.values().sum::<f64>() / metrics.len() as f64;

        CodeQuality { score, metrics }
    }

    fn generate_recommendations(&self, vulnerabilities: &[Vulnerability]) -> Vec<String> {
        let mut recommendations = Vec::new();

        for vuln in vulnerabilities {
            match vuln.vulnerability_type.as_str() {
                "missing_owner_check" => {
                    recommendations.push(
                        "Add owner validation checks before performing privileged operations".to_string()
                    );
                }
                "missing_signer_check" => {
                    recommendations.push(
                        "Ensure all critical accounts are marked as signers and validated".to_string()
                    );
                }
                "integer_overflow" => {
                    recommendations.push(
                        "Use checked arithmetic operations to prevent overflow vulnerabilities".to_string()
                    );
                }
                _ => {}
            }
        }

        recommendations.dedup();
        recommendations
    }
}

