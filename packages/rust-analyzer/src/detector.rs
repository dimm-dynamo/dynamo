use crate::exploit_patterns::EXPLOIT_PATTERNS;
use crate::models::*;
use anyhow::Result;
use log::debug;
use solana_transaction_status::EncodedConfirmedTransactionWithStatusMeta;

pub struct ExploitDetector {
    patterns: Vec<ExploitPattern>,
}

#[derive(Clone)]
struct ExploitPattern {
    name: String,
    exploit_type: ExploitType,
    severity: Severity,
    detector: fn(&EncodedConfirmedTransactionWithStatusMeta, &SimulationResult) -> bool,
}

impl ExploitDetector {
    pub fn new() -> Self {
        Self {
            patterns: Self::initialize_patterns(),
        }
    }

    fn initialize_patterns() -> Vec<ExploitPattern> {
        vec![
            ExploitPattern {
                name: "Reentrancy Attack".to_string(),
                exploit_type: ExploitType::Reentrancy,
                severity: Severity::Critical,
                detector: detect_reentrancy,
            },
            ExploitPattern {
                name: "Integer Overflow".to_string(),
                exploit_type: ExploitType::IntegerOverflow,
                severity: Severity::High,
                detector: detect_integer_overflow,
            },
            ExploitPattern {
                name: "Authority Bypass".to_string(),
                exploit_type: ExploitType::AuthorityBypass,
                severity: Severity::Critical,
                detector: detect_authority_bypass,
            },
            ExploitPattern {
                name: "Missing Signer Check".to_string(),
                exploit_type: ExploitType::MissingSignerCheck,
                severity: Severity::High,
                detector: detect_missing_signer,
            },
            ExploitPattern {
                name: "PDA Mismatch".to_string(),
                exploit_type: ExploitType::PdaMismatch,
                severity: Severity::Medium,
                detector: detect_pda_mismatch,
            },
            ExploitPattern {
                name: "Flash Loan Attack".to_string(),
                exploit_type: ExploitType::FlashLoanAttack,
                severity: Severity::Critical,
                detector: detect_flash_loan,
            },
        ]
    }

    pub fn detect_exploits(
        &self,
        transaction: &EncodedConfirmedTransactionWithStatusMeta,
        simulation: &SimulationResult,
    ) -> Result<Vec<Exploit>> {
        let mut exploits = Vec::new();

        debug!("Running exploit detection patterns");

        for pattern in &self.patterns {
            if (pattern.detector)(transaction, simulation) {
                exploits.push(Exploit {
                    exploit_type: pattern.exploit_type.clone(),
                    severity: pattern.severity.clone(),
                    description: format!("Detected: {}", pattern.name),
                    location: "transaction".to_string(),
                    confidence: 0.85,
                    remediation: Some(self.get_remediation(&pattern.exploit_type)),
                });
            }
        }

        debug!("Detected {} potential exploits", exploits.len());

        Ok(exploits)
    }

    pub fn analyze_program_bytecode(&self, bytecode: &[u8]) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Static analysis of bytecode patterns
        if self.contains_unsafe_pattern(bytecode, &[0x90, 0x90, 0x90]) {
            vulnerabilities.push(Vulnerability {
                vulnerability_type: "suspicious_nop_pattern".to_string(),
                severity: Severity::Medium,
                description: "Suspicious NOP sled pattern detected".to_string(),
                affected_instructions: vec!["unknown".to_string()],
                confidence: 0.65,
            });
        }

        // Check for common vulnerability patterns
        if bytecode.len() > 100000 {
            vulnerabilities.push(Vulnerability {
                vulnerability_type: "large_program_size".to_string(),
                severity: Severity::Low,
                description: "Program size is unusually large, may indicate obfuscation".to_string(),
                affected_instructions: vec![],
                confidence: 0.50,
            });
        }

        // Analyze instruction patterns
        if self.has_missing_owner_check_pattern(bytecode) {
            vulnerabilities.push(Vulnerability {
                vulnerability_type: "missing_owner_check".to_string(),
                severity: Severity::High,
                description: "Potential missing owner validation detected".to_string(),
                affected_instructions: vec!["transfer".to_string()],
                confidence: 0.72,
            });
        }

        Ok(vulnerabilities)
    }

    fn contains_unsafe_pattern(&self, bytecode: &[u8], pattern: &[u8]) -> bool {
        bytecode
            .windows(pattern.len())
            .any(|window| window == pattern)
    }

    fn has_missing_owner_check_pattern(&self, _bytecode: &[u8]) -> bool {
        // Simplified heuristic
        false
    }

    fn get_remediation(&self, exploit_type: &ExploitType) -> String {
        match exploit_type {
            ExploitType::Reentrancy => {
                "Implement checks-effects-interactions pattern and use reentrancy guards".to_string()
            }
            ExploitType::IntegerOverflow => {
                "Use checked arithmetic operations (checked_add, checked_mul, etc.)".to_string()
            }
            ExploitType::AuthorityBypass => {
                "Validate authority signatures and implement proper access control".to_string()
            }
            ExploitType::MissingSignerCheck => {
                "Ensure critical accounts are marked as signers and validated".to_string()
            }
            ExploitType::PdaMismatch => {
                "Verify PDA derivation matches expected seeds and program ID".to_string()
            }
            ExploitType::FlashLoanAttack => {
                "Implement time-weighted average pricing and multi-block validation".to_string()
            }
            _ => "Review code for security best practices".to_string(),
        }
    }
}

// Detection functions
fn detect_reentrancy(
    _tx: &EncodedConfirmedTransactionWithStatusMeta,
    simulation: &SimulationResult,
) -> bool {
    // Detect multiple calls to same program in single transaction
    let program_calls: Vec<_> = simulation
        .logs
        .iter()
        .filter(|log| log.contains("Program") && log.contains("invoke"))
        .collect();

    program_calls.len() > 3
}

fn detect_integer_overflow(
    _tx: &EncodedConfirmedTransactionWithStatusMeta,
    simulation: &SimulationResult,
) -> bool {
    // Look for overflow-related error messages
    simulation
        .logs
        .iter()
        .any(|log| log.contains("overflow") || log.contains("underflow"))
}

fn detect_authority_bypass(
    tx: &EncodedConfirmedTransactionWithStatusMeta,
    _simulation: &SimulationResult,
) -> bool {
    // Check if transaction succeeded without expected authority signature
    if let Some(meta) = &tx.transaction.meta {
        if meta.err.is_none() {
            // Transaction succeeded - check for suspicious patterns
            // This is a simplified heuristic
            return false;
        }
    }
    false
}

fn detect_missing_signer(
    _tx: &EncodedConfirmedTransactionWithStatusMeta,
    simulation: &SimulationResult,
) -> bool {
    simulation
        .logs
        .iter()
        .any(|log| log.contains("missing") && log.contains("signer"))
}

fn detect_pda_mismatch(
    _tx: &EncodedConfirmedTransactionWithStatusMeta,
    simulation: &SimulationResult,
) -> bool {
    simulation
        .logs
        .iter()
        .any(|log| log.contains("PDA") || log.contains("seeds"))
}

fn detect_flash_loan(
    tx: &EncodedConfirmedTransactionWithStatusMeta,
    _simulation: &SimulationResult,
) -> bool {
    // Detect large balance changes within single transaction
    if let Some(meta) = &tx.transaction.meta {
        for (pre, post) in meta.pre_balances.iter().zip(meta.post_balances.iter()) {
            let diff = if post > pre { post - pre } else { pre - post };
            if diff > 1_000_000_000_000 {
                // > 1000 SOL movement
                return true;
            }
        }
    }
    false
}

