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
            ExploitPattern {
                name: "Account Confusion".to_string(),
                exploit_type: ExploitType::AccountConfusion,
                severity: Severity::Critical,
                detector: detect_account_confusion,
            },
            ExploitPattern {
                name: "Signer Bypass".to_string(),
                exploit_type: ExploitType::SignerBypass,
                severity: Severity::Critical,
                detector: detect_signer_bypass,
            },
            ExploitPattern {
                name: "Type Confusion".to_string(),
                exploit_type: ExploitType::TypeConfusion,
                severity: Severity::High,
                detector: detect_type_confusion,
            },
            ExploitPattern {
                name: "Insufficient Rent Exemption".to_string(),
                exploit_type: ExploitType::InsufficientRentExemption,
                severity: Severity::Medium,
                detector: detect_rent_exemption,
            },
            ExploitPattern {
                name: "Oracle Manipulation".to_string(),
                exploit_type: ExploitType::OracleManipulation,
                severity: Severity::Critical,
                detector: detect_oracle_manipulation,
            },
            ExploitPattern {
                name: "DoS Attack".to_string(),
                exploit_type: ExploitType::DosAttack,
                severity: Severity::High,
                detector: detect_dos_attack,
            },
            ExploitPattern {
                name: "Arbitrary CPI".to_string(),
                exploit_type: ExploitType::ArbitraryCpi,
                severity: Severity::Critical,
                detector: detect_arbitrary_cpi,
            },
            ExploitPattern {
                name: "Non-canonical Bump Seed".to_string(),
                exploit_type: ExploitType::BumpSeedCanonical,
                severity: Severity::Medium,
                detector: detect_bump_seed,
            },
            ExploitPattern {
                name: "Account Data Mismatch".to_string(),
                exploit_type: ExploitType::AccountDataMismatch,
                severity: Severity::High,
                detector: detect_account_data_mismatch,
            },
            ExploitPattern {
                name: "Unchecked Account Ownership".to_string(),
                exploit_type: ExploitType::UncheckedAccountOwnership,
                severity: Severity::Critical,
                detector: detect_unchecked_ownership,
            },
            ExploitPattern {
                name: "Token Account Validation".to_string(),
                exploit_type: ExploitType::TokenAccountValidation,
                severity: Severity::High,
                detector: detect_token_validation,
            },
            ExploitPattern {
                name: "Duplicate Mutable Accounts".to_string(),
                exploit_type: ExploitType::DuplicateAccountMutable,
                severity: Severity::High,
                detector: detect_duplicate_mutable,
            },
            ExploitPattern {
                name: "Account Reinitialization".to_string(),
                exploit_type: ExploitType::AccountReinitialization,
                severity: Severity::Critical,
                detector: detect_account_reinitialization,
            },
            ExploitPattern {
                name: "Closed Account Revival".to_string(),
                exploit_type: ExploitType::ClosedAccountRevival,
                severity: Severity::Critical,
                detector: detect_closed_account_revival,
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

        // Check for program size
        if bytecode.len() > 100000 {
            vulnerabilities.push(Vulnerability {
                vulnerability_type: "large_program_size".to_string(),
                severity: Severity::Low,
                description: "Program size is unusually large, may indicate obfuscation".to_string(),
                affected_instructions: vec![],
                confidence: 0.50,
            });
        }

        // Check for missing owner validation
        if self.has_missing_owner_check_pattern(bytecode) {
            vulnerabilities.push(Vulnerability {
                vulnerability_type: "missing_owner_check".to_string(),
                severity: Severity::High,
                description: "Potential missing owner validation detected".to_string(),
                affected_instructions: vec!["transfer".to_string()],
                confidence: 0.72,
            });
        }

        // Check for unchecked arithmetic
        if self.has_unchecked_math_pattern(bytecode) {
            vulnerabilities.push(Vulnerability {
                vulnerability_type: "unchecked_arithmetic".to_string(),
                severity: Severity::High,
                description: "Unchecked arithmetic operations detected, may lead to overflow".to_string(),
                affected_instructions: vec!["math_ops".to_string()],
                confidence: 0.68,
            });
        }

        // Check for missing discriminator
        if !self.has_discriminator_checks(bytecode) {
            vulnerabilities.push(Vulnerability {
                vulnerability_type: "missing_discriminator".to_string(),
                severity: Severity::Medium,
                description: "Account type discriminator not found, may lead to type confusion".to_string(),
                affected_instructions: vec!["deserialization".to_string()],
                confidence: 0.60,
            });
        }

        // Check for unsafe deserialization
        if self.has_unsafe_deserialize_pattern(bytecode) {
            vulnerabilities.push(Vulnerability {
                vulnerability_type: "unsafe_deserialization".to_string(),
                severity: Severity::High,
                description: "Unsafe deserialization pattern detected".to_string(),
                affected_instructions: vec!["deserialize".to_string()],
                confidence: 0.70,
            });
        }

        // Check for missing rent checks
        if self.has_missing_rent_check(bytecode) {
            vulnerabilities.push(Vulnerability {
                vulnerability_type: "missing_rent_check".to_string(),
                severity: Severity::Medium,
                description: "Account creation without rent exemption verification".to_string(),
                affected_instructions: vec!["create_account".to_string()],
                confidence: 0.55,
            });
        }

        // Check for unchecked CPI
        if self.has_unchecked_cpi_pattern(bytecode) {
            vulnerabilities.push(Vulnerability {
                vulnerability_type: "unchecked_cpi".to_string(),
                severity: Severity::Critical,
                description: "Cross-program invocation without program ID validation".to_string(),
                affected_instructions: vec!["invoke".to_string()],
                confidence: 0.75,
            });
        }

        // Check for missing signer checks
        if self.has_missing_signer_validation(bytecode) {
            vulnerabilities.push(Vulnerability {
                vulnerability_type: "missing_signer_validation".to_string(),
                severity: Severity::Critical,
                description: "Critical operations without signer validation".to_string(),
                affected_instructions: vec!["privileged_ops".to_string()],
                confidence: 0.78,
            });
        }

        // Check for account close vulnerabilities
        if self.has_unsafe_close_pattern(bytecode) {
            vulnerabilities.push(Vulnerability {
                vulnerability_type: "unsafe_account_close".to_string(),
                severity: Severity::High,
                description: "Account closure without proper cleanup or validation".to_string(),
                affected_instructions: vec!["close".to_string()],
                confidence: 0.65,
            });
        }

        // Check for bump seed issues
        if self.has_bump_seed_issues(bytecode) {
            vulnerabilities.push(Vulnerability {
                vulnerability_type: "bump_seed_not_canonical".to_string(),
                severity: Severity::Medium,
                description: "PDA bump seed may not be canonical".to_string(),
                affected_instructions: vec!["create_pda".to_string()],
                confidence: 0.58,
            });
        }

        Ok(vulnerabilities)
    }

    fn contains_unsafe_pattern(&self, bytecode: &[u8], pattern: &[u8]) -> bool {
        bytecode
            .windows(pattern.len())
            .any(|window| window == pattern)
    }

    fn has_missing_owner_check_pattern(&self, bytecode: &[u8]) -> bool {
        // Check for transfer operations without owner checks
        // This is a simplified heuristic looking for specific byte patterns
        let transfer_pattern = b"transfer";
        let owner_check_pattern = b"owner";
        
        let has_transfer = bytecode.windows(transfer_pattern.len())
            .any(|w| w == transfer_pattern);
        let has_owner_check = bytecode.windows(owner_check_pattern.len())
            .any(|w| w == owner_check_pattern);
        
        has_transfer && !has_owner_check
    }

    fn has_unchecked_math_pattern(&self, bytecode: &[u8]) -> bool {
        // Look for arithmetic operations without checked_ prefix
        let unchecked_patterns = [b"add", b"sub", b"mul", b"div"];
        let checked_pattern = b"checked_";
        
        for pattern in &unchecked_patterns {
            if bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                if !bytecode.windows(checked_pattern.len()).any(|w| w == checked_pattern) {
                    return true;
                }
            }
        }
        false
    }

    fn has_discriminator_checks(&self, bytecode: &[u8]) -> bool {
        let discriminator_patterns = [b"discriminator", b"account_type", b"tag"];
        
        discriminator_patterns.iter().any(|pattern| {
            bytecode.windows(pattern.len()).any(|w| w == *pattern)
        })
    }

    fn has_unsafe_deserialize_pattern(&self, bytecode: &[u8]) -> bool {
        let deserialize_pattern = b"deserialize";
        let safe_patterns = [b"try_", b"checked_", b"safe_"];
        
        let has_deserialize = bytecode.windows(deserialize_pattern.len())
            .any(|w| w == deserialize_pattern);
        
        let has_safe_wrapper = safe_patterns.iter().any(|pattern| {
            bytecode.windows(pattern.len()).any(|w| w == *pattern)
        });
        
        has_deserialize && !has_safe_wrapper
    }

    fn has_missing_rent_check(&self, bytecode: &[u8]) -> bool {
        let create_account_pattern = b"create_account";
        let rent_check_patterns = [b"rent", b"exemption", b"minimum_balance"];
        
        let has_create = bytecode.windows(create_account_pattern.len())
            .any(|w| w == create_account_pattern);
        
        let has_rent_check = rent_check_patterns.iter().any(|pattern| {
            bytecode.windows(pattern.len()).any(|w| w == *pattern)
        });
        
        has_create && !has_rent_check
    }

    fn has_unchecked_cpi_pattern(&self, bytecode: &[u8]) -> bool {
        let invoke_patterns = [b"invoke", b"invoke_signed"];
        let program_check_patterns = [b"program_id", b"key", b"verify"];
        
        let has_invoke = invoke_patterns.iter().any(|pattern| {
            bytecode.windows(pattern.len()).any(|w| w == *pattern)
        });
        
        let has_check = program_check_patterns.iter().any(|pattern| {
            bytecode.windows(pattern.len()).any(|w| w == *pattern)
        });
        
        has_invoke && !has_check
    }

    fn has_missing_signer_validation(&self, bytecode: &[u8]) -> bool {
        let privileged_ops = [b"transfer", b"mint", b"burn", b"close"];
        let signer_check = b"is_signer";
        
        let has_privileged = privileged_ops.iter().any(|pattern| {
            bytecode.windows(pattern.len()).any(|w| w == *pattern)
        });
        
        let has_signer_check = bytecode.windows(signer_check.len())
            .any(|w| w == signer_check);
        
        has_privileged && !has_signer_check
    }

    fn has_unsafe_close_pattern(&self, bytecode: &[u8]) -> bool {
        let close_pattern = b"close";
        let safety_patterns = [b"lamports", b"zero", b"clear"];
        
        let has_close = bytecode.windows(close_pattern.len())
            .any(|w| w == close_pattern);
        
        let has_safety = safety_patterns.iter().any(|pattern| {
            bytecode.windows(pattern.len()).any(|w| w == *pattern)
        });
        
        has_close && !has_safety
    }

    fn has_bump_seed_issues(&self, bytecode: &[u8]) -> bool {
        let pda_patterns = [b"create_program_address", b"find_program_address"];
        let canonical_check = b"canonical";
        
        let has_pda_creation = pda_patterns.iter().any(|pattern| {
            bytecode.windows(pattern.len()).any(|w| w == *pattern)
        });
        
        let has_canonical_check = bytecode.windows(canonical_check.len())
            .any(|w| w == canonical_check);
        
        has_pda_creation && !has_canonical_check
    }

    fn get_remediation(&self, exploit_type: &ExploitType) -> String {
        match exploit_type {
            ExploitType::Reentrancy => {
                "Implement checks-effects-interactions pattern and use reentrancy guards".to_string()
            }
            ExploitType::IntegerOverflow | ExploitType::IntegerUnderflow => {
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
            ExploitType::AccountConfusion => {
                "Implement strict account type checking and validation before operations".to_string()
            }
            ExploitType::SignerBypass => {
                "Verify signer privileges and implement proper authorization checks".to_string()
            }
            ExploitType::TypeConfusion => {
                "Add discriminator fields and validate account types before deserialization".to_string()
            }
            ExploitType::InsufficientRentExemption => {
                "Verify account has sufficient lamports for rent exemption before operations".to_string()
            }
            ExploitType::OracleManipulation => {
                "Validate oracle data freshness and use multiple oracle sources".to_string()
            }
            ExploitType::DosAttack => {
                "Implement rate limiting, account limits, and proper resource management".to_string()
            }
            ExploitType::ArbitraryCpi => {
                "Whitelist allowed programs for CPI and validate program IDs".to_string()
            }
            ExploitType::BumpSeedCanonical => {
                "Use find_program_address and verify bump seed is canonical".to_string()
            }
            ExploitType::AccountDataMismatch => {
                "Validate account data structure matches expected format before parsing".to_string()
            }
            ExploitType::UncheckedAccountOwnership => {
                "Verify account owner matches expected program ID before operations".to_string()
            }
            ExploitType::TokenAccountValidation => {
                "Validate token account owner, mint, and associated token account derivation".to_string()
            }
            ExploitType::MintAuthorityBypass | ExploitType::FreezeAuthorityBypass => {
                "Verify mint/freeze authority before allowing privileged token operations".to_string()
            }
            ExploitType::DuplicateAccountMutable => {
                "Check for duplicate mutable accounts in instruction account list".to_string()
            }
            ExploitType::AccountReinitialization => {
                "Check is_initialized flag before initialization and set flag after".to_string()
            }
            ExploitType::ClosedAccountRevival => {
                "Zero out account data on close and check discriminator on access".to_string()
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

fn detect_account_confusion(
    _tx: &EncodedConfirmedTransactionWithStatusMeta,
    simulation: &SimulationResult,
) -> bool {
    simulation
        .logs
        .iter()
        .any(|log| log.contains("account") && (log.contains("mismatch") || log.contains("confusion")))
}

fn detect_signer_bypass(
    _tx: &EncodedConfirmedTransactionWithStatusMeta,
    simulation: &SimulationResult,
) -> bool {
    simulation
        .logs
        .iter()
        .any(|log| log.contains("unauthorized") || (log.contains("signer") && log.contains("required")))
}

fn detect_type_confusion(
    _tx: &EncodedConfirmedTransactionWithStatusMeta,
    simulation: &SimulationResult,
) -> bool {
    simulation
        .logs
        .iter()
        .any(|log| log.contains("discriminator") || log.contains("invalid account type"))
}

fn detect_rent_exemption(
    tx: &EncodedConfirmedTransactionWithStatusMeta,
    _simulation: &SimulationResult,
) -> bool {
    if let Some(meta) = &tx.transaction.meta {
        // Check for accounts with insufficient rent
        for balance in &meta.post_balances {
            if *balance > 0 && *balance < 890880 {
                // Minimum rent exemption for small account
                return true;
            }
        }
    }
    false
}

fn detect_oracle_manipulation(
    _tx: &EncodedConfirmedTransactionWithStatusMeta,
    simulation: &SimulationResult,
) -> bool {
    simulation
        .logs
        .iter()
        .any(|log| log.contains("oracle") || log.contains("price") && log.contains("stale"))
}

fn detect_dos_attack(
    tx: &EncodedConfirmedTransactionWithStatusMeta,
    simulation: &SimulationResult,
) -> bool {
    // Detect excessive compute units or account access
    if simulation.compute_units_consumed > 1_000_000 {
        return true;
    }
    
    if simulation.accounts_accessed.len() > 50 {
        return true;
    }
    
    // Check for repeated failed transactions
    if let Some(meta) = &tx.transaction.meta {
        if meta.err.is_some() && simulation.logs.len() > 100 {
            return true;
        }
    }
    
    false
}

fn detect_arbitrary_cpi(
    _tx: &EncodedConfirmedTransactionWithStatusMeta,
    simulation: &SimulationResult,
) -> bool {
    simulation
        .logs
        .iter()
        .any(|log| log.contains("invoke") && !log.contains("System") && !log.contains("Token"))
}

fn detect_bump_seed(
    _tx: &EncodedConfirmedTransactionWithStatusMeta,
    simulation: &SimulationResult,
) -> bool {
    simulation
        .logs
        .iter()
        .any(|log| log.contains("bump") && log.contains("invalid"))
}

fn detect_account_data_mismatch(
    _tx: &EncodedConfirmedTransactionWithStatusMeta,
    simulation: &SimulationResult,
) -> bool {
    simulation
        .logs
        .iter()
        .any(|log| log.contains("deserialization") || log.contains("data mismatch"))
}

fn detect_unchecked_ownership(
    _tx: &EncodedConfirmedTransactionWithStatusMeta,
    simulation: &SimulationResult,
) -> bool {
    simulation
        .logs
        .iter()
        .any(|log| log.contains("owner") && (log.contains("invalid") || log.contains("mismatch")))
}

fn detect_token_validation(
    _tx: &EncodedConfirmedTransactionWithStatusMeta,
    simulation: &SimulationResult,
) -> bool {
    simulation
        .logs
        .iter()
        .any(|log| log.contains("token") && (log.contains("invalid") || log.contains("mint")))
}

fn detect_duplicate_mutable(
    tx: &EncodedConfirmedTransactionWithStatusMeta,
    _simulation: &SimulationResult,
) -> bool {
    if let Some(decoded_tx) = tx.transaction.transaction.decode() {
        let account_keys = &decoded_tx.message.account_keys;
        let mut seen = std::collections::HashSet::new();
        
        for key in account_keys {
            if !seen.insert(key) {
                return true; // Duplicate found
            }
        }
    }
    false
}

fn detect_account_reinitialization(
    _tx: &EncodedConfirmedTransactionWithStatusMeta,
    simulation: &SimulationResult,
) -> bool {
    simulation
        .logs
        .iter()
        .any(|log| log.contains("already initialized") || log.contains("reinitialization"))
}

fn detect_closed_account_revival(
    tx: &EncodedConfirmedTransactionWithStatusMeta,
    simulation: &SimulationResult,
) -> bool {
    if let Some(meta) = &tx.transaction.meta {
        // Check for accounts going from 0 to non-zero (revival)
        for (pre, post) in meta.pre_balances.iter().zip(meta.post_balances.iter()) {
            if *pre == 0 && *post > 0 {
                if simulation.logs.iter().any(|log| log.contains("closed")) {
                    return true;
                }
            }
        }
    }
    false
}

