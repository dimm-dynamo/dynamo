use crate::models::SimulationResult;
use anyhow::Result;
use log::debug;
use solana_transaction_status::EncodedConfirmedTransactionWithStatusMeta;

pub struct StateSimulator {}

impl StateSimulator {
    pub fn new() -> Self {
        Self {}
    }

    pub fn simulate_transaction(
        &self,
        transaction: &EncodedConfirmedTransactionWithStatusMeta,
    ) -> Result<SimulationResult> {
        debug!("Simulating transaction execution");

        let meta = transaction.transaction.meta.as_ref();

        let (success, error, compute_units, logs) = if let Some(m) = meta {
            (
                m.err.is_none(),
                m.err.as_ref().map(|e| format!("{:?}", e)),
                m.compute_units_consumed.unwrap_or(0),
                m.log_messages.clone().unwrap_or_default(),
            )
        } else {
            (false, Some("No metadata available".to_string()), 0, vec![])
        };

        let accounts_accessed = self.extract_accounts_accessed(transaction);

        Ok(SimulationResult {
            success,
            error,
            compute_units_consumed: compute_units,
            logs,
            accounts_accessed,
        })
    }

    fn extract_accounts_accessed(
        &self,
        transaction: &EncodedConfirmedTransactionWithStatusMeta,
    ) -> Vec<String> {
        let mut accounts = Vec::new();

        // Extract account keys from transaction
        if let Some(tx) = transaction.transaction.transaction.decode() {
            for key in tx.message.account_keys {
                accounts.push(key.to_string());
            }
        }

        accounts
    }
}

