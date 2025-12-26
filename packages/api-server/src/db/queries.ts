import { getPool } from './index';
import { logger } from '../utils/logger';

export async function saveAnalysisResult(data: {
  signature: string;
  network: string;
  result: any;
  timestamp: Date;
}) {
  try {
    const pool = getPool();
    await pool.query(
      `INSERT INTO transaction_analyses (signature, network, risk_score, result, created_at)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (signature) DO UPDATE SET
         result = EXCLUDED.result,
         risk_score = EXCLUDED.risk_score`,
      [data.signature, data.network, data.result.risk_score, data.result, data.timestamp]
    );
  } catch (error) {
    logger.error('Failed to save analysis result:', error);
  }
}

export async function saveAuditResult(data: {
  programId: string;
  network: string;
  result: any;
  timestamp: Date;
}) {
  try {
    const pool = getPool();
    await pool.query(
      `INSERT INTO contract_audits (program_id, network, risk_score, result, created_at)
       VALUES ($1, $2, $3, $4, $5)`,
      [data.programId, data.network, data.result.risk_score, data.result, data.timestamp]
    );
  } catch (error) {
    logger.error('Failed to save audit result:', error);
  }
}

export async function getRecentAnalyses(limit: number = 10) {
  try {
    const pool = getPool();
    const result = await pool.query(
      `SELECT * FROM transaction_analyses ORDER BY created_at DESC LIMIT $1`,
      [limit]
    );
    return result.rows;
  } catch (error) {
    logger.error('Failed to fetch recent analyses:', error);
    return [];
  }
}

