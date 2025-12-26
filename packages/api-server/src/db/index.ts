import { Pool } from 'pg';
import { logger } from '../utils/logger';

let pool: Pool;

export async function initializeDatabase() {
  const databaseUrl = process.env.DATABASE_URL;

  if (!databaseUrl) {
    logger.warn('DATABASE_URL not set, database features disabled');
    return;
  }

  pool = new Pool({
    connectionString: databaseUrl,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
  });

  try {
    await pool.query('SELECT NOW()');
    logger.info('Database connection established');

    // Create tables if they don't exist
    await createTables();
  } catch (error) {
    logger.error('Database connection failed:', error);
    throw error;
  }
}

async function createTables() {
  const createAnalysisTable = `
    CREATE TABLE IF NOT EXISTS transaction_analyses (
      id SERIAL PRIMARY KEY,
      signature VARCHAR(128) UNIQUE NOT NULL,
      network VARCHAR(32) NOT NULL,
      risk_score FLOAT NOT NULL,
      result JSONB NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `;

  const createAuditTable = `
    CREATE TABLE IF NOT EXISTS contract_audits (
      id SERIAL PRIMARY KEY,
      program_id VARCHAR(64) NOT NULL,
      network VARCHAR(32) NOT NULL,
      risk_score FLOAT NOT NULL,
      result JSONB NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `;

  const createIndexes = `
    CREATE INDEX IF NOT EXISTS idx_analyses_signature ON transaction_analyses(signature);
    CREATE INDEX IF NOT EXISTS idx_audits_program ON contract_audits(program_id);
    CREATE INDEX IF NOT EXISTS idx_analyses_risk ON transaction_analyses(risk_score DESC);
  `;

  await pool.query(createAnalysisTable);
  await pool.query(createAuditTable);
  await pool.query(createIndexes);

  logger.info('Database tables created/verified');
}

export function getPool(): Pool {
  if (!pool) {
    throw new Error('Database not initialized');
  }
  return pool;
}

