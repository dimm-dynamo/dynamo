import axios from 'axios';
import { logger } from '../utils/logger';
import { Connection, PublicKey } from '@solana/web3.js';

const RUST_ANALYZER_URL = process.env.RUST_ANALYZER_URL || 'http://localhost:8080';
const SOLANA_RPC_URL = process.env.SOLANA_RPC_URL || 'https://api.mainnet-beta.solana.com';

export class RustAnalyzerService {
  private connection: Connection;

  constructor() {
    this.connection = new Connection(SOLANA_RPC_URL, 'confirmed');
  }

  async analyzeTransaction(signature: string, network?: string) {
    try {
      const response = await axios.post(`${RUST_ANALYZER_URL}/analyze/transaction`, {
        signature,
        network: network || 'mainnet-beta',
      });

      return response.data;
    } catch (error: any) {
      logger.error('Rust analyzer transaction analysis failed:', error.message);
      throw new Error(`Failed to analyze transaction: ${error.message}`);
    }
  }

  async auditContract(programId: string, network?: string, depth?: string) {
    try {
      const response = await axios.post(`${RUST_ANALYZER_URL}/audit/contract`, {
        program_id: programId,
        network: network || 'mainnet-beta',
        depth: depth || 'shallow',
      });

      return response.data;
    } catch (error: any) {
      logger.error('Rust analyzer contract audit failed:', error.message);
      throw new Error(`Failed to audit contract: ${error.message}`);
    }
  }

  async getAddressTransactions(address: string, network?: string, limit: number = 10) {
    try {
      const pubkey = new PublicKey(address);
      const signatures = await this.connection.getSignaturesForAddress(pubkey, { limit });

      return signatures.map((sig) => ({
        signature: sig.signature,
        slot: sig.slot,
        blockTime: sig.blockTime,
      }));
    } catch (error: any) {
      logger.error('Failed to fetch address transactions:', error.message);
      throw new Error(`Failed to fetch transactions: ${error.message}`);
    }
  }
}

