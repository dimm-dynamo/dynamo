import { Connection, PublicKey } from '@solana/web3.js';
import { Queue, Worker } from 'bullmq';
import axios from 'axios';
import { logger } from '../utils/logger';
import { RustAnalyzerService } from './rustAnalyzer';
import { AIClusterManager } from './aiCluster';
import { getRedisClient } from '../redis';
import { wsManager } from '../index';

interface MonitorConfig {
  monitorId: string;
  address: string;
  network: string;
  webhookUrl?: string;
}

export class MonitoringService {
  private connection: Connection;
  private monitorQueue: Queue;
  private worker: Worker;
  private activeMonitors: Map<string, MonitorConfig> = new Map();

  constructor() {
    const rpcUrl = process.env.SOLANA_RPC_URL || 'https://api.mainnet-beta.solana.com';
    this.connection = new Connection(rpcUrl, 'confirmed');

    const redisConnection = getRedisClient();
    
    this.monitorQueue = new Queue('address-monitoring', { connection: redisConnection });

    this.worker = new Worker(
      'address-monitoring',
      async (job) => {
        await this.processMonitorJob(job.data);
      },
      { connection: redisConnection, concurrency: 10 }
    );

    logger.info('Monitoring service initialized');
  }

  async startMonitoring(config: MonitorConfig) {
    this.activeMonitors.set(config.monitorId, config);

    // Add recurring job
    await this.monitorQueue.add(
      `monitor-${config.monitorId}`,
      config,
      {
        repeat: {
          every: 10000, // Check every 10 seconds
        },
        jobId: config.monitorId,
      }
    );

    logger.info(`Started monitoring ${config.address} (${config.monitorId})`);
  }

  async stopMonitoring(monitorId: string) {
    await this.monitorQueue.remove(monitorId);
    this.activeMonitors.delete(monitorId);
    logger.info(`Stopped monitoring ${monitorId}`);
  }

  async getMonitorStatus(monitorId: string) {
    const config = this.activeMonitors.get(monitorId);
    if (!config) return null;

    const job = await this.monitorQueue.getJob(monitorId);

    return {
      monitorId,
      address: config.address,
      network: config.network,
      status: job ? 'active' : 'inactive',
      lastCheck: job?.processedOn ? new Date(job.processedOn) : null,
    };
  }

  private async processMonitorJob(config: MonitorConfig) {
    try {
      const pubkey = new PublicKey(config.address);
      
      // Get latest signatures
      const signatures = await this.connection.getSignaturesForAddress(pubkey, { limit: 5 });

      for (const sigInfo of signatures) {
        // Check if we've already processed this signature
        const redis = getRedisClient();
        const processed = await redis.get(`processed:${sigInfo.signature}`);
        
        if (processed) continue;

        // Analyze transaction
        const rustService = new RustAnalyzerService();
        const analysis = await rustService.analyzeTransaction(sigInfo.signature, config.network);

        // AI enhancement
        const aiCluster = AIClusterManager.getInstance();
        const aiAnalysis = await aiCluster.analyzeTransaction(analysis);

        const result = { ...analysis, aiAnalysis };

        // Check if alert worthy (risk score > 60)
        if (result.risk_score > 60) {
          await this.sendAlert(config, result);
        }

        // Mark as processed
        await redis.set(`processed:${sigInfo.signature}`, '1', { EX: 86400 }); // 24 hour TTL
      }
    } catch (error: any) {
      logger.error(`Monitor job failed for ${config.address}:`, error.message);
    }
  }

  private async sendAlert(config: MonitorConfig, analysis: any) {
    const alert = {
      monitorId: config.monitorId,
      address: config.address,
      timestamp: new Date().toISOString(),
      riskScore: analysis.risk_score,
      exploits: analysis.exploits,
      message: `Security alert: High-risk transaction detected for ${config.address}`,
    };

    // Send webhook if configured
    if (config.webhookUrl) {
      try {
        await axios.post(config.webhookUrl, alert, { timeout: 5000 });
      } catch (error: any) {
        logger.error(`Webhook failed for ${config.monitorId}:`, error.message);
      }
    }

    // Send WebSocket notification
    wsManager.broadcast('security-alert', alert);

    logger.warn(`Security alert sent for ${config.address}: Risk Score ${analysis.risk_score}`);
  }
}

