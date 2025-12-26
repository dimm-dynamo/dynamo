import axios from 'axios';
import { logger } from '../utils/logger';

interface AINode {
  id: string;
  url: string;
  healthy: boolean;
  lastCheck: Date;
}

interface AIAnalysisResult {
  confidence: number;
  patterns: string[];
  recommendations: string[];
  clusterScore: number;
}

interface AIAuditEnhancement {
  vulnerabilities: Array<{
    type: string;
    severity: string;
    description: string;
  }>;
  patterns: string[];
  riskAssessment: string;
  recommendations: string[];
}

export class AIClusterManager {
  private static instance: AIClusterManager;
  private nodes: AINode[] = [];
  private currentNodeIndex = 0;

  private constructor() {}

  static getInstance(): AIClusterManager {
    if (!AIClusterManager.instance) {
      AIClusterManager.instance = new AIClusterManager();
    }
    return AIClusterManager.instance;
  }

  async initialize() {
    const nodeUrls = process.env.AI_CLUSTER_NODES?.split(',') || [];

    if (nodeUrls.length === 0) {
      logger.warn('No AI cluster nodes configured, using local analysis mode');
      this.nodes = [];
      return;
    }

    this.nodes = nodeUrls.map((url, idx) => ({
      id: `node-${idx}`,
      url: url.trim(),
      healthy: true,
      lastCheck: new Date(),
    }));

    // Health check
    await this.healthCheck();
    
    // Start periodic health checks
    setInterval(() => this.healthCheck(), 60000);

    logger.info(`AI Cluster initialized with ${this.nodes.length} nodes`);
  }

  async analyzeTransaction(rustAnalysis: any): Promise<AIAnalysisResult> {
    if (this.nodes.length === 0) {
      return this.fallbackAnalysis(rustAnalysis);
    }

    const node = this.getNextHealthyNode();
    if (!node) {
      logger.warn('No healthy AI nodes available, using fallback');
      return this.fallbackAnalysis(rustAnalysis);
    }

    try {
      const response = await axios.post(
        `${node.url}/analyze`,
        {
          exploits: rustAnalysis.exploits,
          stateChanges: rustAnalysis.state_changes,
          simulationResult: rustAnalysis.simulation_result,
        },
        { timeout: 10000 }
      );

      return {
        confidence: response.data.confidence || 0.85,
        patterns: response.data.patterns || [],
        recommendations: response.data.recommendations || [],
        clusterScore: response.data.score || 0,
      };
    } catch (error: any) {
      logger.error(`AI node ${node.id} failed:`, error.message);
      node.healthy = false;
      return this.fallbackAnalysis(rustAnalysis);
    }
  }

  async enhanceAudit(rustAudit: any): Promise<AIAuditEnhancement> {
    if (this.nodes.length === 0) {
      return this.fallbackAuditEnhancement(rustAudit);
    }

    const node = this.getNextHealthyNode();
    if (!node) {
      return this.fallbackAuditEnhancement(rustAudit);
    }

    try {
      const response = await axios.post(
        `${node.url}/enhance-audit`,
        {
          vulnerabilities: rustAudit.vulnerabilities,
          codeQuality: rustAudit.code_quality,
        },
        { timeout: 15000 }
      );

      return {
        vulnerabilities: response.data.vulnerabilities || [],
        patterns: response.data.patterns || [],
        riskAssessment: response.data.riskAssessment || 'unknown',
        recommendations: response.data.recommendations || [],
      };
    } catch (error: any) {
      logger.error(`AI node ${node.id} failed:`, error.message);
      node.healthy = false;
      return this.fallbackAuditEnhancement(rustAudit);
    }
  }

  private async healthCheck() {
    const checks = this.nodes.map(async (node) => {
      try {
        await axios.get(`${node.url}/health`, { timeout: 5000 });
        node.healthy = true;
        node.lastCheck = new Date();
      } catch (error) {
        node.healthy = false;
        logger.warn(`AI node ${node.id} health check failed`);
      }
    });

    await Promise.all(checks);
  }

  private getNextHealthyNode(): AINode | null {
    const healthyNodes = this.nodes.filter((n) => n.healthy);
    if (healthyNodes.length === 0) return null;

    const node = healthyNodes[this.currentNodeIndex % healthyNodes.length];
    this.currentNodeIndex++;
    return node;
  }

  private fallbackAnalysis(rustAnalysis: any): AIAnalysisResult {
    // Rule-based fallback when AI cluster is unavailable
    const patterns: string[] = [];
    const recommendations: string[] = [];

    // Analyze exploit types
    const exploitTypes = new Set(rustAnalysis.exploits?.map((e: any) => e.exploit_type) || []);
    
    if (exploitTypes.has('reentrancy')) {
      patterns.push('potential_reentrancy_vulnerability');
      recommendations.push('Implement reentrancy guards and state locks');
    }

    if (exploitTypes.has('integer_overflow')) {
      patterns.push('arithmetic_overflow_risk');
      recommendations.push('Use checked arithmetic operations');
    }

    // Calculate confidence based on exploit count and severity
    const criticalCount = rustAnalysis.exploits?.filter((e: any) => e.severity === 'critical').length || 0;
    const confidence = Math.min(0.5 + (criticalCount * 0.1), 0.95);

    return {
      confidence,
      patterns,
      recommendations,
      clusterScore: rustAnalysis.risk_score || 0,
    };
  }

  private fallbackAuditEnhancement(rustAudit: any): AIAuditEnhancement {
    return {
      vulnerabilities: [],
      patterns: ['static_analysis_only'],
      riskAssessment: 'limited_ai_analysis',
      recommendations: [
        'AI cluster unavailable - results based on static analysis only',
        'Consider re-running audit when AI cluster is available for enhanced detection',
      ],
    };
  }
}

