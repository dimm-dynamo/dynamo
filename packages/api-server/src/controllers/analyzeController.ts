import { Request, Response, NextFunction } from 'express';
import { RustAnalyzerService } from '../services/rustAnalyzer';
import { AIClusterManager } from '../services/aiCluster';
import { logger } from '../utils/logger';
import { saveAnalysisResult } from '../db/queries';

export async function analyzeTransaction(req: Request, res: Response, next: NextFunction) {
  try {
    const { signature, network } = req.body;

    logger.info(`Analyzing transaction: ${signature}`);

    // Call Rust analyzer
    const rustService = new RustAnalyzerService();
    const rustAnalysis = await rustService.analyzeTransaction(signature, network);

    // Enhance with AI cluster analysis
    const aiCluster = AIClusterManager.getInstance();
    const aiAnalysis = await aiCluster.analyzeTransaction(rustAnalysis);

    const result = {
      ...rustAnalysis,
      aiAnalysis: {
        confidence: aiAnalysis.confidence,
        patterns: aiAnalysis.patterns,
        recommendations: aiAnalysis.recommendations,
        clusterScore: aiAnalysis.clusterScore,
      },
    };

    // Save to database
    await saveAnalysisResult({
      signature,
      network,
      result,
      timestamp: new Date(),
    });

    logger.info(`Analysis complete for ${signature}: Risk Score ${result.risk_score}`);

    res.json(result);
  } catch (error) {
    next(error);
  }
}

export async function analyzeAddress(req: Request, res: Response, next: NextFunction) {
  try {
    const { address, network, depth } = req.body;

    logger.info(`Analyzing address: ${address}`);

    const rustService = new RustAnalyzerService();
    const transactions = await rustService.getAddressTransactions(address, network, depth || 10);

    const analyses = await Promise.all(
      transactions.map(async (tx) => {
        const rustAnalysis = await rustService.analyzeTransaction(tx.signature, network);
        const aiCluster = AIClusterManager.getInstance();
        const aiAnalysis = await aiCluster.analyzeTransaction(rustAnalysis);
        return { ...rustAnalysis, aiAnalysis };
      })
    );

    const aggregatedRisk = analyses.reduce((sum, a) => sum + a.risk_score, 0) / analyses.length;

    res.json({
      address,
      network,
      transactionCount: analyses.length,
      aggregatedRiskScore: aggregatedRisk,
      analyses: analyses.slice(0, 5), // Return top 5
      summary: {
        critical: analyses.filter((a) => a.risk_score >= 80).length,
        high: analyses.filter((a) => a.risk_score >= 60 && a.risk_score < 80).length,
        medium: analyses.filter((a) => a.risk_score >= 40 && a.risk_score < 60).length,
        low: analyses.filter((a) => a.risk_score < 40).length,
      },
    });
  } catch (error) {
    next(error);
  }
}

