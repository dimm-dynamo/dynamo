import { Request, Response, NextFunction } from 'express';
import { RustAnalyzerService } from '../services/rustAnalyzer';
import { AIClusterManager } from '../services/aiCluster';
import { logger } from '../utils/logger';
import { saveAuditResult } from '../db/queries';

export async function auditContract(req: Request, res: Response, next: NextFunction) {
  try {
    const { programId, network, depth } = req.body;

    logger.info(`Auditing contract: ${programId}`);

    // Call Rust analyzer for contract audit
    const rustService = new RustAnalyzerService();
    const rustAudit = await rustService.auditContract(programId, network, depth);

    // Enhance with AI cluster analysis
    const aiCluster = AIClusterManager.getInstance();
    const aiEnhancement = await aiCluster.enhanceAudit(rustAudit);

    const result = {
      ...rustAudit,
      aiEnhancement: {
        additionalVulnerabilities: aiEnhancement.vulnerabilities,
        patternMatches: aiEnhancement.patterns,
        riskAssessment: aiEnhancement.riskAssessment,
        recommendations: aiEnhancement.recommendations,
      },
    };

    // Save to database
    await saveAuditResult({
      programId,
      network,
      result,
      timestamp: new Date(),
    });

    logger.info(`Audit complete for ${programId}: Risk Score ${result.risk_score}`);

    res.json(result);
  } catch (error) {
    next(error);
  }
}

