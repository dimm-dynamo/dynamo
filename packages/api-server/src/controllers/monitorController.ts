import { Request, Response, NextFunction } from 'express';
import { MonitoringService } from '../services/monitoring';
import { logger } from '../utils/logger';
import { v4 as uuidv4 } from 'uuid';

const monitoringService = new MonitoringService();

export async function monitorAddress(req: Request, res: Response, next: NextFunction) {
  try {
    const { address, network, webhookUrl } = req.body;

    logger.info(`Starting monitoring for address: ${address}`);

    const monitorId = uuidv4();

    await monitoringService.startMonitoring({
      monitorId,
      address,
      network,
      webhookUrl,
    });

    res.json({
      monitorId,
      address,
      network,
      status: 'active',
      startedAt: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
}

export async function getMonitorStatus(req: Request, res: Response, next: NextFunction) {
  try {
    const { monitorId } = req.params;

    const status = await monitoringService.getMonitorStatus(monitorId);

    if (!status) {
      return res.status(404).json({ error: 'Monitor not found' });
    }

    res.json(status);
  } catch (error) {
    next(error);
  }
}

export async function stopMonitoring(req: Request, res: Response, next: NextFunction) {
  try {
    const { monitorId } = req.params;

    await monitoringService.stopMonitoring(monitorId);

    res.json({
      monitorId,
      status: 'stopped',
      stoppedAt: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
}

