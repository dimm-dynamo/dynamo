import { Request, Response, NextFunction } from 'express';
import { ZodSchema } from 'zod';
import { logger } from '../utils/logger';

export function validateRequest(schema: ZodSchema) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      await schema.parseAsync(req.body);
      next();
    } catch (error: any) {
      logger.warn('Validation error:', error.errors);
      res.status(400).json({
        error: 'Validation failed',
        details: error.errors,
      });
    }
  };
}

