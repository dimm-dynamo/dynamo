import IORedis from 'ioredis';
import { logger } from '../utils/logger';

let redisClient: IORedis;

export async function initializeRedis() {
  const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';

  redisClient = new IORedis(redisUrl, {
    maxRetriesPerRequest: 3,
    retryStrategy(times) {
      const delay = Math.min(times * 50, 2000);
      return delay;
    },
  });

  redisClient.on('connect', () => {
    logger.info('Redis connection established');
  });

  redisClient.on('error', (error) => {
    logger.error('Redis error:', error);
  });

  try {
    await redisClient.ping();
  } catch (error) {
    logger.error('Redis connection failed:', error);
    throw error;
  }
}

export function getRedisClient(): IORedis {
  if (!redisClient) {
    throw new Error('Redis not initialized');
  }
  return redisClient;
}

