import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { createServer } from 'http';
import { WebSocketServer } from 'ws';
import dotenv from 'dotenv';
import { logger } from './utils/logger';
import { errorHandler } from './middleware/errorHandler';
import { rateLimiter } from './middleware/rateLimiter';
import apiRoutes from './routes';
import { initializeDatabase } from './db';
import { initializeRedis } from './redis';
import { WebSocketManager } from './services/websocket';
import { AIClusterManager } from './services/aiCluster';

dotenv.config();

const PORT = process.env.PORT || 4000;
const app = express();
const httpServer = createServer(app);

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(rateLimiter);

// Routes
app.use('/api/v1', apiRoutes);

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

// Error handling
app.use(errorHandler);

// WebSocket setup
const wss = new WebSocketServer({ server: httpServer });
const wsManager = new WebSocketManager(wss);

// Initialize services
async function initialize() {
  try {
    logger.info('Initializing Dynamo API Server');

    // Initialize database
    await initializeDatabase();
    logger.info('Database initialized');

    // Initialize Redis
    await initializeRedis();
    logger.info('Redis initialized');

    // Initialize AI cluster
    const aiCluster = AIClusterManager.getInstance();
    await aiCluster.initialize();
    logger.info('AI Cluster initialized');

    // Start server
    httpServer.listen(PORT, () => {
      logger.info(`Server running on port ${PORT}`);
      logger.info(`WebSocket server running on port ${PORT}`);
    });
  } catch (error) {
    logger.error('Failed to initialize server:', error);
    process.exit(1);
  }
}

// Graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('SIGTERM received, shutting down gracefully');
  httpServer.close(() => {
    logger.info('HTTP server closed');
    process.exit(0);
  });
});

process.on('SIGINT', async () => {
  logger.info('SIGINT received, shutting down gracefully');
  httpServer.close(() => {
    logger.info('HTTP server closed');
    process.exit(0);
  });
});

initialize();

export { app, wsManager };

