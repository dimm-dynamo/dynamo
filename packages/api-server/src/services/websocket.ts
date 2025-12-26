import { WebSocketServer, WebSocket } from 'ws';
import { logger } from '../utils/logger';
import { v4 as uuidv4 } from 'uuid';

interface Client {
  id: string;
  ws: WebSocket;
  subscriptions: Set<string>;
}

export class WebSocketManager {
  private clients: Map<string, Client> = new Map();

  constructor(private wss: WebSocketServer) {
    this.initialize();
  }

  private initialize() {
    this.wss.on('connection', (ws: WebSocket) => {
      const clientId = uuidv4();
      const client: Client = {
        id: clientId,
        ws,
        subscriptions: new Set(),
      };

      this.clients.set(clientId, client);
      logger.info(`WebSocket client connected: ${clientId}`);

      ws.on('message', (message: string) => {
        this.handleMessage(client, message);
      });

      ws.on('close', () => {
        this.clients.delete(clientId);
        logger.info(`WebSocket client disconnected: ${clientId}`);
      });

      ws.on('error', (error) => {
        logger.error(`WebSocket error for client ${clientId}:`, error);
      });

      // Send welcome message
      this.send(client, 'connected', { clientId });
    });
  }

  private handleMessage(client: Client, message: string) {
    try {
      const data = JSON.parse(message.toString());

      switch (data.type) {
        case 'subscribe':
          if (data.channel) {
            client.subscriptions.add(data.channel);
            this.send(client, 'subscribed', { channel: data.channel });
          }
          break;

        case 'unsubscribe':
          if (data.channel) {
            client.subscriptions.delete(data.channel);
            this.send(client, 'unsubscribed', { channel: data.channel });
          }
          break;

        default:
          logger.warn(`Unknown message type: ${data.type}`);
      }
    } catch (error) {
      logger.error('Failed to parse WebSocket message:', error);
    }
  }

  private send(client: Client, type: string, data: any) {
    if (client.ws.readyState === WebSocket.OPEN) {
      client.ws.send(JSON.stringify({ type, data }));
    }
  }

  public broadcast(channel: string, data: any) {
    const message = JSON.stringify({ type: channel, data });

    this.clients.forEach((client) => {
      if (client.subscriptions.has(channel) && client.ws.readyState === WebSocket.OPEN) {
        client.ws.send(message);
      }
    });
  }

  public getClientCount(): number {
    return this.clients.size;
  }
}

