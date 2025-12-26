import WebSocket from 'ws';
import EventEmitter from 'eventemitter3';

export class WebSocketClient extends EventEmitter {
  private ws?: WebSocket;
  private url: string;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000;
  private subscriptions: Set<string> = new Set();

  constructor(url: string) {
    super();
    this.url = url;
    this.connect();
  }

  private connect(): void {
    this.ws = new WebSocket(this.url);

    this.ws.on('open', () => {
      console.log('WebSocket connected');
      this.reconnectAttempts = 0;

      // Resubscribe to channels
      this.subscriptions.forEach((channel) => {
        this.send({ type: 'subscribe', channel });
      });

      this.emit('connected');
    });

    this.ws.on('message', (data: WebSocket.RawData) => {
      try {
        const message = JSON.parse(data.toString());
        this.emit(message.type, message.data);
      } catch (error) {
        console.error('Failed to parse WebSocket message:', error);
      }
    });

    this.ws.on('close', () => {
      console.log('WebSocket disconnected');
      this.emit('disconnected');
      this.attemptReconnect();
    });

    this.ws.on('error', (error) => {
      console.error('WebSocket error:', error);
      this.emit('error', error);
    });
  }

  private attemptReconnect(): void {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      const delay = this.reconnectDelay * this.reconnectAttempts;
      
      console.log(`Attempting to reconnect in ${delay}ms (attempt ${this.reconnectAttempts})`);
      
      setTimeout(() => {
        this.connect();
      }, delay);
    } else {
      console.error('Max reconnection attempts reached');
      this.emit('max-reconnect-attempts');
    }
  }

  subscribe(channel: string, callback: (data: any) => void): () => void {
    this.subscriptions.add(channel);
    this.send({ type: 'subscribe', channel });
    this.on(channel, callback);

    // Return unsubscribe function
    return () => {
      this.subscriptions.delete(channel);
      this.send({ type: 'unsubscribe', channel });
      this.off(channel, callback);
    };
  }

  private send(data: any): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(data));
    }
  }

  close(): void {
    if (this.ws) {
      this.ws.close();
      this.ws = undefined;
    }
  }
}

