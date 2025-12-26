import axios, { AxiosInstance } from 'axios';
import { WebSocketClient } from './websocket';
import {
  ClientConfig,
  TransactionAnalysisRequest,
  TransactionAnalysisResponse,
  AddressAnalysisRequest,
  AddressAnalysisResponse,
  ContractAuditRequest,
  ContractAuditResponse,
  MonitorAddressRequest,
  MonitorAddressResponse,
  MonitorStatus,
  SecurityAlert,
} from './types';

export class DynamoClient {
  private httpClient: AxiosInstance;
  private wsClient?: WebSocketClient;
  private config: ClientConfig;

  constructor(config: ClientConfig) {
    this.config = {
      timeout: 30000,
      ...config,
    };

    this.httpClient = axios.create({
      baseURL: `${config.endpoint}/api/v1`,
      timeout: this.config.timeout,
      headers: {
        'Content-Type': 'application/json',
        ...(config.apiKey && { 'Authorization': `Bearer ${config.apiKey}` }),
      },
    });
  }

  /**
   * Analyze a single transaction for security exploits
   */
  async analyzeTransaction(
    request: TransactionAnalysisRequest
  ): Promise<TransactionAnalysisResponse> {
    const response = await this.httpClient.post('/analyze/transaction', request);
    return response.data;
  }

  /**
   * Analyze all transactions for a given address
   */
  async analyzeAddress(
    request: AddressAnalysisRequest
  ): Promise<AddressAnalysisResponse> {
    const response = await this.httpClient.post('/analyze/address', request);
    return response.data;
  }

  /**
   * Audit a smart contract for vulnerabilities
   */
  async auditContract(request: ContractAuditRequest): Promise<ContractAuditResponse> {
    const response = await this.httpClient.post('/audit/contract', request);
    return response.data;
  }

  /**
   * Start monitoring an address for suspicious activity
   */
  async monitorAddress(request: MonitorAddressRequest): Promise<MonitorAddressResponse> {
    const response = await this.httpClient.post('/monitor/address', {
      address: request.address,
      network: request.network,
      webhookUrl: request.webhookUrl,
    });

    const monitorResponse = response.data;

    // Setup WebSocket listener if callback provided
    if (request.callback) {
      this.ensureWebSocket();
      this.wsClient!.subscribe('security-alert', (alert: SecurityAlert) => {
        if (alert.address === request.address) {
          request.callback!(alert);
        }
      });
    }

    return monitorResponse;
  }

  /**
   * Get monitoring status
   */
  async getMonitorStatus(monitorId: string): Promise<MonitorStatus> {
    const response = await this.httpClient.get(`/monitor/status/${monitorId}`);
    return response.data;
  }

  /**
   * Stop monitoring an address
   */
  async stopMonitoring(monitorId: string): Promise<void> {
    await this.httpClient.delete(`/monitor/${monitorId}`);
  }

  /**
   * Subscribe to real-time security alerts via WebSocket
   */
  subscribeToAlerts(callback: (alert: SecurityAlert) => void): () => void {
    this.ensureWebSocket();
    return this.wsClient!.subscribe('security-alert', callback);
  }

  /**
   * Check health status of the API
   */
  async health(): Promise<{ status: string; timestamp: string; uptime: number }> {
    const response = await axios.get(`${this.config.endpoint}/health`);
    return response.data;
  }

  /**
   * Close WebSocket connection
   */
  disconnect(): void {
    if (this.wsClient) {
      this.wsClient.close();
      this.wsClient = undefined;
    }
  }

  private ensureWebSocket(): void {
    if (!this.wsClient) {
      const wsUrl = this.config.endpoint.replace(/^http/, 'ws');
      this.wsClient = new WebSocketClient(wsUrl);
    }
  }
}

