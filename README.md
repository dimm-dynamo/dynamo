<div align="center">

<img src="docs/main.png" alt="Dynamo" width="800"/>

# Dynamo

**AI-powered on-chain security exploit detection and audit system for Solana blockchain.**

---

**Donation:** `5rcfn1B3WcHVdjfMmrnD2ZmGhLR9fevd5WH1YZtgGrwJ`

</div>

## Overview

Dynamo is a distributed security audit platform that combines off-chain analysis with chain-executable state verification. The system uses AI clustering to detect potential exploits, vulnerabilities, and security issues in Solana smart contracts and transactions.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         Frontend                             │
│              (React + TypeScript + WebSocket)                │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                      API Server                              │
│         (Node.js + Express + AI Cluster Router)              │
└──────┬───────────────────────────────────┬──────────────────┘
       │                                   │
┌──────▼──────────────┐          ┌────────▼─────────────────┐
│  Rust Analyzer      │          │   AI Cluster Engine      │
│  - Chain State      │          │   - Pattern Detection    │
│  - Exploit Detection│          │   - Anomaly Analysis     │
│  - State Simulation │          │   - Risk Scoring         │
└─────────────────────┘          └──────────────────────────┘
```

### Core Components

1. **Rust Chain Analyzer**: High-performance off-chain analyzer that simulates and verifies chain-executable states
2. **TypeScript API Server**: Central orchestration layer with AI cluster integration
3. **TypeScript SDK**: Programmatic access to Dynamo's capabilities
4. **React Frontend**: Real-time visualization and monitoring dashboard
5. **AI Cluster Engine**: Distributed analysis system for exploit detection

## Features

- Real-time transaction monitoring and analysis
- Smart contract vulnerability detection
- Exploit pattern recognition using AI clustering
- Off-chain state simulation and verification
- WebSocket-based live updates
- RESTful API and SDK access
- Docker-based deployment

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Node.js 18+ (for local development)
- Rust 1.70+ (for local development)
- Solana CLI tools

### Using Docker

```bash
docker-compose up -d
```

Access the dashboard at `http://localhost:3000`

### Local Development

#### 1. Setup Rust Analyzer

```bash
cd packages/rust-analyzer
cargo build --release
cargo run
```

#### 2. Setup API Server

```bash
cd packages/api-server
npm install
npm run dev
```

#### 3. Setup Frontend

```bash
cd packages/frontend
npm install
npm run dev
```

## SDK Usage

```typescript
import { DynamoClient } from '@dynamo/sdk';

const client = new DynamoClient({
  endpoint: 'http://localhost:4000',
  apiKey: 'your-api-key'
});

// Analyze a transaction
const result = await client.analyzeTransaction({
  signature: 'transaction-signature',
  network: 'mainnet-beta'
});

console.log('Risk Score:', result.riskScore);
console.log('Detected Exploits:', result.exploits);

// Monitor address
await client.monitorAddress({
  address: 'wallet-or-program-address',
  callback: (alert) => {
    console.log('Security Alert:', alert);
  }
});
```

## API Endpoints

### Transaction Analysis

```
POST /api/v1/analyze/transaction
```

Request:
```json
{
  "signature": "string",
  "network": "mainnet-beta | devnet | testnet"
}
```

Response:
```json
{
  "riskScore": 0-100,
  "exploits": [
    {
      "type": "reentrancy | overflow | authority_bypass",
      "severity": "critical | high | medium | low",
      "description": "string",
      "location": "string"
    }
  ],
  "aiAnalysis": {
    "confidence": 0-1,
    "patterns": ["string"],
    "recommendations": ["string"]
  }
}
```

### Smart Contract Audit

```
POST /api/v1/audit/contract
```

Request:
```json
{
  "programId": "string",
  "network": "mainnet-beta | devnet | testnet",
  "depth": "shallow | deep"
}
```

### Address Monitoring

```
POST /api/v1/monitor/address
```

Request:
```json
{
  "address": "string",
  "network": "mainnet-beta | devnet | testnet",
  "webhookUrl": "string (optional)"
}
```

## Configuration

### Environment Variables

#### API Server

```env
PORT=4000
SOLANA_RPC_URL=https://api.mainnet-beta.solana.com
RUST_ANALYZER_URL=http://localhost:8080
AI_CLUSTER_NODES=node1:5000,node2:5000,node3:5000
DATABASE_URL=postgresql://user:pass@localhost:5432/dynamo
REDIS_URL=redis://localhost:6379
LOG_LEVEL=info
```

#### Rust Analyzer

```env
RUST_LOG=info
BIND_ADDRESS=0.0.0.0:8080
SOLANA_RPC_URL=https://api.mainnet-beta.solana.com
WORKER_THREADS=4
```

## Architecture Deep Dive

### Rust Chain Analyzer

The Rust component provides high-performance chain state analysis:

- **State Simulation**: Executes transactions in an isolated environment to detect malicious behavior
- **Exploit Detection**: Pattern matching against known exploit signatures
- **Performance**: Handles 1000+ transactions per second
- **Memory Safety**: Leverages Rust's ownership model for secure processing

### AI Cluster Integration

The AI cluster uses multiple analysis strategies:

1. **Supervised Learning**: Trained on known exploit patterns
2. **Unsupervised Clustering**: Detects anomalous transaction patterns
3. **Graph Analysis**: Identifies suspicious transaction relationships
4. **Heuristic Scoring**: Risk assessment based on multiple factors

### TypeScript API Layer

The API server orchestrates:

- Request routing and load balancing
- AI cluster coordination
- WebSocket event streaming
- Caching and rate limiting
- Authentication and authorization

## Security Considerations

- All analysis occurs off-chain; no private keys are required
- API rate limiting prevents abuse
- Webhook signatures prevent spoofing
- Audit logs for compliance

## Performance Metrics

- Transaction analysis: < 500ms average
- Smart contract audit: 2-5 minutes (deep scan)
- WebSocket latency: < 100ms
- Cluster scaling: Linear up to 10 nodes

## Contributing

See CONTRIBUTING.md for development guidelines.

## License

MIT License - see LICENSE file for details
