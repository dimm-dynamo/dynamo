# Architecture

## System Overview

Dynamo is a distributed security audit platform designed to detect exploits and vulnerabilities in Solana smart contracts and transactions. The system combines high-performance Rust analysis with AI-powered pattern detection.

## Component Architecture

### Layer 1: Rust Chain Analyzer

**Purpose**: High-performance off-chain analysis and state simulation

**Technology Stack**:
- Rust 1.75+
- Actix-web for HTTP server
- Solana SDK for blockchain interaction

**Responsibilities**:
- Transaction fetching from Solana RPC
- Off-chain state simulation
- Bytecode analysis
- Exploit pattern matching
- Basic vulnerability detection

**Performance Characteristics**:
- 1000+ transactions/second throughput
- < 500ms average analysis latency
- LRU caching for repeated analyses
- Multi-threaded worker pool

**API Endpoints**:
```
POST /analyze/transaction
POST /audit/contract
GET  /health
```

### Layer 2: TypeScript API Server

**Purpose**: Central orchestration and AI cluster coordination

**Technology Stack**:
- Node.js 18+ / TypeScript
- Express.js for REST API
- WebSocket for real-time updates
- PostgreSQL for persistence
- Redis for caching and job queues
- BullMQ for background jobs

**Responsibilities**:
- Request routing and validation
- AI cluster coordination
- Database operations
- WebSocket management
- Address monitoring
- Webhook delivery

**Components**:

1. **HTTP API Layer**
   - Request validation (Zod schemas)
   - Rate limiting (100 req/15min per IP)
   - Authentication (Bearer tokens)
   - Error handling

2. **AI Cluster Manager**
   - Load balancing across AI nodes
   - Health checking
   - Fallback to rule-based analysis
   - Result aggregation

3. **Monitoring Service**
   - Address subscription management
   - Periodic transaction polling
   - Alert generation
   - Webhook delivery

4. **WebSocket Manager**
   - Client connection handling
   - Channel-based subscriptions
   - Real-time event broadcasting

### Layer 3: AI Cluster

**Purpose**: Advanced pattern detection and anomaly analysis

**Architecture**:
- Distributed node cluster
- Round-robin load balancing
- Independent node scaling
- Graceful degradation

**Analysis Methods**:
1. **Supervised Learning**: Trained on known exploit patterns
2. **Unsupervised Clustering**: Anomaly detection
3. **Graph Analysis**: Transaction relationship analysis
4. **Heuristic Scoring**: Multi-factor risk assessment

**Node Interface**:
```
POST /analyze - Transaction analysis enhancement
POST /enhance-audit - Contract audit enhancement
GET  /health - Health check
```

### Layer 4: Frontend Dashboard

**Purpose**: User interface and visualization

**Technology Stack**:
- React 18
- TypeScript
- Tailwind CSS
- Recharts for data visualization
- React Router for navigation

**Features**:
- Real-time security alerts
- Transaction analysis interface
- Contract audit interface
- Address monitoring management
- Risk visualization

## Data Flow

### Transaction Analysis Flow

```
1. User Request
   ↓
2. API Server (validation)
   ↓
3. Rust Analyzer
   - Fetch transaction from Solana
   - Simulate execution
   - Detect basic exploits
   ↓
4. AI Cluster
   - Enhanced pattern detection
   - Anomaly scoring
   - Recommendation generation
   ↓
5. Database (persist results)
   ↓
6. Response to User
```

### Monitoring Flow

```
1. User creates monitor
   ↓
2. Monitor registered in database
   ↓
3. Background job scheduled (BullMQ)
   ↓
4. Every 10 seconds:
   - Fetch new transactions
   - Analyze each transaction
   - Check risk threshold
   ↓
5. If high risk detected:
   - Generate alert
   - Send webhook (if configured)
   - Broadcast WebSocket event
   ↓
6. Frontend receives alert
```

## Database Schema

### transaction_analyses

```sql
CREATE TABLE transaction_analyses (
  id SERIAL PRIMARY KEY,
  signature VARCHAR(128) UNIQUE NOT NULL,
  network VARCHAR(32) NOT NULL,
  risk_score FLOAT NOT NULL,
  result JSONB NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_analyses_signature ON transaction_analyses(signature);
CREATE INDEX idx_analyses_risk ON transaction_analyses(risk_score DESC);
```

### contract_audits

```sql
CREATE TABLE contract_audits (
  id SERIAL PRIMARY KEY,
  program_id VARCHAR(64) NOT NULL,
  network VARCHAR(32) NOT NULL,
  risk_score FLOAT NOT NULL,
  result JSONB NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audits_program ON contract_audits(program_id);
```

## Caching Strategy

### Redis Cache Keys

```
processed:{signature} - TTL: 24h - Processed transaction tracker
analysis:{signature} - TTL: 1h - Cached analysis results
monitor:{address} - TTL: none - Active monitor metadata
```

### LRU Cache (Rust)

- Size: 1000 entries
- Key: Transaction signature
- Value: Complete analysis result
- Eviction: Least recently used

## Scaling Considerations

### Horizontal Scaling

1. **API Server**: Stateless design allows multiple instances behind load balancer
2. **Rust Analyzer**: Can run multiple instances with shared Redis cache
3. **AI Cluster**: Add nodes to AI_CLUSTER_NODES environment variable
4. **Database**: PostgreSQL replication for read scaling

### Vertical Scaling

1. **Rust Analyzer**: Increase WORKER_THREADS for more parallel processing
2. **API Server**: Increase BullMQ concurrency
3. **Database**: Increase connection pool size

### Performance Bottlenecks

1. **Solana RPC**: Rate limits and latency
   - Mitigation: Use private RPC endpoints, implement request queuing
2. **AI Cluster**: Processing time for deep analysis
   - Mitigation: Implement async processing, cache results
3. **Database**: Write throughput on high traffic
   - Mitigation: Batch inserts, use connection pooling

## Security

### Authentication

- API key based authentication (Bearer tokens)
- Rate limiting per IP address
- Request signature validation for webhooks

### Data Protection

- All analysis occurs off-chain
- No private key storage or handling
- Audit logs for compliance
- Encrypted database connections

### Network Security

- HTTPS/TLS for all external communication
- Internal service mesh for component communication
- Firewall rules for service isolation

## Monitoring and Observability

### Metrics

- Request count and latency (per endpoint)
- Analysis throughput (transactions/second)
- Error rates and types
- AI cluster node health
- Database connection pool utilization
- Cache hit rates

### Logging

- Structured JSON logs
- Log levels: ERROR, WARN, INFO, DEBUG
- Correlation IDs for request tracing
- Centralized log aggregation

### Alerting

- Critical: Service down, database unavailable
- Warning: High error rate, cache misses
- Info: Performance degradation, scaling events

## Deployment Architecture

### Docker Compose (Development)

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│  Frontend   │  │ API Server  │  │    Rust     │
│   :3000     │──│   :4000     │──│  Analyzer   │
│             │  │             │  │   :8080     │
└─────────────┘  └─────────────┘  └─────────────┘
                       │                  │
                       ├──────────────────┤
                       │                  │
                 ┌─────▼─────┐      ┌────▼─────┐
                 │ PostgreSQL │      │  Redis   │
                 │   :5432    │      │  :6379   │
                 └────────────┘      └──────────┘
```

### Kubernetes (Production)

```
┌───────────────────────────────────────────────┐
│              Ingress Controller               │
│         (SSL termination, routing)            │
└───────────┬────────────────────┬──────────────┘
            │                    │
    ┌───────▼────────┐   ┌──────▼───────────┐
    │   Frontend     │   │   API Server     │
    │   Deployment   │   │   Deployment     │
    │   (3 replicas) │   │   (5 replicas)   │
    └────────────────┘   └──────┬───────────┘
                                │
                         ┌──────▼───────────┐
                         │  Rust Analyzer   │
                         │   Deployment     │
                         │   (3 replicas)   │
                         └──────────────────┘

    ┌────────────────┐   ┌──────────────────┐
    │   PostgreSQL   │   │      Redis       │
    │   StatefulSet  │   │   StatefulSet    │
    └────────────────┘   └──────────────────┘
```

## Future Enhancements

1. **Machine Learning Pipeline**: Automated model training from detected exploits
2. **Multi-chain Support**: Ethereum, BSC, Polygon integration
3. **Advanced Visualization**: Interactive exploit graphs, timeline analysis
4. **Collaboration Features**: Shared workspaces, team management
5. **API Rate Plans**: Tiered access with usage quotas
6. **Mobile App**: iOS/Android native applications

