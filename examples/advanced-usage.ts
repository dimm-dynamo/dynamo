/**
 * Advanced Usage Examples for Dynamo SDK
 * 
 * Demonstrates batch processing, real-time monitoring, and webhooks
 */

import { DynamoClient } from '@dynamo/sdk';

const client = new DynamoClient({
  endpoint: 'http://localhost:4000',
  timeout: 60000, // 60 second timeout for deep scans
});

// Example 1: Batch Transaction Analysis
async function batchAnalysis() {
  console.log('Batch Transaction Analysis\n');

  const signatures = [
    'signature1',
    'signature2',
    'signature3',
  ];

  const results = await Promise.allSettled(
    signatures.map((signature) =>
      client.analyzeTransaction({ signature, network: 'mainnet-beta' })
    )
  );

  let criticalCount = 0;
  let highCount = 0;

  results.forEach((result, idx) => {
    if (result.status === 'fulfilled') {
      const analysis = result.value;
      console.log(`Transaction ${idx + 1}: Risk Score ${analysis.risk_score}`);
      
      if (analysis.risk_score >= 80) criticalCount++;
      else if (analysis.risk_score >= 60) highCount++;
    } else {
      console.error(`Transaction ${idx + 1}: Failed - ${result.reason.message}`);
    }
  });

  console.log(`\nSummary: ${criticalCount} critical, ${highCount} high risk`);
}

// Example 2: Deep Contract Audit with Detailed Reporting
async function deepContractAudit(programId: string) {
  console.log(`\nDeep Contract Audit: ${programId}\n`);

  const audit = await client.auditContract({
    programId,
    network: 'mainnet-beta',
    depth: 'deep',
  });

  console.log('Risk Assessment:');
  console.log(`  Overall Risk Score: ${audit.risk_score}/100`);
  console.log(`  Code Quality Score: ${(audit.code_quality.score * 100).toFixed(1)}%`);

  console.log('\nCode Quality Metrics:');
  Object.entries(audit.code_quality.metrics).forEach(([metric, score]) => {
    const percentage = (score * 100).toFixed(1);
    const bar = '█'.repeat(Math.floor(score * 20)) + '░'.repeat(20 - Math.floor(score * 20));
    console.log(`  ${metric.padEnd(20)}: ${bar} ${percentage}%`);
  });

  console.log('\nVulnerabilities by Severity:');
  const bySeverity = audit.vulnerabilities.reduce((acc, vuln) => {
    acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  Object.entries(bySeverity).forEach(([severity, count]) => {
    console.log(`  ${severity}: ${count}`);
  });

  console.log('\nTop Recommendations:');
  audit.recommendations.slice(0, 5).forEach((rec, idx) => {
    console.log(`  ${idx + 1}. ${rec}`);
  });

  return audit;
}

// Example 3: Real-time Monitoring with Custom Alerts
async function monitorWithCustomAlerts(addresses: string[]) {
  console.log('\nSetting up Real-time Monitoring\n');

  const monitorIds: string[] = [];

  for (const address of addresses) {
    const monitor = await client.monitorAddress({
      address,
      network: 'mainnet-beta',
      callback: (alert) => {
        handleSecurityAlert(alert, address);
      },
    });

    monitorIds.push(monitor.monitorId);
    console.log(`Monitoring ${address.slice(0, 8)}... (ID: ${monitor.monitorId})`);
  }

  console.log(`\nMonitoring ${addresses.length} addresses...`);
  
  return monitorIds;
}

function handleSecurityAlert(alert: any, address: string) {
  const severity = getSeverityLevel(alert.riskScore);
  const timestamp = new Date(alert.timestamp).toLocaleString();

  console.log(`\n${'='.repeat(60)}`);
  console.log(`SECURITY ALERT [${severity}]`);
  console.log(`${'='.repeat(60)}`);
  console.log(`Address: ${address}`);
  console.log(`Time: ${timestamp}`);
  console.log(`Risk Score: ${alert.riskScore}/100`);
  
  if (alert.exploits.length > 0) {
    console.log(`\nExploits Detected:`);
    alert.exploits.forEach((exploit: any, idx: number) => {
      console.log(`  ${idx + 1}. ${exploit.exploit_type} (${exploit.severity})`);
    });
  }

  // Custom alert handling based on severity
  if (alert.riskScore >= 80) {
    sendCriticalAlert(alert);
  } else if (alert.riskScore >= 60) {
    sendHighPriorityAlert(alert);
  }
}

function getSeverityLevel(riskScore: number): string {
  if (riskScore >= 80) return 'CRITICAL';
  if (riskScore >= 60) return 'HIGH';
  if (riskScore >= 40) return 'MEDIUM';
  return 'LOW';
}

function sendCriticalAlert(alert: any) {
  // Implement your critical alert logic
  console.log(`  → CRITICAL alert sent to incident response team`);
}

function sendHighPriorityAlert(alert: any) {
  // Implement your high priority alert logic
  console.log(`  → HIGH priority alert logged`);
}

// Example 4: Address Analysis with Historical Data
async function analyzeAddressHistory(address: string) {
  console.log(`\nAnalyzing Address History: ${address}\n`);

  const analysis = await client.analyzeAddress({
    address,
    network: 'mainnet-beta',
    depth: 50, // Analyze last 50 transactions
  });

  console.log(`Total Transactions Analyzed: ${analysis.transactionCount}`);
  console.log(`Aggregated Risk Score: ${analysis.aggregatedRiskScore.toFixed(2)}`);

  console.log('\nRisk Distribution:');
  console.log(`  Critical: ${analysis.summary.critical}`);
  console.log(`  High: ${analysis.summary.high}`);
  console.log(`  Medium: ${analysis.summary.medium}`);
  console.log(`  Low: ${analysis.summary.low}`);

  // Analyze top risky transactions
  const riskyTransactions = analysis.analyses
    .filter(a => a.risk_score >= 60)
    .sort((a, b) => b.risk_score - a.risk_score);

  if (riskyTransactions.length > 0) {
    console.log('\nTop Risky Transactions:');
    riskyTransactions.slice(0, 3).forEach((tx, idx) => {
      console.log(`  ${idx + 1}. Risk Score: ${tx.risk_score}`);
      console.log(`     Exploits: ${tx.exploits.map(e => e.exploit_type).join(', ')}`);
    });
  }

  return analysis;
}

// Example 5: WebSocket Subscription for Multiple Channels
async function subscribeToMultipleChannels() {
  console.log('\nSubscribing to Real-time Events\n');

  const unsubscribe = client.subscribeToAlerts((alert) => {
    console.log(`[${new Date().toLocaleTimeString()}] Alert received:`);
    console.log(`  Address: ${alert.address}`);
    console.log(`  Risk: ${alert.riskScore}`);
    console.log(`  Message: ${alert.message}`);
  });

  console.log('Listening for alerts... (Press Ctrl+C to stop)');

  // Cleanup on exit
  process.on('SIGINT', () => {
    console.log('\nUnsubscribing and cleaning up...');
    unsubscribe();
    client.disconnect();
    process.exit(0);
  });
}

// Run examples
async function main() {
  try {
    // Uncomment the examples you want to run:

    // await batchAnalysis();
    
    // await deepContractAudit('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
    
    // const addresses = ['address1', 'address2'];
    // await monitorWithCustomAlerts(addresses);
    
    // await analyzeAddressHistory('your-address-here');
    
    // await subscribeToMultipleChannels();

    console.log('\nExamples completed!');
  } catch (error) {
    console.error('Error:', error);
  }
}

if (require.main === module) {
  main();
}

export {
  batchAnalysis,
  deepContractAudit,
  monitorWithCustomAlerts,
  analyzeAddressHistory,
  subscribeToMultipleChannels,
};

