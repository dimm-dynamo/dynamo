/**
 * Basic Usage Examples for Dynamo SDK
 * 
 * Run with: ts-node examples/basic-usage.ts
 */

import { DynamoClient } from '@dynamo/sdk';

const client = new DynamoClient({
  endpoint: 'http://localhost:4000',
  // apiKey: 'your-api-key', // Uncomment for authenticated requests
});

async function main() {
  console.log('Dynamo SDK Basic Usage Examples\n');

  // Example 1: Analyze a Transaction
  console.log('1. Analyzing Transaction...');
  try {
    const txAnalysis = await client.analyzeTransaction({
      signature: 'your-transaction-signature-here',
      network: 'mainnet-beta',
    });

    console.log(`   Risk Score: ${txAnalysis.risk_score}`);
    console.log(`   Exploits Found: ${txAnalysis.exploits.length}`);
    console.log(`   Compute Units: ${txAnalysis.simulation_result.compute_units_consumed}`);
    
    if (txAnalysis.exploits.length > 0) {
      console.log('   Detected Exploits:');
      txAnalysis.exploits.forEach((exploit, idx) => {
        console.log(`     ${idx + 1}. ${exploit.exploit_type} (${exploit.severity})`);
        console.log(`        ${exploit.description}`);
      });
    }
  } catch (error: any) {
    console.error('   Error:', error.message);
  }

  // Example 2: Audit a Smart Contract
  console.log('\n2. Auditing Smart Contract...');
  try {
    const audit = await client.auditContract({
      programId: 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
      network: 'mainnet-beta',
      depth: 'shallow',
    });

    console.log(`   Risk Score: ${audit.risk_score}`);
    console.log(`   Code Quality: ${(audit.code_quality.score * 100).toFixed(1)}%`);
    console.log(`   Vulnerabilities: ${audit.vulnerabilities.length}`);
    console.log(`   Recommendations: ${audit.recommendations.length}`);
  } catch (error: any) {
    console.error('   Error:', error.message);
  }

  // Example 3: Monitor an Address
  console.log('\n3. Starting Address Monitoring...');
  try {
    const monitor = await client.monitorAddress({
      address: 'your-solana-address-here',
      network: 'mainnet-beta',
      callback: (alert) => {
        console.log(`\n   ALERT: ${alert.message}`);
        console.log(`   Risk Score: ${alert.riskScore}`);
        console.log(`   Timestamp: ${alert.timestamp}`);
      },
    });

    console.log(`   Monitor ID: ${monitor.monitorId}`);
    console.log(`   Status: ${monitor.status}`);
    console.log('   Monitoring active... (Press Ctrl+C to stop)');

    // Keep the script running to receive alerts
    await new Promise(() => {});
  } catch (error: any) {
    console.error('   Error:', error.message);
  }
}

main().catch(console.error);

