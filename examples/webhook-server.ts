/**
 * Example webhook server for receiving Dynamo security alerts
 * 
 * Run with: ts-node examples/webhook-server.ts
 */

import express from 'express';
import { DynamoClient } from '@dynamo/sdk';

const app = express();
app.use(express.json());

const PORT = 3001;
const WEBHOOK_URL = `http://localhost:${PORT}/webhook`;

const client = new DynamoClient({
  endpoint: 'http://localhost:4000',
});

// Webhook endpoint to receive alerts
app.post('/webhook', (req, res) => {
  const alert = req.body;

  console.log('\n' + '='.repeat(60));
  console.log('WEBHOOK ALERT RECEIVED');
  console.log('='.repeat(60));
  console.log(`Monitor ID: ${alert.monitorId}`);
  console.log(`Address: ${alert.address}`);
  console.log(`Timestamp: ${alert.timestamp}`);
  console.log(`Risk Score: ${alert.riskScore}`);
  console.log(`Message: ${alert.message}`);

  if (alert.exploits && alert.exploits.length > 0) {
    console.log('\nExploits:');
    alert.exploits.forEach((exploit: any, idx: number) => {
      console.log(`  ${idx + 1}. ${exploit.exploit_type} - ${exploit.severity}`);
      console.log(`     ${exploit.description}`);
    });
  }

  console.log('='.repeat(60) + '\n');

  // Process the alert (send notification, log to database, etc.)
  processAlert(alert);

  // Respond with 200 OK
  res.status(200).json({ received: true });
});

async function processAlert(alert: any) {
  // Example: Send to different channels based on severity
  if (alert.riskScore >= 80) {
    await sendPagerDutyAlert(alert);
    await sendSlackAlert(alert, '#critical-alerts');
    await logToDatabase(alert);
  } else if (alert.riskScore >= 60) {
    await sendSlackAlert(alert, '#security-alerts');
    await logToDatabase(alert);
  } else {
    await logToDatabase(alert);
  }
}

async function sendPagerDutyAlert(alert: any) {
  console.log('  → Sending PagerDuty alert');
  // Implement PagerDuty integration
}

async function sendSlackAlert(alert: any, channel: string) {
  console.log(`  → Sending Slack alert to ${channel}`);
  // Implement Slack integration
}

async function logToDatabase(alert: any) {
  console.log('  → Logging to database');
  // Implement database logging
}

// Start webhook server
app.listen(PORT, async () => {
  console.log(`Webhook server listening on port ${PORT}`);
  console.log(`Webhook URL: ${WEBHOOK_URL}\n`);

  // Example: Start monitoring with webhook
  console.log('Starting address monitoring with webhook...\n');

  try {
    const monitor = await client.monitorAddress({
      address: 'your-solana-address-here',
      network: 'mainnet-beta',
      webhookUrl: WEBHOOK_URL,
    });

    console.log(`Monitor ID: ${monitor.monitorId}`);
    console.log(`Status: ${monitor.status}`);
    console.log('\nWaiting for alerts...\n');
  } catch (error: any) {
    console.error('Error starting monitor:', error.message);
  }
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\nShutting down webhook server...');
  process.exit(0);
});

