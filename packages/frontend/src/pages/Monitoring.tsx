import { useState } from 'react';
import { Bell, AlertCircle } from 'lucide-react';
import { useDynamo } from '../contexts/DynamoContext';
import { formatDistance } from 'date-fns';

function Monitoring() {
  const { client, alerts } = useDynamo();
  const [address, setAddress] = useState('');
  const [network, setNetwork] = useState<'mainnet-beta' | 'devnet' | 'testnet'>('mainnet-beta');
  const [webhookUrl, setWebhookUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const handleStartMonitoring = async () => {
    if (!address.trim()) {
      setError('Please enter an address');
      return;
    }

    setLoading(true);
    setError(null);
    setSuccess(null);

    try {
      const result = await client.monitorAddress({
        address,
        network,
        webhookUrl: webhookUrl || undefined,
      });

      setSuccess(`Monitoring started successfully. Monitor ID: ${result.monitorId}`);
      setAddress('');
      setWebhookUrl('');
    } catch (err: any) {
      setError(err.response?.data?.error || err.message || 'Failed to start monitoring');
    } finally {
      setLoading(false);
    }
  };

  const getSeverityBadge = (riskScore: number) => {
    if (riskScore >= 80) return 'badge-critical';
    if (riskScore >= 60) return 'badge-high';
    if (riskScore >= 40) return 'badge-medium';
    return 'badge-low';
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white">Address Monitoring</h1>
        <p className="mt-2 text-slate-400">Monitor addresses for suspicious activity in real-time</p>
      </div>

      <div className="card p-6">
        <h2 className="text-xl font-semibold text-white mb-4">Start New Monitor</h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Address to Monitor
            </label>
            <input
              type="text"
              className="input"
              placeholder="Enter Solana address..."
              value={address}
              onChange={(e) => setAddress(e.target.value)}
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">Network</label>
            <select
              className="input"
              value={network}
              onChange={(e) => setNetwork(e.target.value as any)}
            >
              <option value="mainnet-beta">Mainnet Beta</option>
              <option value="devnet">Devnet</option>
              <option value="testnet">Testnet</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Webhook URL (Optional)
            </label>
            <input
              type="url"
              className="input"
              placeholder="https://your-server.com/webhook"
              value={webhookUrl}
              onChange={(e) => setWebhookUrl(e.target.value)}
            />
          </div>

          <button
            onClick={handleStartMonitoring}
            disabled={loading}
            className="btn btn-primary w-full flex items-center justify-center"
          >
            <Bell className="w-4 h-4 mr-2" />
            {loading ? 'Starting...' : 'Start Monitoring'}
          </button>
        </div>
      </div>

      {error && (
        <div className="card p-4 bg-danger-500/10 border-danger-500">
          <div className="flex items-center space-x-2">
            <AlertCircle className="w-5 h-5 text-danger-500" />
            <span className="text-danger-500">{error}</span>
          </div>
        </div>
      )}

      {success && (
        <div className="card p-4 bg-success-500/10 border-success-500">
          <div className="flex items-center space-x-2">
            <Bell className="w-5 h-5 text-success-500" />
            <span className="text-success-500">{success}</span>
          </div>
        </div>
      )}

      <div className="card p-6">
        <h2 className="text-xl font-semibold text-white mb-4">Security Alerts</h2>
        <div className="space-y-3 max-h-[600px] overflow-y-auto">
          {alerts.map((alert, idx) => (
            <div key={idx} className="p-4 bg-slate-700/50 rounded-lg">
              <div className="flex items-start justify-between mb-2">
                <div>
                  <p className="font-semibold text-white">{alert.message}</p>
                  <p className="text-sm text-slate-400 mt-1">
                    Address: {alert.address.slice(0, 8)}...{alert.address.slice(-8)}
                  </p>
                </div>
                <span className={`badge ${getSeverityBadge(alert.riskScore)}`}>
                  Risk: {alert.riskScore}
                </span>
              </div>

              {alert.exploits.length > 0 && (
                <div className="mt-3 space-y-1">
                  <p className="text-xs text-slate-400">Detected Exploits:</p>
                  {alert.exploits.slice(0, 3).map((exploit, eIdx) => (
                    <div key={eIdx} className="flex items-center space-x-2">
                      <span className={`badge badge-${exploit.severity} text-xs`}>
                        {exploit.severity}
                      </span>
                      <span className="text-xs text-slate-300">{exploit.exploit_type}</span>
                    </div>
                  ))}
                </div>
              )}

              <p className="text-xs text-slate-400 mt-2">
                {formatDistance(new Date(alert.timestamp), new Date(), { addSuffix: true })}
              </p>
            </div>
          ))}

          {alerts.length === 0 && (
            <p className="text-slate-400 text-center py-8">No alerts yet</p>
          )}
        </div>
      </div>
    </div>
  );
}

export default Monitoring;

