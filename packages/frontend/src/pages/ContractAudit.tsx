import { useState } from 'react';
import { Shield, AlertCircle } from 'lucide-react';
import { useDynamo } from '../contexts/DynamoContext';
import { ContractAuditResponse } from '@dynamo/sdk';
import RiskScoreCard from '../components/RiskScoreCard';

function ContractAudit() {
  const { client } = useDynamo();
  const [programId, setProgramId] = useState('');
  const [network, setNetwork] = useState<'mainnet-beta' | 'devnet' | 'testnet'>('mainnet-beta');
  const [depth, setDepth] = useState<'shallow' | 'deep'>('shallow');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ContractAuditResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleAudit = async () => {
    if (!programId.trim()) {
      setError('Please enter a program ID');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const audit = await client.auditContract({ programId, network, depth });
      setResult(audit);
    } catch (err: any) {
      setError(err.response?.data?.error || err.message || 'Audit failed');
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-danger-500';
      case 'high': return 'text-warning-500';
      case 'medium': return 'text-yellow-500';
      case 'low': return 'text-success-500';
      default: return 'text-blue-500';
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white">Contract Audit</h1>
        <p className="mt-2 text-slate-400">Comprehensive security audit for Solana programs</p>
      </div>

      <div className="card p-6">
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Program ID
            </label>
            <input
              type="text"
              className="input"
              placeholder="Enter program ID..."
              value={programId}
              onChange={(e) => setProgramId(e.target.value)}
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
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
              <label className="block text-sm font-medium text-slate-300 mb-2">Audit Depth</label>
              <select
                className="input"
                value={depth}
                onChange={(e) => setDepth(e.target.value as any)}
              >
                <option value="shallow">Shallow</option>
                <option value="deep">Deep</option>
              </select>
            </div>
          </div>

          <button
            onClick={handleAudit}
            disabled={loading}
            className="btn btn-primary w-full flex items-center justify-center"
          >
            <Shield className="w-4 h-4 mr-2" />
            {loading ? 'Auditing...' : 'Start Audit'}
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

      {result && (
        <div className="space-y-6">
          <RiskScoreCard score={result.risk_score} />

          <div className="card p-6">
            <h2 className="text-xl font-semibold text-white mb-4">Code Quality</h2>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Overall Score:</span>
                <span className="text-2xl font-bold text-white">
                  {(result.code_quality.score * 100).toFixed(1)}%
                </span>
              </div>
              {Object.entries(result.code_quality.metrics).map(([key, value]) => (
                <div key={key} className="flex items-center justify-between">
                  <span className="text-slate-400 capitalize">{key}:</span>
                  <div className="flex items-center space-x-2">
                    <div className="w-32 h-2 bg-slate-700 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-primary-500"
                        style={{ width: `${value * 100}%` }}
                      />
                    </div>
                    <span className="text-white text-sm">{(value * 100).toFixed(0)}%</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="card p-6">
            <h2 className="text-xl font-semibold text-white mb-4">Vulnerabilities</h2>
            <div className="space-y-3">
              {result.vulnerabilities.map((vuln, idx) => (
                <div key={idx} className="p-4 bg-slate-700/50 rounded-lg">
                  <div className="flex items-start justify-between mb-2">
                    <h3 className="font-semibold text-white">{vuln.vulnerability_type}</h3>
                    <span className={`badge badge-${vuln.severity}`}>
                      {vuln.severity}
                    </span>
                  </div>
                  <p className="text-slate-300 text-sm mb-2">{vuln.description}</p>
                  <div className="flex items-center justify-between text-xs text-slate-400">
                    <span>Confidence: {(vuln.confidence * 100).toFixed(0)}%</span>
                    <span>{vuln.affected_instructions.length} instruction(s) affected</span>
                  </div>
                </div>
              ))}
              {result.vulnerabilities.length === 0 && (
                <p className="text-slate-400 text-center py-4">No vulnerabilities detected</p>
              )}
            </div>
          </div>

          <div className="card p-6">
            <h2 className="text-xl font-semibold text-white mb-4">Recommendations</h2>
            <ul className="space-y-2">
              {result.recommendations.map((rec, idx) => (
                <li key={idx} className="flex items-start space-x-2">
                  <span className="text-primary-500 mt-1">•</span>
                  <span className="text-slate-300">{rec}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}

export default ContractAudit;

