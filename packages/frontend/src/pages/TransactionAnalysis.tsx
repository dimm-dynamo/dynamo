import { useState } from 'react';
import { Search, AlertCircle } from 'lucide-react';
import { useDynamo } from '../contexts/DynamoContext';
import { TransactionAnalysisResponse } from '@dynamo/sdk';
import ExploitList from '../components/ExploitList';
import RiskScoreCard from '../components/RiskScoreCard';

function TransactionAnalysis() {
  const { client } = useDynamo();
  const [signature, setSignature] = useState('');
  const [network, setNetwork] = useState<'mainnet-beta' | 'devnet' | 'testnet'>('mainnet-beta');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<TransactionAnalysisResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleAnalyze = async () => {
    if (!signature.trim()) {
      setError('Please enter a transaction signature');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const analysis = await client.analyzeTransaction({ signature, network });
      setResult(analysis);
    } catch (err: any) {
      setError(err.response?.data?.error || err.message || 'Analysis failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white">Transaction Analysis</h1>
        <p className="mt-2 text-slate-400">Analyze Solana transactions for security exploits</p>
      </div>

      <div className="card p-6">
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Transaction Signature
            </label>
            <input
              type="text"
              className="input"
              placeholder="Enter transaction signature..."
              value={signature}
              onChange={(e) => setSignature(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleAnalyze()}
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

          <button
            onClick={handleAnalyze}
            disabled={loading}
            className="btn btn-primary w-full flex items-center justify-center"
          >
            <Search className="w-4 h-4 mr-2" />
            {loading ? 'Analyzing...' : 'Analyze Transaction'}
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
            <h2 className="text-xl font-semibold text-white mb-4">Detected Exploits</h2>
            <ExploitList exploits={result.exploits} />
          </div>

          <div className="card p-6">
            <h2 className="text-xl font-semibold text-white mb-4">Simulation Result</h2>
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-slate-400">Status:</span>
                <span className={result.simulation_result.success ? 'text-success-500' : 'text-danger-500'}>
                  {result.simulation_result.success ? 'Success' : 'Failed'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Compute Units:</span>
                <span className="text-white">{result.simulation_result.compute_units_consumed.toLocaleString()}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Accounts Accessed:</span>
                <span className="text-white">{result.simulation_result.accounts_accessed.length}</span>
              </div>
            </div>
          </div>

          <div className="card p-6">
            <h2 className="text-xl font-semibold text-white mb-4">AI Analysis</h2>
            <div className="space-y-3">
              <div>
                <span className="text-slate-400">Confidence: </span>
                <span className="text-white">{(result.aiAnalysis.confidence * 100).toFixed(1)}%</span>
              </div>
              <div>
                <span className="text-slate-400 block mb-2">Patterns Detected:</span>
                <div className="flex flex-wrap gap-2">
                  {result.aiAnalysis.patterns.map((pattern, idx) => (
                    <span key={idx} className="badge bg-blue-500">{pattern}</span>
                  ))}
                </div>
              </div>
              <div>
                <span className="text-slate-400 block mb-2">Recommendations:</span>
                <ul className="list-disc list-inside space-y-1">
                  {result.aiAnalysis.recommendations.map((rec, idx) => (
                    <li key={idx} className="text-slate-300">{rec}</li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default TransactionAnalysis;

