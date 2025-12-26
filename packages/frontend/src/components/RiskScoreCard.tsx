import { AlertTriangle, Shield, CheckCircle } from 'lucide-react';

interface RiskScoreCardProps {
  score: number;
}

function RiskScoreCard({ score }: RiskScoreCardProps) {
  const getRiskLevel = () => {
    if (score >= 80) return { label: 'Critical', color: 'text-danger-500', bg: 'bg-danger-500', Icon: AlertTriangle };
    if (score >= 60) return { label: 'High', color: 'text-warning-500', bg: 'bg-warning-500', Icon: AlertTriangle };
    if (score >= 40) return { label: 'Medium', color: 'text-yellow-500', bg: 'bg-yellow-500', Icon: Shield };
    return { label: 'Low', color: 'text-success-500', bg: 'bg-success-500', Icon: CheckCircle };
  };

  const risk = getRiskLevel();
  const Icon = risk.Icon;

  return (
    <div className="card p-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold text-white mb-2">Risk Assessment</h2>
          <div className="flex items-center space-x-3">
            <div className={`${risk.color} bg-opacity-10 p-3 rounded-lg`}>
              <Icon className={`w-8 h-8 ${risk.color}`} />
            </div>
            <div>
              <p className="text-4xl font-bold text-white">{score.toFixed(1)}</p>
              <p className={`text-sm font-medium ${risk.color}`}>{risk.label} Risk</p>
            </div>
          </div>
        </div>

        <div className="w-32 h-32">
          <svg viewBox="0 0 100 100" className="transform -rotate-90">
            <circle
              cx="50"
              cy="50"
              r="40"
              fill="none"
              stroke="#334155"
              strokeWidth="8"
            />
            <circle
              cx="50"
              cy="50"
              r="40"
              fill="none"
              stroke="currentColor"
              strokeWidth="8"
              strokeDasharray={`${score * 2.51} 251`}
              className={risk.color}
              strokeLinecap="round"
            />
          </svg>
        </div>
      </div>
    </div>
  );
}

export default RiskScoreCard;

