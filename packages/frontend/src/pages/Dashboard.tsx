import { useState, useEffect } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { TrendingUp, AlertTriangle, Shield, Activity } from 'lucide-react';
import { useDynamo } from '../contexts/DynamoContext';

function Dashboard() {
  const { alerts } = useDynamo();
  const [stats, setStats] = useState({
    totalAnalyses: 0,
    criticalIssues: 0,
    activeMonitors: 0,
    avgRiskScore: 0,
  });

  useEffect(() => {
    const criticalCount = alerts.filter((a) => a.riskScore >= 80).length;
    const avgRisk = alerts.length > 0
      ? alerts.reduce((sum, a) => sum + a.riskScore, 0) / alerts.length
      : 0;

    setStats({
      totalAnalyses: alerts.length,
      criticalIssues: criticalCount,
      activeMonitors: 3,
      avgRiskScore: avgRisk,
    });
  }, [alerts]);

  const severityData = [
    { name: 'Critical', count: alerts.filter((a) => a.riskScore >= 80).length },
    { name: 'High', count: alerts.filter((a) => a.riskScore >= 60 && a.riskScore < 80).length },
    { name: 'Medium', count: alerts.filter((a) => a.riskScore >= 40 && a.riskScore < 60).length },
    { name: 'Low', count: alerts.filter((a) => a.riskScore < 40).length },
  ];

  const statCards = [
    {
      title: 'Total Analyses',
      value: stats.totalAnalyses,
      icon: Activity,
      color: 'text-blue-500',
      bgColor: 'bg-blue-500/10',
    },
    {
      title: 'Critical Issues',
      value: stats.criticalIssues,
      icon: AlertTriangle,
      color: 'text-red-500',
      bgColor: 'bg-red-500/10',
    },
    {
      title: 'Active Monitors',
      value: stats.activeMonitors,
      icon: Shield,
      color: 'text-green-500',
      bgColor: 'bg-green-500/10',
    },
    {
      title: 'Avg Risk Score',
      value: stats.avgRiskScore.toFixed(1),
      icon: TrendingUp,
      color: 'text-yellow-500',
      bgColor: 'bg-yellow-500/10',
    },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white">Security Dashboard</h1>
        <p className="mt-2 text-slate-400">Real-time security monitoring and analysis</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {statCards.map((stat) => {
          const Icon = stat.icon;
          return (
            <div key={stat.title} className="card p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-slate-400 text-sm">{stat.title}</p>
                  <p className="text-3xl font-bold text-white mt-2">{stat.value}</p>
                </div>
                <div className={`${stat.bgColor} p-3 rounded-lg`}>
                  <Icon className={`w-6 h-6 ${stat.color}`} />
                </div>
              </div>
            </div>
          );
        })}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card p-6">
          <h2 className="text-xl font-semibold text-white mb-4">Severity Distribution</h2>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={severityData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="name" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#1e293b',
                  border: '1px solid #334155',
                  borderRadius: '8px',
                }}
              />
              <Bar dataKey="count" fill="#0ea5e9" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="card p-6">
          <h2 className="text-xl font-semibold text-white mb-4">Recent Alerts</h2>
          <div className="space-y-3 max-h-[300px] overflow-y-auto">
            {alerts.slice(0, 5).map((alert, idx) => (
              <div key={idx} className="flex items-start space-x-3 p-3 bg-slate-700/50 rounded-lg">
                <AlertTriangle className="w-5 h-5 text-warning-500 flex-shrink-0 mt-0.5" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-white truncate">{alert.message}</p>
                  <p className="text-xs text-slate-400 mt-1">
                    Risk Score: {alert.riskScore} • {new Date(alert.timestamp).toLocaleString()}
                  </p>
                </div>
              </div>
            ))}
            {alerts.length === 0 && (
              <p className="text-slate-400 text-center py-8">No alerts yet</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default Dashboard;

