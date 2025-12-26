import { Link, useLocation } from 'react-router-dom';
import { Activity, Shield, Search, Bell } from 'lucide-react';
import { useDynamo } from '../contexts/DynamoContext';

function Layout({ children }: { children: React.ReactNode }) {
  const location = useLocation();
  const { alerts } = useDynamo();

  const navigation = [
    { name: 'Dashboard', path: '/', icon: Activity },
    { name: 'Analyze', path: '/analyze', icon: Search },
    { name: 'Audit', path: '/audit', icon: Shield },
    { name: 'Monitor', path: '/monitor', icon: Bell },
  ];

  const unreadAlerts = alerts.filter((a) => a.riskScore > 60).length;

  return (
    <div className="min-h-screen bg-slate-900">
      <nav className="bg-slate-800 border-b border-slate-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex">
              <div className="flex-shrink-0 flex items-center">
                <Shield className="w-8 h-8 text-primary-500" />
                <span className="ml-2 text-xl font-bold text-white">Dynamo</span>
              </div>
              <div className="ml-10 flex space-x-8">
                {navigation.map((item) => {
                  const Icon = item.icon;
                  const isActive = location.pathname === item.path;
                  return (
                    <Link
                      key={item.path}
                      to={item.path}
                      className={`inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium ${
                        isActive
                          ? 'border-primary-500 text-white'
                          : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-600'
                      }`}
                    >
                      <Icon className="w-4 h-4 mr-2" />
                      {item.name}
                      {item.path === '/monitor' && unreadAlerts > 0 && (
                        <span className="ml-2 badge badge-critical">{unreadAlerts}</span>
                      )}
                    </Link>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {children}
      </main>
    </div>
  );
}

export default Layout;

