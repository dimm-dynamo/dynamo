import React, { createContext, useContext, useState, useEffect } from 'react';
import { DynamoClient, SecurityAlert } from '@dynamo/sdk';

interface DynamoContextType {
  client: DynamoClient;
  alerts: SecurityAlert[];
  addAlert: (alert: SecurityAlert) => void;
}

const DynamoContext = createContext<DynamoContextType | undefined>(undefined);

export function DynamoProvider({ children }: { children: React.ReactNode }) {
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [client] = useState(() => {
    const endpoint = import.meta.env.VITE_API_URL || 'http://localhost:4000';
    return new DynamoClient({ endpoint });
  });

  useEffect(() => {
    const unsubscribe = client.subscribeToAlerts((alert) => {
      setAlerts((prev) => [alert, ...prev].slice(0, 50));
    });

    return () => {
      unsubscribe();
      client.disconnect();
    };
  }, [client]);

  const addAlert = (alert: SecurityAlert) => {
    setAlerts((prev) => [alert, ...prev].slice(0, 50));
  };

  return (
    <DynamoContext.Provider value={{ client, alerts, addAlert }}>
      {children}
    </DynamoContext.Provider>
  );
}

export function useDynamo() {
  const context = useContext(DynamoContext);
  if (!context) {
    throw new Error('useDynamo must be used within DynamoProvider');
  }
  return context;
}

