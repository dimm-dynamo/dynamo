import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import TransactionAnalysis from './pages/TransactionAnalysis';
import ContractAudit from './pages/ContractAudit';
import Monitoring from './pages/Monitoring';
import { DynamoProvider } from './contexts/DynamoContext';

function App() {
  return (
    <DynamoProvider>
      <Router>
        <Layout>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/analyze" element={<TransactionAnalysis />} />
            <Route path="/audit" element={<ContractAudit />} />
            <Route path="/monitor" element={<Monitoring />} />
          </Routes>
        </Layout>
      </Router>
    </DynamoProvider>
  );
}

export default App;

