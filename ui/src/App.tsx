import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import Sessions from './pages/Sessions';
import NewSession from './pages/NewSession';
import SessionDetail from './pages/SessionDetail';
import Findings from './pages/Findings';
import Tools from './pages/Tools';
import Reports from './pages/Reports';
import Config from './pages/Config';
import { ToastProvider } from './components/Toaster';

export default function App() {
  return (
    <ToastProvider>
      <BrowserRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route path="/" element={<Dashboard />} />
            <Route path="/sessions" element={<Sessions />} />
            <Route path="/sessions/new" element={<NewSession />} />
            <Route path="/sessions/:id" element={<SessionDetail />} />
            <Route path="/findings" element={<Findings />} />
            <Route path="/tools" element={<Tools />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/config" element={<Config />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ToastProvider>
  );
}
