import { useState } from 'react';
import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';
import { Toaster } from './Toaster';

export default function Layout() {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div className="flex min-h-screen">
      <Sidebar collapsed={collapsed} onToggle={() => setCollapsed(c => !c)} />
      <main className={`flex-1 p-6 min-h-screen transition-all duration-200 ${collapsed ? 'ml-16' : 'ml-56'}`}>
        <Outlet />
        <Toaster />
      </main>
    </div>
  );
}
