import { Link, useLocation } from 'react-router-dom';
import {
  LayoutDashboard, List, AlertTriangle, Wrench,
  FileText, Settings, Shield, ChevronLeft, ChevronRight,
  Activity
} from 'lucide-react';

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/sessions', icon: List, label: 'Sessions' },
  { to: '/findings', icon: AlertTriangle, label: 'Findings' },
  { to: '/tools', icon: Wrench, label: 'Tools' },
  { to: '/reports', icon: FileText, label: 'Reports' },
  { to: '/config', icon: Settings, label: 'Config' },
];

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
}

export default function Sidebar({ collapsed, onToggle }: SidebarProps) {
  const location = useLocation();

  return (
    <aside className={`fixed left-0 top-0 bottom-0 bg-surface border-r border-border z-50 flex flex-col transition-all duration-200 ${collapsed ? 'w-16' : 'w-56'}`}>
      <div className="flex items-center gap-3 px-4 py-5 border-b border-border">
        <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-accent to-accent2 flex items-center justify-center text-black font-bold text-sm shrink-0 shadow-lg shadow-accent/10">
          <Shield size={18} />
        </div>
        {!collapsed && (
          <div className="overflow-hidden">
            <h1 className="text-sm font-bold bg-gradient-to-r from-accent to-accent2 bg-clip-text text-transparent leading-tight">CHAI</h1>
            <span className="text-[10px] text-text3 block">Cyber Host AI v2.0</span>
          </div>
        )}
        <button onClick={onToggle} className="ml-auto text-text3 hover:text-accent p-1 transition-colors">
          {collapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
        </button>
      </div>

      <div className="px-3 py-2">
        {!collapsed && (
          <div className="text-[10px] text-text3 uppercase tracking-wider px-2 mb-1 flex items-center gap-1">
            <Activity size={10} /> Menu
          </div>
        )}
        <nav className="space-y-0.5">
          {navItems.map((item) => {
            const Icon = item.icon;
            const active = location.pathname === item.to || location.pathname.startsWith(item.to + '/');
            return (
              <Link
                key={item.to}
                to={item.to}
                className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all ${
                  active
                    ? 'text-accent bg-accent/10 border border-accent/20'
                    : 'text-text2 border border-transparent hover:text-text hover:bg-surface2'
                } ${collapsed ? 'justify-center px-0' : ''}`}
                title={collapsed ? item.label : undefined}
              >
                <Icon size={18} className={active ? 'text-accent' : 'text-text3'} />
                {!collapsed && <span>{item.label}</span>}
              </Link>
            );
          })}
        </nav>
      </div>

      <div className="flex-1" />

      <div className={`px-3 py-3 border-t border-border ${collapsed ? 'text-center px-1' : ''}`}>
        {!collapsed && (
          <div className="flex items-center gap-2 mb-2 px-2">
            <div className="w-2 h-2 rounded-full bg-success animate-pulse" />
            <span className="text-[10px] text-text3">System Online</span>
          </div>
        )}
        <div className={`text-[10px] text-text3 ${collapsed ? 'text-center' : 'px-2'}`}>
          {collapsed ? 'v2.0' : 'CHAI v2.0.0 — MCP Server'}
        </div>
      </div>
    </aside>
  );
}
