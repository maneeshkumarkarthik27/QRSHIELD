import type { Page } from './types';
import {
  Shield,
  LayoutDashboard,
  MousePointer2,
  Link2,
  QrCode,
  Clock,
  FileSearch,
  Box,
  Sparkles,
  Settings,
} from 'lucide-react';

interface Props {
  page: Page;
  setPage: (p: Page) => void;
}

const NAV: { id: Page; label: string; icon: React.ReactNode }[] = [
  { id: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard size={18} /> },
  { id: 'cursor', label: 'Cursor Protection', icon: <MousePointer2 size={18} /> },
  { id: 'link-analyzer', label: 'Link Analyzer', icon: <Link2 size={18} /> },
  { id: 'qr-scanner', label: 'QR Scanner', icon: <QrCode size={18} /> },
  { id: 'history', label: 'Scan History', icon: <Clock size={18} /> },
  { id: 'scan-details', label: 'Scan Details', icon: <FileSearch size={18} /> },
  { id: 'sandbox-evidence', label: 'Sandbox Evidence', icon: <Box size={18} /> },
  { id: 'ai-report', label: 'AI Threat Report', icon: <Sparkles size={18} /> },
  { id: 'settings', label: 'Settings', icon: <Settings size={18} /> },
];

export default function Sidebar({ page, setPage }: Props) {
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <h1><Shield size={20} /> QRShield</h1>
        <p>Windows Link & QR Protection</p>
        <span className="sidebar-demo-badge">DEMO MODE</span>
      </div>
      <nav className="sidebar-nav">
        {NAV.map((item) => (
          <button
            key={item.id}
            className={page === item.id ? 'active' : ''}
            onClick={() => setPage(item.id)}
            aria-label={item.label}
          >
            {item.icon}
            <span>{item.label}</span>
          </button>
        ))}
      </nav>
      <div className="sidebar-footer">
        QRShield Desktop v1.0.0
      </div>
    </aside>
  );
}
