import React, { useState, useRef } from "react";
import { Shield, LayoutDashboard, Bell, AlertTriangle, Activity, Ban, ScanLine, Network as NetworkIcon, FileText, Settings as SettingsIcon, Users as UsersIcon, FileDigit, LogOut, ChevronDown } from "lucide-react";
import Overview from "../pages/Overview";
import Alerts from "../pages/Alerts";
import Detections from "../pages/Detections";
import Network from "../pages/Network";
import Reports from "../pages/Reports";
import Settings from "../pages/Settings";
import Users from "../pages/Users";
import Logs from "../pages/Logs";

import { io } from "socket.io-client";

export default function Home({ user, onLogout }) {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [livePackets, setLivePackets] = useState([]);
  const [liveAlerts, setLiveAlerts] = useState([]);
  const [stats, setStats] = useState({
    totalAnalyzed: 0,
    threatsFound: 0,
    blocked: 0,
    monitoredHosts: 0
  });
  const alertCounterRef = useRef(0);

  React.useEffect(() => {
    fetch('http://localhost:5000/api/stats')
      .then(res => res.json())
      .then(data => {
        if (data.threatsFound) {
          setStats(s => ({ ...s, threatsFound: data.threatsFound }));
          alertCounterRef.current = data.threatsFound;
        }
      })
      .catch(err => console.error(err));

    const socket = io("http://localhost:5000");
    const hostsSet = new Set();
    
    socket.on("packet_update", (data) => {
      hostsSet.add(data.src);
      hostsSet.add(data.dst);

      setStats(prev => {
        let newThreats = prev.threatsFound;
        let newBlocked = prev.blocked;
        if (data.verdict !== "Normal") {
          newThreats++;
          if (data.sev === "High" || data.sev === "Critical") newBlocked++;
        }
        return {
          totalAnalyzed: prev.totalAnalyzed + 1,
          threatsFound: newThreats,
          blocked: newBlocked,
          monitoredHosts: hostsSet.size
        };
      });

      const newPacket = {
        id: data.id || Math.random().toString(36).substr(2, 9),
        time: new Date(data.timestamp),
        src: data.src,
        dst: data.dst,
        proto: data.proto,
        size: data.length,
        flags: "...",
        sev: data.sev,
        type: data.type || data.verdict,
        verdict: data.verdict || data.type
      };

      setLivePackets(prev => [newPacket, ...prev].slice(0, 50));

      if (data.verdict !== "Normal" && data.type !== "Normal") {
        alertCounterRef.current += 1;
        const formattedId = `ALT-${String(alertCounterRef.current).padStart(4, '0')}`;
        
        const attackType = data.type || data.verdict || 'Unknown Threat';
        let severity = data.sev;
        if (!severity) {
            if (['Dos/DDos', 'Infiltration', 'Botnet ARES'].includes(attackType)) {
                severity = 'Critical';
            } else if (['Web Attack', 'Brute Force'].includes(attackType)) {
                severity = 'High';
            } else if (['PortScan'].includes(attackType)) {
                severity = 'Medium';
            } else {
                severity = 'Low';
            }
        }

        const newAlert = {
          id: formattedId,
          time: new Date(data.timestamp).toLocaleString(),
          type: attackType,
          severity: severity,
          srcIp: data.src,
          destIp: data.dst,
        };
        setLiveAlerts(prev => [newAlert, ...prev].slice(0, 100));
      }
    });

    return () => socket.disconnect();
  }, []);

  return (
    <div className="dash-root">
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

        .dash-root {
          font-family: 'Inter', sans-serif;
          display: flex;
          height: 100vh;
          background: #f1f5f9;
          overflow: hidden;
          color: #0f172a;
        }

        /* Sidebar */
        .sidebar {
          width: 260px;
          background: #0f172a;
          color: #94a3b8;
          display: flex;
          flex-direction: column;
          border-right: 1px solid #1e293b;
        }

        .sidebar-brand {
          padding: 24px;
          display: flex;
          align-items: center;
          gap: 12px;
          color: white;
          border-bottom: 1px solid rgba(255,255,255,0.05);
        }

        .sidebar-brand-text {
          font-weight: 600;
          font-size: 18px;
          letter-spacing: 0.5px;
          display: flex;
          flex-direction: column;
        }
        .sidebar-brand-sub {
          font-size: 11px;
          color: #38bdf8;
          text-transform: uppercase;
          letter-spacing: 1px;
          font-weight: 700;
          margin-top: 2px;
        }

        .nav-list {
          padding: 20px 12px;
          display: flex;
          flex-direction: column;
          gap: 4px;
          flex: 1;
        }

        .nav-item {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 12px 16px;
          border-radius: 8px;
          cursor: pointer;
          transition: all 0.2s;
          font-size: 14px;
          font-weight: 500;
        }

        .nav-item:hover {
          background: rgba(255,255,255,0.05);
          color: white;
        }

        .nav-item.active {
          background: #2563eb;
          color: white;
        }

        .sidebar-footer {
          padding: 20px;
          border-top: 1px solid rgba(255,255,255,0.05);
          display: flex;
          align-items: center;
          justify-content: space-between;
        }

        .sidebar-user {
          display: flex;
          align-items: center;
          gap: 10px;
        }

        .sidebar-user-avatar {
          width: 32px;
          height: 32px;
          border-radius: 50%;
          background: #1e293b;
          display: flex;
          align-items: center;
          justify-content: center;
          color: #38bdf8;
          font-weight: 600;
          font-size: 14px;
        }

        .sidebar-user-info {
          display: flex;
          flex-direction: column;
        }

        .sidebar-user-name {
          color: white;
          font-size: 13px;
          font-weight: 500;
          white-space: nowrap;
          overflow: hidden;
          text-overflow: ellipsis;
          max-width: 120px;
        }

        .sidebar-user-role {
          color: #64748b;
          font-size: 11px;
        }

        .logout-btn-icon {
          color: #64748b;
          cursor: pointer;
          transition: all 0.2s;
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 8px;
          border-radius: 6px;
        }
        .logout-btn-icon:hover { 
          color: white; 
          background: rgba(255,255,255,0.05);
        }

        /* Main Content */
        .main-content {
          flex: 1;
          display: flex;
          flex-direction: column;
          overflow-y: auto;
        }

        /* Topbar */
        .topbar {
          background: white;
          padding: 20px 32px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          border-bottom: 1px solid #e2e8f0;
          position: sticky;
          top: 0;
          z-index: 10;
        }

        .page-title h1 {
          font-size: 24px;
          font-weight: 600;
          margin: 0 0 4px 0;
          color: #0f172a;
        }
        .page-title p {
          margin: 0;
          color: #64748b;
          font-size: 14px;
        }

        .top-actions {
          display: flex;
          align-items: center;
          gap: 24px;
        }

        .date-picker {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 8px 12px;
          border: 1px solid #e2e8f0;
          border-radius: 6px;
          font-size: 13px;
          color: #475569;
          background: #f8fafc;
          cursor: pointer;
        }

        .icon-btn {
          position: relative;
          color: #64748b;
          cursor: pointer;
        }
        .icon-btn .badge {
          position: absolute;
          top: -2px; right: -2px;
          width: 8px; height: 8px;
          background: #ef4444;
          border-radius: 50%;
        }

        .user-profile {
          display: flex;
          align-items: center;
          gap: 12px;
        }
        .avatar {
          width: 36px; height: 36px;
          background: #e0e7ff;
          border-radius: 50%;
          display: flex; align-items: center; justify-content: center;
          color: #4f46e5;
          font-weight: 600;
          font-size: 14px;
        }
        .user-info { display: flex; flex-direction: column; }
        .user-name { font-size: 14px; font-weight: 600; color: #0f172a; }
        .user-role { font-size: 12px; color: #64748b; }

        /* Dashboard Grid */
        .dash-container {
          padding: 32px;
          display: flex;
          flex-direction: column;
          gap: 24px;
          max-width: 1400px;
          margin: 0 auto;
          width: 100%;
        }

        .stats-grid {
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 20px;
        }

        .stat-card {
          background: white;
          border-radius: 12px;
          padding: 20px;
          border: 1px solid #e2e8f0;
          box-shadow: 0 4px 6px -1px rgba(0,0,0,0.02);
          display: flex;
          flex-direction: column;
        }

        .stat-header {
          display: flex;
          align-items: center;
          gap: 12px;
          margin-bottom: 16px;
          color: #475569;
          font-size: 14px;
          font-weight: 500;
        }

        .stat-icon {
          width: 32px; height: 32px;
          border-radius: 8px;
          display: flex; align-items: center; justify-content: center;
        }

        .stat-icon.green { background: #dcfce7; color: #16a34a; }
        .stat-icon.red { background: #fee2e2; color: #ef4444; }
        .stat-icon.orange { background: #ffedd5; color: #f97316; }
        .stat-icon.blue { background: #dbeafe; color: #2563eb; }

        .stat-val-row {
          display: flex;
          align-items: baseline;
          gap: 12px;
        }
        .stat-val {
          font-size: 28px;
          font-weight: 700;
          color: #0f172a;
        }
        .stat-trend {
          font-size: 13px;
          font-weight: 600;
        }
        .stat-trend.up { color: #16a34a; }
        .stat-trend.down { color: #ef4444; }
        .stat-sub { font-size: 12px; color: #94a3b8; margin-top: 4px; }

        .charts-grid {
          display: grid;
          grid-template-columns: 2fr 1fr;
          gap: 24px;
        }

        .card {
          background: white;
          border-radius: 12px;
          padding: 24px;
          border: 1px solid #e2e8f0;
          box-shadow: 0 4px 6px -1px rgba(0,0,0,0.02);
        }

        .card-title {
          font-size: 16px;
          font-weight: 600;
          margin-bottom: 20px;
          color: #0f172a;
        }

        /* SVG Line Chart */
        .chart-svg { width: 100%; height: 220px; overflow: visible; }
        .chart-line-blue { fill: none; stroke: #3b82f6; stroke-width: 3; }
        .chart-line-red { fill: none; stroke: #ef4444; stroke-width: 3; }
        .chart-area-blue { fill: url(#gradBlue); }
        .chart-area-red { fill: url(#gradRed); }

        .chart-legend { display: flex; gap: 16px; font-size: 12px; color: #64748b; margin-bottom: 20px; }
        .legend-item { display: flex; align-items: center; gap: 6px; }
        .dot { width: 8px; height: 8px; border-radius: 50%; }

        /* Donut Chart */
        .donut-container { position: relative; width: 160px; height: 160px; margin: 0 auto; }
        .donut-inner { position: absolute; top: 0; left: 0; width: 100%; height: 100%; display: flex; flex-direction: column; align-items: center; justify-content: center; }
        .donut-val { font-size: 32px; font-weight: 700; color: #0f172a; line-height: 1; }
        .donut-lbl { font-size: 12px; color: #64748b; margin-top: 4px; }
        .donut-legend { margin-top: 24px; display: flex; flex-direction: column; gap: 12px; }
        .dl-item { display: flex; align-items: center; justify-content: space-between; font-size: 13px; }
        .dl-left { display: flex; align-items: center; gap: 8px; color: #475569; }

        .bottom-grid {
          display: grid;
          grid-template-columns: 2fr 1fr;
          gap: 24px;
        }

        /* Alerts List */
        .alerts-list { display: flex; flex-direction: column; gap: 16px; }
        .alert-item { display: flex; align-items: center; justify-content: space-between; padding-bottom: 16px; border-bottom: 1px solid #f1f5f9; }
        .alert-item:last-child { border: none; padding-bottom: 0; }
        .alert-left { display: flex; align-items: center; gap: 16px; }
        .alert-badge { padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: 600; width: 70px; text-align: center; }
        .alert-badge.high { background: #fee2e2; color: #ef4444; }
        .alert-badge.critical { background: #fef2f2; color: #dc2626; border: 1px solid #f87171; }
        .alert-badge.medium { background: #ffedd5; color: #f97316; }
        .alert-text { font-size: 14px; font-weight: 500; color: #0f172a; }
        .alert-sub { font-size: 13px; color: #64748b; }
        
        .view-all { font-size: 13px; color: #2563eb; font-weight: 500; cursor: pointer; float: right; margin-top: -38px; }

      `}</style>

      {/* Sidebar */}
      <div className="sidebar">
        <div className="sidebar-brand">
          <Shield size={28} color="#38bdf8" />
          <div className="sidebar-brand-text">
            NIDS COMMAND
            <span className="sidebar-brand-sub">Security Center v2.4</span>
          </div>
        </div>
        <div className="nav-list">
          <div className={`nav-item ${activeTab === 'dashboard' ? 'active' : ''}`} onClick={() => setActiveTab('dashboard')}><LayoutDashboard size={18} /> Dashboard</div>
          <div className={`nav-item ${activeTab === 'alerts' ? 'active' : ''}`} onClick={() => setActiveTab('alerts')}><Bell size={18} /> Alerts</div>
          <div className={`nav-item ${activeTab === 'detections' ? 'active' : ''}`} onClick={() => setActiveTab('detections')}><AlertTriangle size={18} /> Detections</div>
          <div className={`nav-item ${activeTab === 'network' ? 'active' : ''}`} onClick={() => setActiveTab('network')}><NetworkIcon size={18} /> Network</div>
          <div className={`nav-item ${activeTab === 'reports' ? 'active' : ''}`} onClick={() => setActiveTab('reports')}><FileText size={18} /> Reports</div>
          <div className={`nav-item ${activeTab === 'settings' ? 'active' : ''}`} onClick={() => setActiveTab('settings')}><SettingsIcon size={18} /> Settings</div>
          <div className={`nav-item ${activeTab === 'users' ? 'active' : ''}`} onClick={() => setActiveTab('users')}><UsersIcon size={18} /> Users</div>
          <div className={`nav-item ${activeTab === 'logs' ? 'active' : ''}`} onClick={() => setActiveTab('logs')}><FileDigit size={18} /> Logs</div>
        </div>
        <div className="sidebar-footer">
          <div className="sidebar-user">
            <div className="sidebar-user-avatar">{user?.firstName?.[0] || 'A'}</div>
            <div className="sidebar-user-info">
              <span className="sidebar-user-name">{user ? `${user.firstName} ${user.lastName}` : 'Admin User'}</span>
              <span className="sidebar-user-role">{user?.role || 'Administrator'}</span>
            </div>
          </div>
          <div className="logout-btn-icon" onClick={onLogout} title="Logout">
            <LogOut size={18} />
          </div>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="main-content">
        <div className="topbar">
          <div className="page-title">
            <h1>{activeTab.charAt(0).toUpperCase() + activeTab.slice(1)}</h1>
            <p>Overview of your network security</p>
          </div>
          <div className="top-actions">
            <div className="date-picker">
              May 16 - May 22, 2024 <ChevronDown size={14} />
            </div>

            <div className="user-profile">
              <div className="avatar">{user?.firstName?.[0] || 'A'}</div>
              <div className="user-info">
                <span className="user-name">{user ? `${user.firstName} ${user.lastName}` : 'Admin User'}</span>
                <span className="user-role">{user?.role || 'Administrator'}</span>
              </div>
            </div>
          </div>
        </div>

        {activeTab === 'dashboard' && <Overview stats={stats} packets={livePackets} alerts={liveAlerts} />}
        {activeTab === 'alerts' && <Alerts alerts={liveAlerts} />}
        {activeTab === 'detections' && <Detections />}
        {activeTab === 'network' && <Network />}
        {activeTab === 'reports' && <Reports />}
        {activeTab === 'settings' && <Settings />}
        {activeTab === 'users' && <Users />}
        {activeTab === 'logs' && <Logs />}
      </div>
    </div>
  );
}
