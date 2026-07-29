import React, { useState, useEffect } from "react";
import { Shield, AlertTriangle, Ban, Activity } from "lucide-react";
import { io } from "socket.io-client";

// Real-time packet table logic driven by websockets

export default function Overview() {
  const [packets, setPackets] = useState([]);
  const [totalAnalyzed, setTotalAnalyzed] = useState(0);
  const [threatsFound, setThreatsFound] = useState(0);
  const [blocked, setBlocked] = useState(0);
  const [monitoredHosts, setMonitoredHosts] = useState(0);
  const [recentAlerts, setRecentAlerts] = useState([]);
  const hostsSet = new Set();

  useEffect(() => {
    // Fetch initial total alerts from SQLite DB
    fetch('http://localhost:5000/api/stats')
      .then(res => res.json())
      .then(data => {
        if (data.threatsFound) setThreatsFound(data.threatsFound);
      })
      .catch(err => console.error(err));

    const socket = io("http://localhost:5000");
    socket.on("connect", () => console.log("Overview: Connected to API Server for live stream"));
    
    socket.on("packet_update", (data) => {
      setTotalAnalyzed(prev => prev + 1);
      
      hostsSet.add(data.src);
      hostsSet.add(data.dst);
      setMonitoredHosts(hostsSet.size);

      const newPacket = {
        id: data.id || Math.random().toString(36).substr(2, 9),
        time: new Date(data.timestamp),
        src: data.src,
        dst: data.dst,
        proto: data.proto,
        size: data.length,
        flags: "...", // Dynamic flags not strictly needed
        sev: data.sev,
        type: data.type || data.verdict,
        verdict: data.verdict || data.type
      };

      setPackets(prev => [newPacket, ...prev].slice(0, 50));

      if (data.verdict !== "Normal") {
        setThreatsFound(prev => prev + 1);
        if (data.sev === "High" || data.sev === "Critical") setBlocked(prev => prev + 1);
        
        setRecentAlerts(prev => {
          const alert = { sev: data.sev, type: data.type, src: data.src, time: 'Just now' };
          return [alert, ...prev].slice(0, 4);
        });
      }
    });

    return () => {
      socket.disconnect();
    };
  }, []);

  return (
    <div className="dash-container">
      {/* Top Stats */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-header">
            <div className="stat-icon green"><Shield size={18} /></div>
            Total Alerts
          </div>
          <div className="stat-val-row">
            <span className="stat-val">{totalAnalyzed}</span>
            <span className="stat-trend down">↓ 12%</span>
          </div>
          <div className="stat-sub">vs last 7 days</div>
        </div>
        <div className="stat-card">
          <div className="stat-header">
            <div className="stat-icon red"><AlertTriangle size={18} /></div>
            Critical Alerts
          </div>
          <div className="stat-val-row">
            <span className="stat-val">{threatsFound}</span>
            <span className="stat-trend down">↑ 75%</span>
          </div>
          <div className="stat-sub">vs last 7 days</div>
        </div>
        <div className="stat-card">
          <div className="stat-header">
            <div className="stat-icon orange"><Ban size={18} /></div>
            Blocked Attacks
          </div>
          <div className="stat-val-row">
            <span className="stat-val">{blocked}</span>
            <span className="stat-trend up">↑ 20%</span>
          </div>
          <div className="stat-sub">vs last 7 days</div>
        </div>
        <div className="stat-card">
          <div className="stat-header">
            <div className="stat-icon blue"><Activity size={18} /></div>
            Monitored Hosts
          </div>
          <div className="stat-val-row">
            <span className="stat-val">{monitoredHosts}</span>
            <span className="stat-trend up">↑ 5%</span>
          </div>
          <div className="stat-sub">vs last 7 days</div>
        </div>
      </div>

      {/* Charts Row */}
      <div className="charts-grid">
        <div className="card">
          <div className="card-title">Intrusion Detections Over Time</div>
          <div className="chart-legend">
            <div className="legend-item"><div className="dot" style={{background: '#3b82f6'}}></div> Detected</div>
            <div className="legend-item"><div className="dot" style={{background: '#ef4444'}}></div> Blocked</div>
          </div>
          
          <svg className="chart-svg" viewBox="0 0 800 200" preserveAspectRatio="none">
            <defs>
              <linearGradient id="gradBlue" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.2"/>
                <stop offset="100%" stopColor="#3b82f6" stopOpacity="0"/>
              </linearGradient>
              <linearGradient id="gradRed" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#ef4444" stopOpacity="0.15"/>
                <stop offset="100%" stopColor="#ef4444" stopOpacity="0"/>
              </linearGradient>
            </defs>
            
            {[0, 50, 100, 150, 200].map(y => (
              <g key={y}>
                <line x1="40" y1={y} x2="800" y2={y} stroke="#f1f5f9" strokeWidth="1" />
                <text x="30" y={y + 4} fontSize="11" fill="#94a3b8" textAnchor="end">{100 - (y/2)}</text>
              </g>
            ))}
            
            <path d="M 40 120 L 140 140 L 240 100 L 340 150 L 440 110 L 540 140 L 640 110 L 740 150 L 800 130" className="chart-line-blue" />
            <path d="M 40 120 L 140 140 L 240 100 L 340 150 L 440 110 L 540 140 L 640 110 L 740 150 L 800 130 L 800 200 L 40 200 Z" className="chart-area-blue" />
            
            <path d="M 40 160 L 140 170 L 240 150 L 340 180 L 440 160 L 540 170 L 640 140 L 740 170 L 800 150" className="chart-line-red" />
            <path d="M 40 160 L 140 170 L 240 150 L 340 180 L 440 160 L 540 170 L 640 140 L 740 170 L 800 150 L 800 200 L 40 200 Z" className="chart-area-red" />
            
            {['May 16', 'May 17', 'May 18', 'May 19', 'May 20', 'May 21', 'May 22'].map((lbl, i) => (
              <text key={i} x={40 + i * (760/6)} y="220" fontSize="11" fill="#94a3b8" textAnchor="middle">{lbl}</text>
            ))}
          </svg>
        </div>
        
        <div className="card">
          <div className="card-title">Threat Types</div>
          <div className="donut-container">
            <svg viewBox="0 0 36 36" style={{width: '100%', height: '100%', transform: 'rotate(-90deg)'}}>
              <circle cx="18" cy="18" r="15.915" fill="transparent" stroke="#3b82f6" strokeWidth="6" strokeDasharray="40 60" />
              <circle cx="18" cy="18" r="15.915" fill="transparent" stroke="#ef4444" strokeWidth="6" strokeDasharray="25 75" strokeDashoffset="-40" />
              <circle cx="18" cy="18" r="15.915" fill="transparent" stroke="#f97316" strokeWidth="6" strokeDasharray="15 85" strokeDashoffset="-65" />
              <circle cx="18" cy="18" r="15.915" fill="transparent" stroke="#eab308" strokeWidth="6" strokeDasharray="10 90" strokeDashoffset="-80" />
              <circle cx="18" cy="18" r="15.915" fill="transparent" stroke="#8b5cf6" strokeWidth="6" strokeDasharray="10 90" strokeDashoffset="-90" />
            </svg>
            <div className="donut-inner">
              <span className="donut-val">{threatsFound}</span>
              <span className="donut-lbl">Total</span>
            </div>
          </div>
          <div className="donut-legend">
            <div className="dl-item"><div className="dl-left"><div className="dot" style={{background:'#3b82f6'}}></div> DoS</div> <span>40%</span></div>
            <div className="dl-item"><div className="dl-left"><div className="dot" style={{background:'#ef4444'}}></div> Port Scan</div> <span>25%</span></div>
            <div className="dl-item"><div className="dl-left"><div className="dot" style={{background:'#f97316'}}></div> Brute Force</div> <span>15%</span></div>
            <div className="dl-item"><div className="dl-left"><div className="dot" style={{background:'#eab308'}}></div> Web Attacks</div> <span>10%</span></div>
            <div className="dl-item"><div className="dl-left"><div className="dot" style={{background:'#8b5cf6'}}></div> Others</div> <span>10%</span></div>
          </div>
        </div>
      </div>

      {/* Bottom Row */}
      <div className="bottom-grid">
        <div className="card">
          <div className="card-title">Recent Alerts</div>
          <div className="view-all">View All</div>
          <div className="alerts-list">
            {recentAlerts.map((alert, i) => (
              <div className="alert-item" key={i}>
                <div className="alert-left">
                  <div className={`alert-badge ${(alert.sev || 'High').toLowerCase()}`}>{alert.sev || 'High'}</div>
                  <div className="alert-text">{alert.type || alert.verdict || 'Alert'} from <span style={{color: '#64748b'}}>{alert.src}</span></div>
                </div>
                <div className="alert-sub">{alert.time}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="card-title">Network Status</div>
          <div style={{display: 'flex', alignItems: 'center', gap: '30px', marginTop: '20px'}}>
            <div className="donut-container" style={{width: '120px', height: '120px'}}>
              <svg viewBox="0 0 36 36" style={{width: '100%', height: '100%', transform: 'rotate(-90deg)'}}>
                <circle cx="18" cy="18" r="15.915" fill="transparent" stroke="#22c55e" strokeWidth="6" strokeDasharray="85 15" />
                <circle cx="18" cy="18" r="15.915" fill="transparent" stroke="#ef4444" strokeWidth="6" strokeDasharray="15 85" strokeDashoffset="-85" />
              </svg>
              <div className="donut-inner">
                <span className="donut-val" style={{fontSize: '24px'}}>85%</span>
                <span className="donut-lbl" style={{fontSize: '10px'}}>Secure</span>
              </div>
            </div>
            <div style={{display: 'flex', flexDirection: 'column', gap: '16px', flex: 1}}>
              <div className="dl-item"><div className="dl-left"><div className="dot" style={{background:'#22c55e'}}></div> <span style={{fontSize: '12px'}}>24 Hosts Online</span></div></div>
              <div className="dl-item"><div className="dl-left"><div className="dot" style={{background:'#eab308'}}></div> <span style={{fontSize: '12px'}}>3 Suspicious</span></div></div>
              <div className="dl-item"><div className="dl-left"><div className="dot" style={{background:'#ef4444'}}></div> <span style={{fontSize: '12px'}}>1 Blocked</span></div></div>
              <div className="view-all" style={{float:'left', marginTop:'4px'}}>View Details</div>
            </div>
          </div>
        </div>
      </div>

      {/* Live Packets Table */}
      <div className="card" style={{ marginTop: '24px' }}>
        <div className="card-title">Live Network Traffic</div>
        <div style={{ overflowX: 'auto', marginTop: '16px' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px', textAlign: 'left' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #e2e8f0', color: '#64748b' }}>
                <th style={{ padding: '12px 8px' }}>Time</th>
                <th style={{ padding: '12px 8px' }}>Source IP</th>
                <th style={{ padding: '12px 8px' }}>Dest IP</th>
                <th style={{ padding: '12px 8px' }}>Protocol</th>
                <th style={{ padding: '12px 8px' }}>Length</th>
                <th style={{ padding: '12px 8px' }}>Verdict</th>
              </tr>
            </thead>
            <tbody>
              {packets.slice(0, 15).map((pkt, i) => (
                <tr key={i} style={{ borderBottom: '1px solid #f1f5f9' }}>
                  <td style={{ padding: '12px 8px', color: '#64748b' }}>{pkt.time instanceof Date && !isNaN(pkt.time.getTime()) ? pkt.time.toLocaleTimeString() : 'Just now'}</td>
                  <td style={{ padding: '12px 8px', fontWeight: 500 }}>{pkt.src}</td>
                  <td style={{ padding: '12px 8px', fontWeight: 500 }}>{pkt.dst}</td>
                  <td style={{ padding: '12px 8px' }}>{pkt.proto}</td>
                  <td style={{ padding: '12px 8px' }}>{pkt.size}</td>
                  <td style={{ padding: '12px 8px' }}>
                    <span style={{ 
                      padding: '4px 8px', 
                      borderRadius: '4px', 
                      backgroundColor: (pkt.verdict === 'Normal' || pkt.type === 'Normal') ? '#dcfce7' : '#fee2e2',
                      color: (pkt.verdict === 'Normal' || pkt.type === 'Normal') ? '#16a34a' : '#ef4444',
                      fontWeight: 500,
                      fontSize: '11px'
                    }}>
                      {pkt.verdict || pkt.type}
                    </span>
                  </td>
                </tr>
              ))}
              {packets.length === 0 && (
                <tr>
                  <td colSpan="6" style={{ padding: '24px', textAlign: 'center', color: '#94a3b8' }}>Waiting for live network traffic...</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
