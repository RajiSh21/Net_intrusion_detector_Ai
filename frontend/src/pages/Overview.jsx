import React, { useState, useEffect } from "react";
import { Shield, AlertTriangle, Ban, Activity } from "lucide-react";
import { io } from "socket.io-client";

// Simulated packet generator (display-only)
const generatePacket = () => ({
  id: Math.random().toString(36).substr(2, 9),
  time: new Date(),
  src: `192.168.1.${Math.floor(Math.random() * 255)}`,
  dst: `10.0.0.${Math.floor(Math.random() * 255)}`,
  proto: ["TCP", "UDP", "ICMP"][Math.floor(Math.random() * 3)],
  size: Math.floor(Math.random() * 1500) + 64,
  flags: ["SYN", "ACK", "PSH", "FIN"][Math.floor(Math.random() * 4)],
  sev: Math.random() > 0.8 ? "High" : Math.random() > 0.5 ? "Medium" : "Low",
  type: Math.random() > 0.8 ? "DoS Attack" : Math.random() > 0.6 ? "Port Scan" : "Normal"
});

export default function Overview() {
  const [packets, setPackets] = useState([]);
  const [totalAnalyzed, setTotalAnalyzed] = useState(12543);
  const [threatsFound, setThreatsFound] = useState(128);
  const [blocked, setBlocked] = useState(56);
  const [monitoredHosts, setMonitoredHosts] = useState(24);
  const [recentAlerts, setRecentAlerts] = useState([
    { sev: 'High', type: 'DoS Attack Detected', src: '192.168.1.45', time: '2 min ago' },
    { sev: 'Critical', type: 'SQL Injection Attempt', src: '192.168.1.23', time: '5 min ago' },
    { sev: 'Medium', type: 'Port Scan Detected', src: '10.0.0.5', time: '8 min ago' },
    { sev: 'High', type: 'Brute Force Attempt', src: '192.168.1.78', time: '12 min ago' }
  ]);

  useEffect(() => {
    const socket = io("http://localhost:5000");
    socket.on("connect", () => console.log("Overview: Connected to API Server"));
    
    socket.on("analysis_result", (data) => {
      setTotalAnalyzed(prev => prev + 1);
      if (data.prediction !== "Benign") {
        setThreatsFound(prev => prev + 1);
        if (Math.random() > 0.5) setBlocked(prev => prev + 1);
      }
    });

    const interval = setInterval(() => {
      setPackets(prev => {
        const newPackets = [generatePacket(), ...prev].slice(0, 50);
        return newPackets;
      });
    }, 2000);

    return () => {
      socket.disconnect();
      clearInterval(interval);
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
                  <div className={`alert-badge ${alert.sev.toLowerCase()}`}>{alert.sev}</div>
                  <div className="alert-text">{alert.type} from <span style={{color: '#64748b'}}>{alert.src}</span></div>
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
    </div>
  );
}
