import React, { useState, useEffect } from 'react';
import { Terminal, Download, Play, Square } from 'lucide-react';

export default function Logs() {
  const [logs, setLogs] = useState([
    '[2024-05-22 14:01:23] INFO: API Server started on port 5000',
    '[2024-05-22 14:01:23] INFO: Connecting to database schema...',
    '[2024-05-22 14:01:24] SUCCESS: Database connection established.',
    '[2024-05-22 14:01:25] INFO: Initializing ML model: Random Forest',
    '[2024-05-22 14:01:28] INFO: Loading GAN adversarial weights...',
    '[2024-05-22 14:01:30] SUCCESS: ML models loaded successfully. Memory footprint: 1.2GB',
    '[2024-05-22 14:01:35] DEBUG: WebSocket client connected (127.0.0.1)',
  ]);
  const [isPaused, setIsPaused] = useState(false);

  useEffect(() => {
    if (isPaused) return;

    const messages = [
      'DEBUG: Processing batch of 50 packets...',
      'INFO: Anomaly detected at node 192.168.1.45. Generating alert.',
      'DEBUG: Updating moving average for baseline throughput.',
      'WARN: High latency detected on interface eth0 (45ms).',
      'DEBUG: ML inference completed in 0.014ms.',
      'INFO: Syncing threat intelligence feed with central server.',
      'DEBUG: Dropping malformed packet from 10.0.0.99.'
    ];

    const interval = setInterval(() => {
      setLogs(prev => {
        const newLog = `[${new Date().toISOString().replace('T', ' ').substring(0, 19)}] ${messages[Math.floor(Math.random() * messages.length)]}`;
        const next = [...prev, newLog];
        if (next.length > 100) next.shift();
        return next;
      });
    }, 1500);

    return () => clearInterval(interval);
  }, [isPaused]);

  return (
    <div className="dash-container">
      <div className="card" style={{ padding: '32px', display: 'flex', flexDirection: 'column', height: 'calc(100vh - 160px)' }}>
        
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <Terminal size={24} color="#0f172a" />
            <div>
              <h2 style={{ fontSize: '20px', fontWeight: '600', margin: '0 0 4px 0', color: '#0f172a' }}>System Logs</h2>
              <p style={{ margin: 0, color: '#64748b', fontSize: '14px' }}>Real-time backend diagnostic output.</p>
            </div>
          </div>
          
          <div style={{ display: 'flex', gap: '12px' }}>
            <button 
              onClick={() => setIsPaused(!isPaused)}
              style={{ 
                background: 'white', color: '#475569', border: '1px solid #e2e8f0', borderRadius: '6px', 
                padding: '8px 16px', fontWeight: '500', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px'
              }}
            >
              {isPaused ? <Play size={14} color="#16a34a" /> : <Square size={14} color="#dc2626" />}
              {isPaused ? 'Resume Stream' : 'Pause Stream'}
            </button>
            <button style={{ 
              background: '#2563eb', color: 'white', border: 'none', borderRadius: '6px', 
              padding: '8px 16px', fontWeight: '500', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px'
            }}>
              <Download size={14} /> Export Log
            </button>
          </div>
        </div>

        <div style={{ 
          background: '#0f172a', flex: 1, borderRadius: '8px', padding: '24px', 
          overflowY: 'auto', fontFamily: 'monospace', fontSize: '13px', lineHeight: '1.8',
          boxShadow: 'inset 0 2px 4px rgba(0,0,0,0.2)', display: 'flex', flexDirection: 'column', gap: '4px'
        }}>
          {logs.map((log, i) => {
            let color = '#94a3b8'; // default DEBUG
            if (log.includes('INFO:')) color = '#38bdf8';
            if (log.includes('SUCCESS:')) color = '#4ade80';
            if (log.includes('WARN:')) color = '#facc15';
            if (log.includes('ERROR:')) color = '#f87171';

            return (
              <div key={i} style={{ color }}>{log}</div>
            );
          })}
        </div>
        
      </div>
    </div>
  );
}
