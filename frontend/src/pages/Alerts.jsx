import React, { useState } from 'react';
import { Search, Filter, AlertTriangle, ChevronDown } from 'lucide-react';

const MOCK_ALERTS = Array.from({ length: 25 }, (_, i) => ({
  id: `ALT-${1000 + i}`,
  time: new Date(Date.now() - Math.floor(Math.random() * 10000000)).toLocaleString(),
  type: ['DoS Attack', 'Port Scan', 'SQL Injection', 'Brute Force', 'Malware Signature'][Math.floor(Math.random() * 5)],
  severity: ['Critical', 'High', 'Medium', 'Low'][Math.floor(Math.random() * 4)],
  srcIp: `192.168.1.${Math.floor(Math.random() * 255)}`,
  destIp: `10.0.0.${Math.floor(Math.random() * 255)}`,
  status: ['Open', 'Investigating', 'Resolved'][Math.floor(Math.random() * 3)],
}));

export default function Alerts() {
  const [searchTerm, setSearchTerm] = useState('');

  const filteredAlerts = MOCK_ALERTS.filter(a => 
    a.type.toLowerCase().includes(searchTerm.toLowerCase()) || 
    a.srcIp.includes(searchTerm)
  );

  const getBadgeClass = (sev) => {
    switch (sev) {
      case 'Critical': return 'alert-badge critical';
      case 'High': return 'alert-badge high';
      case 'Medium': return 'alert-badge medium';
      default: return 'alert-badge low';
    }
  };

  return (
    <div className="dash-container">
      <div className="card" style={{ padding: '32px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
          <div>
            <h2 style={{ fontSize: '20px', fontWeight: '600', margin: '0 0 8px 0', color: '#0f172a' }}>Network Alerts</h2>
            <p style={{ margin: 0, color: '#64748b', fontSize: '14px' }}>Review and manage security incidents.</p>
          </div>
          
          <div style={{ display: 'flex', gap: '12px' }}>
            <div style={{ position: 'relative' }}>
              <Search size={16} color="#94a3b8" style={{ position: 'absolute', left: '12px', top: '10px' }} />
              <input 
                type="text" 
                placeholder="Search alerts..." 
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                style={{
                  padding: '8px 16px 8px 36px',
                  border: '1px solid #e2e8f0',
                  borderRadius: '6px',
                  outline: 'none',
                  fontSize: '13px',
                  width: '250px'
                }}
              />
            </div>
            <button style={{
              display: 'flex', alignItems: 'center', gap: '8px', padding: '8px 16px',
              background: 'white', border: '1px solid #e2e8f0', borderRadius: '6px',
              fontSize: '13px', color: '#475569', cursor: 'pointer', fontWeight: '500'
            }}>
              <Filter size={16} /> Filter <ChevronDown size={14} />
            </button>
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '14px' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #e2e8f0', color: '#64748b' }}>
                <th style={{ padding: '16px 12px', fontWeight: '500' }}>Alert ID</th>
                <th style={{ padding: '16px 12px', fontWeight: '500' }}>Timestamp</th>
                <th style={{ padding: '16px 12px', fontWeight: '500' }}>Severity</th>
                <th style={{ padding: '16px 12px', fontWeight: '500' }}>Threat Type</th>
                <th style={{ padding: '16px 12px', fontWeight: '500' }}>Source IP</th>
                <th style={{ padding: '16px 12px', fontWeight: '500' }}>Destination IP</th>
                <th style={{ padding: '16px 12px', fontWeight: '500' }}>Status</th>
              </tr>
            </thead>
            <tbody>
              {filteredAlerts.map((alert, i) => (
                <tr key={i} style={{ borderBottom: '1px solid #f1f5f9', color: '#0f172a' }}>
                  <td style={{ padding: '16px 12px', fontWeight: '500', color: '#2563eb' }}>{alert.id}</td>
                  <td style={{ padding: '16px 12px', color: '#64748b' }}>{alert.time}</td>
                  <td style={{ padding: '16px 12px' }}>
                    <span className={getBadgeClass(alert.severity)} style={{ display: 'inline-block', width: '70px', textAlign: 'center' }}>
                      {alert.severity}
                    </span>
                  </td>
                  <td style={{ padding: '16px 12px', fontWeight: '500' }}>{alert.type}</td>
                  <td style={{ padding: '16px 12px', fontFamily: 'monospace' }}>{alert.srcIp}</td>
                  <td style={{ padding: '16px 12px', fontFamily: 'monospace', color: '#64748b' }}>{alert.destIp}</td>
                  <td style={{ padding: '16px 12px' }}>
                    <span style={{ 
                      padding: '4px 10px', borderRadius: '4px', fontSize: '12px', fontWeight: '600',
                      background: alert.status === 'Open' ? '#fee2e2' : alert.status === 'Investigating' ? '#fef08a' : '#dcfce7',
                      color: alert.status === 'Open' ? '#dc2626' : alert.status === 'Investigating' ? '#854d0e' : '#16a34a'
                    }}>
                      {alert.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        
        {filteredAlerts.length === 0 && (
          <div style={{ textAlign: 'center', padding: '48px', color: '#94a3b8' }}>
            <AlertTriangle size={32} style={{ margin: '0 auto 16px auto', opacity: 0.5 }} />
            <p>No alerts found matching your criteria.</p>
          </div>
        )}
        
      </div>
    </div>
  );
}
