import React, { useState, useEffect, useRef } from 'react';
import { Search, Filter, AlertTriangle, ChevronDown } from 'lucide-react';
import { io } from 'socket.io-client';

export default function Alerts({ alerts }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('All');
  const [showFilterDropdown, setShowFilterDropdown] = useState(false);
  const filterRef = useRef(null);

  useEffect(() => {
    function handleClickOutside(event) {
      if (filterRef.current && !filterRef.current.contains(event.target)) {
        setShowFilterDropdown(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const filteredAlerts = alerts.filter(a => {
    const term = searchTerm.toLowerCase();
    const matchesSearch = 
      (a.id || '').toLowerCase().includes(term) ||
      (a.type || '').toLowerCase().includes(term) ||
      (a.srcIp || '').toLowerCase().includes(term) ||
      (a.destIp || '').toLowerCase().includes(term) ||
      (a.severity || '').toLowerCase().includes(term);
      
    const matchesSeverity = severityFilter === 'All' || a.severity === severityFilter;
    
    return matchesSearch && matchesSeverity;
  });

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
                placeholder="Search alerts (ID, IP, Type)..."
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
            <div style={{ position: 'relative' }} ref={filterRef}>
              <button 
                onClick={() => setShowFilterDropdown(!showFilterDropdown)}
                style={{
                  display: 'flex', alignItems: 'center', gap: '8px', padding: '8px 16px',
                  background: severityFilter === 'All' ? 'white' : '#e0e7ff', 
                  border: '1px solid #e2e8f0', borderRadius: '6px',
                  fontSize: '13px', color: severityFilter === 'All' ? '#475569' : '#4f46e5', 
                  cursor: 'pointer', fontWeight: '500'
                }}>
                <Filter size={16} /> {severityFilter === 'All' ? 'Filter' : severityFilter} <ChevronDown size={14} />
              </button>
              
              {showFilterDropdown && (
                <div style={{
                  position: 'absolute', top: 'calc(100% + 8px)', right: 0,
                  background: 'white', border: '1px solid #e2e8f0', borderRadius: '8px',
                  boxShadow: '0 10px 15px -3px rgba(0,0,0,0.1), 0 4px 6px -2px rgba(0,0,0,0.05)', 
                  zIndex: 9999, width: '160px', overflow: 'hidden'
                }}>
                  {['All', 'Critical', 'High', 'Medium', 'Low'].map(sev => (
                    <div 
                      key={sev}
                      onClick={() => { setSeverityFilter(sev); setShowFilterDropdown(false); }}
                      onMouseEnter={(e) => {
                        if (severityFilter !== sev) e.currentTarget.style.background = '#f8fafc';
                      }}
                      onMouseLeave={(e) => {
                        if (severityFilter !== sev) e.currentTarget.style.background = 'transparent';
                      }}
                      style={{
                        padding: '12px 16px', fontSize: '13px', cursor: 'pointer',
                        background: severityFilter === sev ? '#f1f5f9' : 'transparent',
                        borderBottom: sev !== 'Low' ? '1px solid #f1f5f9' : 'none',
                        color: severityFilter === sev ? '#0f172a' : '#475569',
                        fontWeight: severityFilter === sev ? '600' : '400',
                        transition: 'background 0.15s ease',
                        display: 'flex', justifyContent: 'space-between', alignItems: 'center'
                      }}>
                      <span>{sev}</span>
                      {severityFilter === sev && <span style={{ color: '#4f46e5', fontSize: '14px' }}>✓</span>}
                    </div>
                  ))}
                </div>
              )}
            </div>
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
