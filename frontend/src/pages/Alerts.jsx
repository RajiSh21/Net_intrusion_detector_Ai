import React, { useState } from "react";

export default function Alerts({ alerts }) {
  const [filter, setFilter] = useState('All');

  const dosCount = alerts.filter(a => a.type === 'Dos/DDos' || a.type === 'Dos/DDoS').length;
  const portScanCount = alerts.filter(a => a.type === 'PortScan').length;
  const bruteCount = alerts.filter(a => a.type === 'Brute Force').length;
  const webCount = alerts.filter(a => a.type === 'Web Attack').length;
  const otherCount = alerts.length - (dosCount + portScanCount + bruteCount + webCount);

  const filteredAlerts = alerts.filter(a => {
    if (filter === 'All') return true;
    if (filter === 'Dos/DDoS') return a.type === 'Dos/DDos' || a.type === 'Dos/DDoS';
    if (filter === 'PortScan') return a.type === 'PortScan';
    if (filter === 'Brute Force') return a.type === 'Brute Force';
    if (filter === 'Web Attack') return a.type === 'Web Attack';
    if (filter === 'Other') return !['Dos/DDos', 'Dos/DDoS', 'PortScan', 'Brute Force', 'Web Attack'].includes(a.type);
    return true;
  });

  return (
    <div className="tab-page active" id="alerts">
      <div className="page-head"><div><div className="eyebrow">MONITOR / LIVE ALERTS</div><div className="page-title">Live alerts</div></div></div>
      <div className="filter-row">
        <div className={`chip ${filter === 'All' ? 'active' : ''}`} onClick={() => setFilter('All')} style={{cursor: 'pointer'}}>All · {alerts.length}</div>
        <div className={`chip ${filter === 'Dos/DDoS' ? 'active' : ''}`} onClick={() => setFilter('Dos/DDoS')} style={{cursor: 'pointer'}}>Dos/DDoS · {dosCount}</div>
        <div className={`chip ${filter === 'PortScan' ? 'active' : ''}`} onClick={() => setFilter('PortScan')} style={{cursor: 'pointer'}}>PortScan · {portScanCount}</div>
        <div className={`chip ${filter === 'Brute Force' ? 'active' : ''}`} onClick={() => setFilter('Brute Force')} style={{cursor: 'pointer'}}>Brute Force · {bruteCount}</div>
        <div className={`chip ${filter === 'Web Attack' ? 'active' : ''}`} onClick={() => setFilter('Web Attack')} style={{cursor: 'pointer'}}>Web Attack · {webCount}</div>
        <div className={`chip ${filter === 'Other' ? 'active' : ''}`} onClick={() => setFilter('Other')} style={{cursor: 'pointer'}}>Other · {otherCount}</div>
      </div>
      <div className="panel">
        {filteredAlerts.map((a, i) => (
          <div className="alert-row" key={i}>
            <div className="alert-left">
              <div className="alert-ic">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M12 9v4M12 17h.01"/><circle cx="12" cy="12" r="9"/>
                </svg>
              </div>
              <span className="sev-chip">{a.severity ? a.severity.toUpperCase() : 'HIGH'}</span>
              <span className="alert-text"><b>{a.type}</b> <span className="arrow">{a.srcIp} → {a.destIp}</span></span>
            </div>
            <span className="alert-time">{a.time}</span>
          </div>
        ))}
        {filteredAlerts.length === 0 && (
          <div style={{padding: "20px", textAlign: "center", color: "var(--text-tertiary)"}}>
            No {filter !== 'All' ? filter.toLowerCase() : 'active'} alerts detected.
          </div>
        )}
      </div>
    </div>
  );
}
