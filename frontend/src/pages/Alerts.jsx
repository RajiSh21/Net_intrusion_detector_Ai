import React from 'react';

export default function Alerts({ alerts }) {
  const getBadgeStyle = (sev) => {
    const s = (sev || 'High').toLowerCase();
    if (s === 'critical' || s === 'high') {
      return { bg: 'var(--bg-danger)', text: 'var(--text-danger)' };
    } else if (s === 'medium') {
      return { bg: 'var(--bg-warning)', text: 'var(--text-warning)' };
    } else {
      return { bg: 'var(--surface-1)', text: 'var(--text-secondary)' };
    }
  };

  return (
    <div style={{ animation: "fadeIn 0.3s ease" }}>
      <p style={{ fontSize: "16px", fontWeight: "500", margin: "0 0 2px" }}>Live alerts</p>
      <p style={{ fontSize: "12px", color: "var(--text-secondary)", margin: "0 0 16px" }}>{alerts.length} active, streaming from alerts.db</p>
      
      <div className="card-anim" style={{ display: "flex", flexDirection: "column", gap: "8px", background: "var(--surface-1)", padding: "1.25rem", borderRadius: "12px", border: "1px solid var(--border)" }}>
        {alerts.map((alert, i) => {
          const style = getBadgeStyle(alert.severity);
          return (
            <div key={i} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 16px", background: style.bg, borderRadius: "8px", border: "1px solid rgba(0,0,0,0.02)" }}>
              <span style={{ fontSize: "14px", fontWeight: "500", color: style.text }}>{alert.type} <span style={{ color: "var(--text-secondary)", fontWeight: "400" }}>— {alert.srcIp} to {alert.destIp}</span></span>
              <span style={{ fontSize: "12px", color: style.text, fontWeight: "500" }}>{(alert.severity || 'high').toUpperCase()} · {alert.time}</span>
            </div>
          );
        })}
        {alerts.length === 0 && (
          <div style={{ padding: "16px", background: "var(--surface-1)", borderRadius: "var(--radius)", textAlign: "center" }}>
            <span style={{ fontSize: "14px", color: "var(--text-secondary)" }}>No active alerts.</span>
          </div>
        )}
      </div>
    </div>
  );
}
