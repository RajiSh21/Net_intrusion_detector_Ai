import React from 'react';

export default function Settings() {
  return (
    <div style={{ animation: "fadeIn 0.3s ease" }}>
      <p style={{ fontSize: "16px", fontWeight: "500", margin: "0 0 2px" }}>Admin</p>
      <p style={{ fontSize: "12px", color: "var(--text-secondary)", margin: "0 0 16px" }}>System configuration and status</p>
      
      <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
        <div className="card-anim" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 16px", background: "var(--surface-1)", borderRadius: "12px", border: "1px solid var(--border)" }}>
          <span style={{ fontSize: "14px", fontWeight: "500" }}>Active dataset: IDS2025.csv</span>
          <span style={{ fontSize: "13px", color: "var(--text-secondary)" }}>91,703 flows</span>
        </div>
        
        <div className="card-anim" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 16px", background: "var(--surface-1)", borderRadius: "12px", border: "1px solid var(--border)" }}>
          <span style={{ fontSize: "14px", fontWeight: "500" }}>Model version</span>
          <span style={{ fontSize: "13px", color: "var(--text-secondary)" }}>xgb_nids_engine v1</span>
        </div>
        
        <div className="card-anim" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 16px", background: "var(--surface-1)", borderRadius: "12px", border: "1px solid var(--border)" }}>
          <span style={{ fontSize: "14px", fontWeight: "500" }}>Sniffer status</span>
          <span style={{ fontSize: "13px", color: "var(--text-success)", fontWeight: "500" }}>running</span>
        </div>
        
        <div className="card-anim" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 16px", background: "var(--surface-1)", borderRadius: "12px", border: "1px solid var(--border)" }}>
          <span style={{ fontSize: "14px", fontWeight: "500" }}>Alert database</span>
          <span style={{ fontSize: "13px", color: "var(--text-secondary)" }}>alerts.db</span>
        </div>
      </div>
    </div>
  );
}
