import React, { useState, useEffect } from "react";

export default function Overview({ stats, packets, alerts, modelInfo }) {
  const time = new Date().toLocaleTimeString();

  const activeAlertsCount = alerts.length;
  const totalAnalyzed = stats.totalAnalyzed || 0;
  const accuracy = modelInfo?.accuracy || '...';
  const monitoredHosts = stats.monitoredHosts || 0;

  return (
    <div style={{ animation: "fadeIn 0.3s ease" }}>
      <p style={{ fontSize: "16px", fontWeight: "500", margin: "0 0 2px" }}>Overview</p>
      <p style={{ fontSize: "12px", color: "var(--text-secondary)", margin: "0 0 16px" }}>Last updated {time}</p>
      
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: "12px", marginBottom: "16px" }}>
        <div className="card-anim" style={{ background: "var(--surface-1)", borderRadius: "var(--radius)", padding: "1.25rem", border: "1px solid var(--border)" }}>
          <p style={{ fontSize: "13px", color: "var(--text-secondary)", margin: "0 0 8px", fontWeight: "500" }}>Overall accuracy</p>
          <p style={{ fontSize: "28px", fontWeight: "600", margin: 0, letterSpacing: "-0.5px" }}>{accuracy}</p>
        </div>
        <div className="card-anim" style={{ background: "var(--surface-1)", borderRadius: "var(--radius)", padding: "1.25rem", border: "1px solid var(--border)" }}>
          <p style={{ fontSize: "13px", color: "var(--text-secondary)", margin: "0 0 8px", fontWeight: "500" }}>Active alerts</p>
          <p style={{ fontSize: "28px", fontWeight: "600", margin: 0, letterSpacing: "-0.5px", color: activeAlertsCount > 0 ? "var(--text-danger)" : "var(--text-success)" }}>{activeAlertsCount}</p>
        </div>
        <div className="card-anim" style={{ background: "var(--surface-1)", borderRadius: "var(--radius)", padding: "1.25rem", border: "1px solid var(--border)" }}>
          <p style={{ fontSize: "13px", color: "var(--text-secondary)", margin: "0 0 8px", fontWeight: "500" }}>Total Analyzed</p>
          <p style={{ fontSize: "28px", fontWeight: "600", margin: 0, letterSpacing: "-0.5px" }}>{totalAnalyzed}</p>
        </div>
        <div className="card-anim" style={{ background: "var(--surface-1)", borderRadius: "var(--radius)", padding: "1.25rem", border: "1px solid var(--border)" }}>
          <p style={{ fontSize: "13px", color: "var(--text-secondary)", margin: "0 0 8px", fontWeight: "500" }}>Monitored Hosts</p>
          <p style={{ fontSize: "28px", fontWeight: "600", margin: 0, letterSpacing: "-0.5px", color: "var(--text-accent)" }}>{monitoredHosts}</p>
        </div>
      </div>

      <div className="card-anim" style={{ background: "var(--surface-1)", borderRadius: "12px", border: "1px solid var(--border)", overflow: "hidden" }}>
        <div style={{ padding: "1.25rem 1.25rem 0.5rem" }}>
          <p style={{ fontSize: "14px", fontWeight: "500", margin: "0 0 4px" }}>Recent Traffic Log</p>
          <p style={{ fontSize: "12px", color: "var(--text-secondary)", margin: 0 }}>Latest bidirectional flows</p>
        </div>
        <table style={{ width: "100%", fontSize: "13px", borderCollapse: "collapse", tableLayout: "fixed" }}>
          <thead>
            <tr style={{ color: "var(--text-secondary)", textAlign: "left", borderBottom: "1px solid var(--border)" }}>
              <th style={{ padding: "10px 16px", fontWeight: "500" }}>Source IP</th>
              <th style={{ padding: "10px 16px", fontWeight: "500" }}>Dest IP</th>
              <th style={{ padding: "10px 16px", fontWeight: "500" }}>Port/Size</th>
              <th style={{ padding: "10px 16px", fontWeight: "500" }}>Protocol</th>
              <th style={{ padding: "10px 16px", fontWeight: "500" }}>Class</th>
              <th style={{ padding: "10px 16px", fontWeight: "500" }}>Time</th>
            </tr>
          </thead>
          <tbody>
            {packets.slice(0, 5).map((pkt, i) => {
              let color = 'var(--text-secondary)';
              const v = (pkt.verdict || pkt.type || '').toLowerCase();
              if (v.includes('dos') || v.includes('brute') || v.includes('botnet') || v.includes('infiltration')) color = 'var(--text-danger)';
              else if (v.includes('scan')) color = 'var(--text-warning)';

              return (
                <tr key={i} style={{ borderBottom: "1px solid var(--border)", transition: "background 0.2s" }} onMouseEnter={(e) => e.currentTarget.style.backgroundColor = "rgba(15, 23, 42, 0.02)"} onMouseLeave={(e) => e.currentTarget.style.backgroundColor = "transparent"}>
                  <td style={{ padding: "12px 16px", fontWeight: "500" }}>{pkt.src}</td>
                  <td style={{ padding: "12px 16px", fontWeight: "500" }}>{pkt.dst}</td>
                  <td style={{ padding: "12px 16px", color: "var(--text-secondary)" }}>{pkt.size}</td>
                  <td style={{ padding: "12px 16px", color: "var(--text-secondary)" }}>{pkt.proto}</td>
                  <td style={{ padding: "12px 16px", fontWeight: "500", color: color }}>{pkt.verdict || pkt.type}</td>
                  <td style={{ padding: "12px 16px", color: "var(--text-secondary)" }}>{pkt.time instanceof Date ? pkt.time.toLocaleTimeString() : 'Just now'}</td>
                </tr>
              )
            })}
            {packets.length === 0 && (
              <tr>
                <td colSpan="6" style={{ padding: "24px 16px", color: "var(--text-secondary)", textAlign: "center" }}>Waiting for traffic...</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
