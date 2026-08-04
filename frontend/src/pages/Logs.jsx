import React from 'react';

export default function Logs({ packets = [] }) {
  const getClassColor = (cls) => {
    const s = (cls || '').toLowerCase();
    if (s.includes('normal')) return 'var(--text-secondary)';
    if (s.includes('dos') || s.includes('brute') || s.includes('botnet') || s.includes('infiltration')) return 'var(--text-danger)';
    if (s.includes('scan')) return 'var(--text-warning)';
    return 'var(--text-secondary)';
  };

  return (
    <div style={{ animation: "fadeIn 0.3s ease" }}>
      <p style={{ fontSize: "16px", fontWeight: "500", margin: "0 0 2px" }}>Traffic log</p>
      <p style={{ fontSize: "12px", color: "var(--text-secondary)", margin: "0 0 16px" }}>Most recent bidirectional flows</p>
      
      <div className="card-anim" style={{ background: "var(--surface-1)", borderRadius: "12px", border: "1px solid var(--border)", overflow: "hidden" }}>
        <table style={{ width: "100%", fontSize: "13px", borderCollapse: "collapse", tableLayout: "fixed" }}>
          <thead>
            <tr style={{ background: "var(--surface-2)", color: "var(--text-secondary)", textAlign: "left", borderBottom: "1px solid var(--border)" }}>
              <th style={{ padding: "10px 16px", fontWeight: "500" }}>Source IP</th>
              <th style={{ padding: "10px 16px", fontWeight: "500" }}>Dest IP</th>
              <th style={{ padding: "10px 16px", fontWeight: "500" }}>Port/Size</th>
              <th style={{ padding: "10px 16px", fontWeight: "500" }}>Protocol</th>
              <th style={{ padding: "10px 16px", fontWeight: "500" }}>Class</th>
              <th style={{ padding: "10px 16px", fontWeight: "500" }}>Time</th>
            </tr>
          </thead>
          <tbody>
            {packets.map((pkt, i) => (
              <tr key={i} style={{ borderBottom: "1px solid var(--border)", transition: "background 0.2s" }} onMouseEnter={(e) => e.currentTarget.style.backgroundColor = "rgba(15, 23, 42, 0.02)"} onMouseLeave={(e) => e.currentTarget.style.backgroundColor = "transparent"}>
                <td style={{ padding: "12px 16px", fontWeight: "500" }}>{pkt.src}</td>
                <td style={{ padding: "12px 16px", fontWeight: "500" }}>{pkt.dst}</td>
                <td style={{ padding: "12px 16px", color: "var(--text-secondary)" }}>{pkt.size}</td>
                <td style={{ padding: "12px 16px", color: "var(--text-secondary)" }}>{pkt.proto}</td>
                <td style={{ padding: "12px 16px", fontWeight: "500", color: getClassColor(pkt.verdict || pkt.type) }}>{pkt.verdict || pkt.type}</td>
                <td style={{ padding: "12px 16px", color: "var(--text-secondary)" }}>{pkt.time instanceof Date ? pkt.time.toLocaleTimeString() : 'Just now'}</td>
              </tr>
            ))}
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
