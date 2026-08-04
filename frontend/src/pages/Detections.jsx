import React from 'react';
import { AlertTriangle, Server, Database, BrainCircuit, Users } from 'lucide-react';

export default function Detections({ modelInfo }) {
  const isLoaded = !!modelInfo?.algorithm;

  return (
    <div style={{ animation: "fadeIn 0.3s ease" }}>
      <p style={{ fontSize: "16px", fontWeight: "500", margin: "0 0 2px" }}>Model performance</p>
      <p style={{ fontSize: "12px", color: "var(--text-secondary)", margin: "0 0 16px" }}>Real-time details from backend engine</p>
      
      {!isLoaded ? (
        <div style={{ padding: "2rem", textAlign: "center", color: "var(--text-secondary)", background: "var(--surface-1)", borderRadius: "var(--radius)", border: "1px solid var(--border)" }}>
          Connecting to backend for model info...
        </div>
      ) : (
        <>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", marginBottom: "16px" }}>
            <div className="card-anim" style={{ background: "var(--surface-1)", borderRadius: "var(--radius)", padding: "1.25rem", border: "1px solid var(--border)" }}>
              <p style={{ fontSize: "13px", color: "var(--text-secondary)", margin: "0 0 8px", fontWeight: "500" }}>Algorithm</p>
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <BrainCircuit size={20} color="var(--text-accent)" />
                <p style={{ fontSize: "24px", fontWeight: "600", margin: 0, letterSpacing: "-0.5px" }}>{modelInfo.algorithm}</p>
              </div>
            </div>
            
            <div className="card-anim" style={{ background: "var(--surface-1)", borderRadius: "var(--radius)", padding: "1.25rem", border: "1px solid var(--border)" }}>
              <p style={{ fontSize: "13px", color: "var(--text-secondary)", margin: "0 0 8px", fontWeight: "500" }}>Reported Accuracy</p>
              <p style={{ fontSize: "28px", fontWeight: "600", margin: 0, letterSpacing: "-0.5px", color: "var(--text-success)" }}>{modelInfo.accuracy}</p>
            </div>

            <div className="card-anim" style={{ background: "var(--surface-1)", borderRadius: "var(--radius)", padding: "1.25rem", border: "1px solid var(--border)" }}>
              <p style={{ fontSize: "13px", color: "var(--text-secondary)", margin: "0 0 8px", fontWeight: "500" }}>Training Samples</p>
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <Database size={18} color="var(--text-secondary)" />
                <p style={{ fontSize: "24px", fontWeight: "600", margin: 0, letterSpacing: "-0.5px" }}>{modelInfo.trainingSamples.toLocaleString()}</p>
              </div>
            </div>

            <div className="card-anim" style={{ background: "var(--surface-1)", borderRadius: "var(--radius)", padding: "1.25rem", border: "1px solid var(--border)" }}>
              <p style={{ fontSize: "13px", color: "var(--text-secondary)", margin: "0 0 8px", fontWeight: "500" }}>GAN Augmented</p>
              <p style={{ fontSize: "24px", fontWeight: "600", margin: 0, letterSpacing: "-0.5px" }}>{modelInfo.ganAugmented ? 'Yes' : 'No'}</p>
            </div>
          </div>

          <div className="card-anim" style={{ background: "var(--surface-1)", border: "1px solid var(--border)", borderRadius: "12px", padding: "1.25rem", marginBottom: "12px" }}>
            <p style={{ fontSize: "14px", fontWeight: "500", margin: "0 0 10px" }}>Detected Threat Classes</p>
            <div style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
              {(modelInfo.classes || []).map((cls, idx) => (
                <span key={idx} style={{ background: "var(--bg-accent)", color: "var(--text-accent)", padding: "6px 12px", borderRadius: "16px", fontSize: "13px", fontWeight: "500" }}>
                  {cls}
                </span>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
