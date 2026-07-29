import React from 'react';
import { Cpu, CheckCircle2, AlertTriangle, ScanLine } from 'lucide-react';

export default function Detections() {
  return (
    <div className="dash-container">
      <div className="charts-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
        
        {/* Model Status Card */}
        <div className="card">
          <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Cpu size={20} color="#2563eb" /> AI Detection Engine
          </div>
          
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginTop: '24px' }}>
            <div style={{ padding: '16px', background: '#f8fafc', borderRadius: '8px', border: '1px solid #e2e8f0' }}>
              <div style={{ fontSize: '13px', color: '#64748b', marginBottom: '8px' }}>Active Model</div>
              <div style={{ fontSize: '16px', fontWeight: '600', color: '#0f172a' }}>Random Forest (GAN-Augmented)</div>
            </div>
            <div style={{ padding: '16px', background: '#f8fafc', borderRadius: '8px', border: '1px solid #e2e8f0' }}>
              <div style={{ fontSize: '13px', color: '#64748b', marginBottom: '8px' }}>Base Accuracy</div>
              <div style={{ fontSize: '16px', fontWeight: '600', color: '#16a34a' }}>99.93%</div>
            </div>
            <div style={{ padding: '16px', background: '#f8fafc', borderRadius: '8px', border: '1px solid #e2e8f0' }}>
              <div style={{ fontSize: '13px', color: '#64748b', marginBottom: '8px' }}>Avg Inference Time</div>
              <div style={{ fontSize: '16px', fontWeight: '600', color: '#0f172a' }}>0.015 ms</div>
            </div>
            <div style={{ padding: '16px', background: '#f8fafc', borderRadius: '8px', border: '1px solid #e2e8f0' }}>
              <div style={{ fontSize: '13px', color: '#64748b', marginBottom: '8px' }}>Status</div>
              <div style={{ fontSize: '16px', fontWeight: '600', color: '#16a34a', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <CheckCircle2 size={16} /> Online
              </div>
            </div>
          </div>
        </div>

        {/* GAN Augmentation Card */}
        <div className="card">
          <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <ScanLine size={20} color="#8b5cf6" /> Adversarial Defense (GAN)
          </div>
          <p style={{ fontSize: '14px', color: '#64748b', lineHeight: '1.6' }}>
            The detection engine is currently utilizing a Generative Adversarial Network to generate synthetic attack signatures. This allows the classifier to proactively learn zero-day attack patterns before they hit your network.
          </p>
          
          <div style={{ marginTop: '24px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px', fontSize: '13px', fontWeight: '500' }}>
              <span style={{ color: '#475569' }}>Generator Loss</span>
              <span style={{ color: '#8b5cf6' }}>0.412</span>
            </div>
            <div style={{ width: '100%', height: '6px', background: '#f1f5f9', borderRadius: '3px', overflow: 'hidden' }}>
              <div style={{ width: '41%', height: '100%', background: '#8b5cf6' }} />
            </div>
          </div>

          <div style={{ marginTop: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px', fontSize: '13px', fontWeight: '500' }}>
              <span style={{ color: '#475569' }}>Discriminator Loss</span>
              <span style={{ color: '#3b82f6' }}>0.285</span>
            </div>
            <div style={{ width: '100%', height: '6px', background: '#f1f5f9', borderRadius: '3px', overflow: 'hidden' }}>
              <div style={{ width: '28%', height: '100%', background: '#3b82f6' }} />
            </div>
          </div>
        </div>

      </div>

      <div className="card" style={{ marginTop: '24px' }}>
        <div className="card-title">Live Classification Feed</div>
        <p style={{ color: '#64748b', fontSize: '14px', marginBottom: '24px' }}>Simulated real-time packet inspection results.</p>
        
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '14px' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #e2e8f0', color: '#64748b' }}>
                <th style={{ padding: '16px 12px', fontWeight: '500' }}>Target</th>
                <th style={{ padding: '16px 12px', fontWeight: '500' }}>Protocol</th>
                <th style={{ padding: '16px 12px', fontWeight: '500' }}>Predicted Class</th>
                <th style={{ padding: '16px 12px', fontWeight: '500' }}>Confidence</th>
                <th style={{ padding: '16px 12px', fontWeight: '500' }}>Latency</th>
              </tr>
            </thead>
            <tbody>
              {Array.from({length: 5}).map((_, i) => (
                <tr key={i} style={{ borderBottom: '1px solid #f1f5f9', color: '#0f172a' }}>
                  <td style={{ padding: '16px 12px', fontFamily: 'monospace' }}>10.0.0.{Math.floor(Math.random() * 255)}:443</td>
                  <td style={{ padding: '16px 12px' }}>TCP</td>
                  <td style={{ padding: '16px 12px', color: '#16a34a', fontWeight: '500' }}>Normal Traffic</td>
                  <td style={{ padding: '16px 12px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <div style={{ flex: 1, height: '6px', background: '#f1f5f9', borderRadius: '3px' }}>
                        <div style={{ width: '99%', height: '100%', background: '#16a34a', borderRadius: '3px' }} />
                      </div>
                      <span style={{ fontSize: '12px', color: '#64748b' }}>99.9%</span>
                    </div>
                  </td>
                  <td style={{ padding: '16px 12px', color: '#64748b' }}>0.01ms</td>
                </tr>
              ))}
            </tbody>
          </table>
      </div>
    </div>
  );
}
