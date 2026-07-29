import React from 'react';
import { Network as NetworkIcon, Server, Shield, Activity } from 'lucide-react';

export default function Network() {
  const nodes = [
    { id: 'Gateway-01', ip: '192.168.1.1', status: 'Secure', load: '45%' },
    { id: 'Web-Server-Alpha', ip: '192.168.1.10', status: 'Warning', load: '82%' },
    { id: 'DB-Primary', ip: '10.0.0.50', status: 'Secure', load: '12%' },
    { id: 'App-Server-01', ip: '192.168.1.20', status: 'Secure', load: '34%' },
    { id: 'DMZ-Router', ip: '172.16.0.1', status: 'Critical', load: '98%' },
  ];

  return (
    <div className="dash-container">
      <div className="card" style={{ padding: '32px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '32px' }}>
          <div style={{ background: '#e0e7ff', padding: '12px', borderRadius: '12px' }}>
            <NetworkIcon size={24} color="#4f46e5" />
          </div>
          <div>
            <h2 style={{ fontSize: '20px', fontWeight: '600', margin: '0 0 4px 0', color: '#0f172a' }}>Network Topology Map</h2>
            <p style={{ margin: 0, color: '#64748b', fontSize: '14px' }}>Monitor active nodes and their security statuses.</p>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '20px' }}>
          
          {nodes.map((node, i) => (
            <div key={i} style={{ 
              border: '1px solid #e2e8f0', borderRadius: '12px', padding: '24px',
              position: 'relative', overflow: 'hidden'
            }}>
              {/* Decorative top bar indicating status */}
              <div style={{ 
                position: 'absolute', top: 0, left: 0, right: 0, height: '4px',
                background: node.status === 'Secure' ? '#16a34a' : node.status === 'Warning' ? '#f59e0b' : '#dc2626'
              }} />
              
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '20px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <Server size={20} color="#64748b" />
                  <div>
                    <div style={{ fontSize: '15px', fontWeight: '600', color: '#0f172a' }}>{node.id}</div>
                    <div style={{ fontSize: '13px', color: '#64748b', fontFamily: 'monospace' }}>{node.ip}</div>
                  </div>
                </div>
                
                <span style={{ 
                  padding: '4px 10px', borderRadius: '4px', fontSize: '12px', fontWeight: '600',
                  background: node.status === 'Secure' ? '#dcfce7' : node.status === 'Warning' ? '#fef3c7' : '#fee2e2',
                  color: node.status === 'Secure' ? '#16a34a' : node.status === 'Warning' ? '#d97706' : '#dc2626'
                }}>
                  {node.status}
                </span>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div style={{ background: '#f8fafc', padding: '12px', borderRadius: '8px' }}>
                  <div style={{ fontSize: '12px', color: '#64748b', marginBottom: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Activity size={14} /> Traffic Load
                  </div>
                  <div style={{ fontSize: '16px', fontWeight: '600', color: '#0f172a' }}>{node.load}</div>
                </div>
                <div style={{ background: '#f8fafc', padding: '12px', borderRadius: '8px' }}>
                  <div style={{ fontSize: '12px', color: '#64748b', marginBottom: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Shield size={14} /> Defenses
                  </div>
                  <div style={{ fontSize: '16px', fontWeight: '600', color: '#0f172a' }}>Active</div>
                </div>
              </div>

            </div>
          ))}

        </div>
      </div>
    </div>
  );
}
