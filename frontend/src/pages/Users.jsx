import React from 'react';
import { UserPlus, Shield, Mail, MoreVertical } from 'lucide-react';

export default function Users() {
  const users = [
    { name: 'Sarah Jenkins', role: 'Security Admin', email: 'sarah.j@nids.local', status: 'Active', avatar: 'S' },
    { name: 'David Chen', role: 'Security Analyst', email: 'david.c@nids.local', status: 'Active', avatar: 'D' },
    { name: 'Marcus Rowell', role: 'Incident Responder', email: 'marcus.r@nids.local', status: 'Away', avatar: 'M' },
    { name: 'Elena Rodriguez', role: 'Read-Only Viewer', email: 'elena.r@nids.local', status: 'Offline', avatar: 'E' },
  ];

  return (
    <div className="dash-container">
      <div className="card" style={{ padding: '32px' }}>
        
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '32px' }}>
          <div>
            <h2 style={{ fontSize: '20px', fontWeight: '600', margin: '0 0 4px 0', color: '#0f172a' }}>Team Access Management</h2>
            <p style={{ margin: 0, color: '#64748b', fontSize: '14px' }}>Manage administrators and analyst roles.</p>
          </div>
          <button style={{ 
            background: '#2563eb', color: 'white', border: 'none', borderRadius: '6px', 
            padding: '10px 16px', fontWeight: '500', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '8px', fontSize: '14px'
          }}>
            <UserPlus size={16} /> Invite User
          </button>
        </div>

        <div style={{ display: 'grid', gap: '16px' }}>
          {users.map((u, i) => (
            <div key={i} style={{ 
              display: 'flex', alignItems: 'center', justifyContent: 'space-between', 
              padding: '16px 20px', border: '1px solid #e2e8f0', borderRadius: '12px' 
            }}>
              
              <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                <div style={{ 
                  width: '40px', height: '40px', borderRadius: '50%', background: '#e0e7ff', 
                  color: '#4f46e5', display: 'flex', alignItems: 'center', justifyContent: 'center', 
                  fontSize: '16px', fontWeight: '600'
                }}>
                  {u.avatar}
                </div>
                <div>
                  <div style={{ fontSize: '15px', fontWeight: '600', color: '#0f172a', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    {u.name}
                    {u.role.includes('Admin') && <Shield size={14} color="#2563eb" />}
                  </div>
                  <div style={{ fontSize: '13px', color: '#64748b', display: 'flex', alignItems: 'center', gap: '6px', marginTop: '2px' }}>
                    <Mail size={12} /> {u.email}
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '40px' }}>
                <div>
                  <div style={{ fontSize: '12px', color: '#64748b', marginBottom: '2px' }}>Role</div>
                  <div style={{ fontSize: '14px', fontWeight: '500', color: '#0f172a' }}>{u.role}</div>
                </div>
                
                <div>
                  <div style={{ fontSize: '12px', color: '#64748b', marginBottom: '2px' }}>Status</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: u.status === 'Active' ? '#16a34a' : u.status === 'Away' ? '#f59e0b' : '#94a3b8' }} />
                    <span style={{ fontSize: '14px', fontWeight: '500', color: '#0f172a' }}>{u.status}</span>
                  </div>
                </div>

                <button style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: '#94a3b8', padding: '4px' }}>
                  <MoreVertical size={20} />
                </button>
              </div>

            </div>
          ))}
        </div>

      </div>
    </div>
  );
}
