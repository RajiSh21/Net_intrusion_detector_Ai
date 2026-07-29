import React, { useState } from 'react';
import { Save, Bell, Shield, Database, Key } from 'lucide-react';

export default function Settings() {
  const [activeTab, setActiveTab] = useState('general');

  return (
    <div className="dash-container">
      <div style={{ display: 'grid', gridTemplateColumns: '240px 1fr', gap: '32px' }}>
        
        {/* Settings Navigation */}
        <div>
          <h2 style={{ fontSize: '18px', fontWeight: '600', color: '#0f172a', marginBottom: '20px' }}>Settings</h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <button 
              onClick={() => setActiveTab('general')}
              style={{ textAlign: 'left', padding: '10px 16px', borderRadius: '8px', border: 'none', background: activeTab === 'general' ? '#e0e7ff' : 'transparent', color: activeTab === 'general' ? '#4f46e5' : '#475569', fontWeight: '500', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '10px', fontSize: '14px' }}
            >
              <Shield size={16} /> Security Rules
            </button>
            <button 
              onClick={() => setActiveTab('notifications')}
              style={{ textAlign: 'left', padding: '10px 16px', borderRadius: '8px', border: 'none', background: activeTab === 'notifications' ? '#e0e7ff' : 'transparent', color: activeTab === 'notifications' ? '#4f46e5' : '#475569', fontWeight: '500', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '10px', fontSize: '14px' }}
            >
              <Bell size={16} /> Notifications
            </button>
            <button 
              onClick={() => setActiveTab('api')}
              style={{ textAlign: 'left', padding: '10px 16px', borderRadius: '8px', border: 'none', background: activeTab === 'api' ? '#e0e7ff' : 'transparent', color: activeTab === 'api' ? '#4f46e5' : '#475569', fontWeight: '500', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '10px', fontSize: '14px' }}
            >
              <Key size={16} /> API Keys
            </button>
            <button 
              onClick={() => setActiveTab('data')}
              style={{ textAlign: 'left', padding: '10px 16px', borderRadius: '8px', border: 'none', background: activeTab === 'data' ? '#e0e7ff' : 'transparent', color: activeTab === 'data' ? '#4f46e5' : '#475569', fontWeight: '500', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '10px', fontSize: '14px' }}
            >
              <Database size={16} /> Data Retention
            </button>
          </div>
        </div>

        {/* Settings Content Area */}
        <div className="card" style={{ padding: '32px' }}>
          
          {activeTab === 'general' && (
            <div>
              <h3 style={{ fontSize: '18px', fontWeight: '600', color: '#0f172a', margin: '0 0 24px 0', paddingBottom: '16px', borderBottom: '1px solid #e2e8f0' }}>Security Rules & Thresholds</h3>
              
              <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <div>
                    <div style={{ fontSize: '15px', fontWeight: '500', color: '#0f172a', marginBottom: '4px' }}>Auto-Block High Severity Threats</div>
                    <div style={{ fontSize: '13px', color: '#64748b', maxWidth: '400px' }}>Automatically drop connections and block IPs that exceed a 95% threat confidence rating.</div>
                  </div>
                  <label style={{ position: 'relative', display: 'inline-block', width: '44px', height: '24px' }}>
                    <input type="checkbox" defaultChecked style={{ opacity: 0, width: 0, height: 0 }} />
                    <span style={{ position: 'absolute', cursor: 'pointer', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: '#2563eb', transition: '.4s', borderRadius: '24px' }}>
                      <span style={{ position: 'absolute', content: '""', height: '18px', width: '18px', left: '22px', bottom: '3px', backgroundColor: 'white', transition: '.4s', borderRadius: '50%' }}></span>
                    </span>
                  </label>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <div>
                    <div style={{ fontSize: '15px', fontWeight: '500', color: '#0f172a', marginBottom: '4px' }}>GAN Adversarial Augmentation</div>
                    <div style={{ fontSize: '13px', color: '#64748b', maxWidth: '400px' }}>Keep the Generative Adversarial Network running to continuously train the AI model against zero-day signatures.</div>
                  </div>
                  <label style={{ position: 'relative', display: 'inline-block', width: '44px', height: '24px' }}>
                    <input type="checkbox" defaultChecked style={{ opacity: 0, width: 0, height: 0 }} />
                    <span style={{ position: 'absolute', cursor: 'pointer', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: '#2563eb', transition: '.4s', borderRadius: '24px' }}>
                      <span style={{ position: 'absolute', content: '""', height: '18px', width: '18px', left: '22px', bottom: '3px', backgroundColor: 'white', transition: '.4s', borderRadius: '50%' }}></span>
                    </span>
                  </label>
                </div>
                
                <div>
                  <div style={{ fontSize: '15px', fontWeight: '500', color: '#0f172a', marginBottom: '8px' }}>Sensitivity Threshold (Confidence %)</div>
                  <div style={{ fontSize: '13px', color: '#64748b', marginBottom: '12px' }}>Minimum AI confidence required to flag an alert.</div>
                  <input type="range" min="50" max="99" defaultValue="85" style={{ width: '100%', maxWidth: '300px' }} />
                  <div style={{ fontSize: '13px', color: '#0f172a', fontWeight: '600', marginTop: '8px' }}>85%</div>
                </div>
              </div>
            </div>
          )}

          {activeTab !== 'general' && (
            <div style={{ padding: '40px', textAlign: 'center', color: '#94a3b8' }}>
              <p>Settings for {activeTab} will go here.</p>
            </div>
          )}

          <div style={{ marginTop: '40px', paddingTop: '24px', borderTop: '1px solid #e2e8f0', display: 'flex', justifyContent: 'flex-end' }}>
            <button style={{ 
              background: '#2563eb', color: 'white', border: 'none', borderRadius: '6px', 
              padding: '10px 24px', fontWeight: '500', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '8px' 
            }}>
              <Save size={16} /> Save Changes
            </button>
          </div>

        </div>
      </div>
    </div>
  );
}
