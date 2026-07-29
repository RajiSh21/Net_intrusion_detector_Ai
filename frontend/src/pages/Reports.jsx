import React from 'react';
import { FileText, Download, Calendar } from 'lucide-react';

export default function Reports() {
  const reports = [
    { name: 'Weekly Security Summary', date: 'May 20, 2024', size: '2.4 MB', type: 'PDF' },
    { name: 'Monthly Threat Analysis', date: 'May 01, 2024', size: '8.1 MB', type: 'PDF' },
    { name: 'Network Traffic Dump', date: 'April 28, 2024', size: '142 MB', type: 'CSV' },
    { name: 'Incident Report (Port Scan)', date: 'April 15, 2024', size: '1.2 MB', type: 'PDF' },
  ];

  return (
    <div className="dash-container">
      
      <div className="card" style={{ padding: '32px', marginBottom: '24px' }}>
        <h2 style={{ fontSize: '20px', fontWeight: '600', margin: '0 0 16px 0', color: '#0f172a' }}>Generate New Report</h2>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr auto', gap: '16px', alignItems: 'end' }}>
          
          <div>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: '500', color: '#64748b', marginBottom: '8px' }}>Report Type</label>
            <select style={{ width: '100%', padding: '10px 12px', border: '1px solid #e2e8f0', borderRadius: '6px', outline: 'none', color: '#0f172a', background: 'white' }}>
              <option>Security Summary</option>
              <option>Threat Analysis</option>
              <option>Raw Traffic Log</option>
            </select>
          </div>
          
          <div>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: '500', color: '#64748b', marginBottom: '8px' }}>Date Range</label>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '9px 12px', border: '1px solid #e2e8f0', borderRadius: '6px', background: 'white' }}>
              <Calendar size={16} color="#64748b" />
              <span style={{ fontSize: '14px', color: '#0f172a' }}>Last 7 Days</span>
            </div>
          </div>
          
          <div>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: '500', color: '#64748b', marginBottom: '8px' }}>Format</label>
            <select style={{ width: '100%', padding: '10px 12px', border: '1px solid #e2e8f0', borderRadius: '6px', outline: 'none', color: '#0f172a', background: 'white' }}>
              <option>PDF Document</option>
              <option>CSV Export</option>
              <option>JSON Data</option>
            </select>
          </div>
          
          <button style={{ 
            background: '#2563eb', color: 'white', border: 'none', borderRadius: '6px', 
            padding: '10px 24px', fontWeight: '500', cursor: 'pointer', height: '40px' 
          }}>
            Generate
          </button>
          
        </div>
      </div>

      <div className="card" style={{ padding: '32px' }}>
        <h2 style={{ fontSize: '20px', fontWeight: '600', margin: '0 0 24px 0', color: '#0f172a' }}>Archived Reports</h2>
        
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: '20px' }}>
          {reports.map((report, i) => (
            <div key={i} style={{ 
              border: '1px solid #e2e8f0', borderRadius: '12px', padding: '20px',
              display: 'flex', flexDirection: 'column', gap: '16px', background: 'white'
            }}>
              <div style={{ display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
                <div style={{ background: '#f1f5f9', padding: '12px', borderRadius: '8px' }}>
                  <FileText size={24} color="#64748b" />
                </div>
                <div>
                  <div style={{ fontSize: '15px', fontWeight: '600', color: '#0f172a', marginBottom: '4px' }}>{report.name}</div>
                  <div style={{ fontSize: '13px', color: '#64748b' }}>Generated {report.date}</div>
                </div>
              </div>
              
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 'auto', paddingTop: '16px', borderTop: '1px solid #f1f5f9' }}>
                <div style={{ fontSize: '13px', color: '#64748b', fontWeight: '500' }}>{report.type} • {report.size}</div>
                <button style={{ 
                  background: 'transparent', border: 'none', color: '#2563eb', 
                  display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px', fontWeight: '600', cursor: 'pointer'
                }}>
                  <Download size={14} /> Download
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
      
    </div>
  );
}
