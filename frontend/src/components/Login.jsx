import React, { useState } from 'react';
import { Shield, Eye, EyeOff } from 'lucide-react';

export default function Login({ onLogin }) {
  const [isRegistering, setIsRegistering] = useState(false);
  const [isResetting, setIsResetting] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [email, setEmail] = useState('');
  const [contact, setContact] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (password.length > 0 && password.length < 4) {
      setError('Password is too short. It must be at least 4 characters.');
      return;
    }
    
    if (isRegistering) {
      if (/\d/.test(username)) {
        setError('Username cannot contain numbers.');
        return;
      }
      if (username.toLowerCase() === password.toLowerCase()) {
        setError('Password cannot be identical to your username.');
        return;
      }
    }

    if (isResetting) {
      if (!email || !password) {
        setError('Email and new password are required.');
        return;
      }
    }

    setLoading(true);

    let endpoint = 'http://localhost:5000/api/login';
    let payload = { username, password };

    if (isRegistering) {
      endpoint = 'http://localhost:5000/api/register';
      payload = { username, password, firstName, lastName, email, contact };
    } else if (isResetting) {
      endpoint = 'http://localhost:5000/api/reset-password';
      payload = { email, newPassword: password };
    }
    
    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error || 'Authentication failed');
      }
      
      if (isRegistering) {
        setIsRegistering(false);
        setError('');
        alert('Registration successful! Please login with your new credentials.');
      } else if (isResetting) {
        setIsResetting(false);
        setPassword('');
        setError('');
        alert('Password reset successful! Please login.');
      } else {
        onLogin(data.user);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-root">
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

        .login-root {
          font-family: 'Inter', sans-serif;
          min-height: 100vh;
          display: flex;
          background: #f1f5f9;
        }

        .left-pane {
          flex: 1.2;
          background: linear-gradient(135deg, #020617 0%, #0f172a 50%, #1e3a8a 100%);
          display: flex;
          flex-direction: column;
          padding: 40px;
          color: white;
          position: relative;
          overflow: hidden;
        }

        /* Connecting nodes background effect */
        .left-pane::before {
          content: '';
          position: absolute;
          top: 0; left: 0; right: 0; bottom: 0;
          background-image: radial-gradient(circle at 50% 50%, rgba(56,189,248,0.1) 0%, transparent 60%);
          opacity: 0.8;
          pointer-events: none;
        }

        .brand-header {
          display: flex;
          align-items: center;
          gap: 12px;
          z-index: 10;
        }

        .brand-title-left {
          font-size: 20px;
          font-weight: 700;
          line-height: 1.2;
        }

        .brand-sub-left {
          font-size: 11px;
          color: #94a3b8;
        }

        .hero-content {
          margin-top: auto;
          margin-bottom: auto;
          z-index: 10;
          display: flex;
          flex-direction: column;
          align-items: center;
          text-align: center;
        }

        .hero-shield-wrap {
          margin-bottom: 40px;
          position: relative;
        }
        
        .hero-shield-bg {
          position: absolute;
          top: 50%; left: 50%;
          transform: translate(-50%, -50%);
          width: 200px; height: 200px;
          background: radial-gradient(circle, rgba(56,189,248,0.2) 0%, transparent 70%);
        }

        .hero-title {
          font-size: 32px;
          font-weight: 600;
          margin-bottom: 12px;
        }
        
        .hero-title span {
          color: #60a5fa;
        }

        .hero-desc {
          color: #94a3b8;
          font-size: 14px;
          line-height: 1.6;
          max-width: 300px;
        }

        .footer-text {
          font-size: 11px;
          color: #64748b;
          margin-top: auto;
          z-index: 10;
        }

        .right-pane {
          flex: 1;
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 40px;
        }

        .auth-card {
          background: white;
          border-radius: 16px;
          padding: 40px;
          width: 100%;
          max-width: 420px;
          box-shadow: 0 10px 25px -5px rgba(0,0,0,0.05);
        }

        .card-title {
          font-size: 24px;
          font-weight: 600;
          color: #0f172a;
          margin-bottom: 8px;
        }

        .card-sub {
          font-size: 13px;
          color: #64748b;
          margin-bottom: 30px;
        }

        .input-group {
          margin-bottom: 20px;
        }

        .input-label {
          display: block;
          font-size: 13px;
          font-weight: 500;
          color: #334155;
          margin-bottom: 8px;
        }

        .input-wrapper {
          position: relative;
        }

        .input-field {
          width: 100%;
          background: #f8fafc;
          border: 1px solid #e2e8f0;
          color: #0f172a;
          padding: 12px 14px;
          border-radius: 8px;
          font-family: inherit;
          font-size: 14px;
          transition: all 0.2s;
          outline: none;
        }

        .input-field:focus {
          border-color: #3b82f6;
          box-shadow: 0 0 0 3px rgba(59,130,246,0.1);
        }
        
        .input-icon-right {
          position: absolute;
          right: 14px;
          top: 50%;
          transform: translateY(-50%);
          color: #94a3b8;
          cursor: pointer;
        }

        .actions-row {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 24px;
          font-size: 13px;
        }

        .checkbox-label {
          display: flex;
          align-items: center;
          gap: 8px;
          color: #475569;
          cursor: pointer;
        }

        .checkbox {
          accent-color: #2563eb;
          width: 16px;
          height: 16px;
        }

        .forgot-link {
          color: #2563eb;
          text-decoration: none;
        }
        .forgot-link:hover { text-decoration: underline; }

        .submit-btn {
          width: 100%;
          background: #2563eb;
          color: white;
          border: none;
          padding: 14px;
          border-radius: 8px;
          font-weight: 500;
          font-size: 15px;
          cursor: pointer;
          transition: background 0.2s;
          margin-bottom: 24px;
        }

        .submit-btn:hover {
          background: #1d4ed8;
        }
        .submit-btn:disabled { opacity: 0.7; cursor: not-allowed; }

        .toggle-link {
          text-align: center;
          font-size: 13px;
          color: #64748b;
        }

        .toggle-link span {
          color: #2563eb;
          cursor: pointer;
          font-weight: 500;
          margin-left: 4px;
        }
        .toggle-link span:hover { text-decoration: underline; }

        .error-msg {
          color: #e11d48;
          font-size: 13px;
          margin-bottom: 16px;
          background: #ffe4e6;
          padding: 10px;
          border-radius: 6px;
        }
        
        @media (max-width: 900px) {
          .left-pane { display: none; }
        }
      `}</style>
      
      <div className="left-pane">
        <div className="brand-header">
          <Shield size={28} color="#38bdf8" strokeWidth={1.5} />
          <div>
            <div className="brand-title-left">NIDS</div>
            <div className="brand-sub-left">Network Intrusion<br/>Detection System</div>
          </div>
        </div>
        
        <div className="hero-content">
          <div className="hero-shield-wrap">
            <div className="hero-shield-bg" />
            <Shield size={120} color="#38bdf8" strokeWidth={1} style={{ position: 'relative', zIndex: 2 }} />
          </div>
          <div className="hero-title">
            Secure Networks.<br/>
            <span>Safer Tomorrow.</span>
          </div>
          <div className="hero-desc">
            Monitor, Detect, Respond. Protect your network from cyber threats in real-time.
          </div>
        </div>
        
        <div className="footer-text">
          © 2024 NIDS. All rights reserved.
        </div>
      </div>

      <div className="right-pane">
        <div className="auth-card">
          <div className="card-title">
            {isResetting ? "Reset Password" : (isRegistering ? "Create Account" : "Welcome Back")}
          </div>
          <div className="card-sub">
            {isResetting ? "Enter your email to reset your password" : (isRegistering ? "Join NIDS to secure your network" : "Sign in to continue to NIDS")}
          </div>

          <form onSubmit={handleSubmit}>
            {error && <div className="error-msg">{error}</div>}
            
            {isRegistering && !isResetting && (
              <>
                <div className="input-group">
                  <label className="input-label">First Name</label>
                  <input type="text" className="input-field" placeholder="John" value={firstName} onChange={(e) => setFirstName(e.target.value)} required />
                </div>
                <div className="input-group">
                  <label className="input-label">Last Name</label>
                  <input type="text" className="input-field" placeholder="Doe" value={lastName} onChange={(e) => setLastName(e.target.value)} required />
                </div>
              </>
            )}

            {!isResetting && (
              <div className="input-group">
                <label className="input-label">Administrator ID (Username)</label>
                <input type="text" className="input-field" placeholder="Enter your ID" value={username} onChange={(e) => setUsername(e.target.value)} required pattern="[A-Za-z_]+" title="Only letters and underscores are allowed (no numbers)" />
              </div>
            )}

            {(isRegistering || isResetting) && (
              <div className="input-group">
                <label className="input-label">Email</label>
                <input type="email" className="input-field" placeholder="Enter your email" value={email} onChange={(e) => setEmail(e.target.value)} required />
              </div>
            )}
            
            <div className="input-group">
              <label className="input-label">{isResetting ? "New Password" : "Password"}</label>
              <div className="input-wrapper">
                <input type={showPassword ? "text" : "password"} className="input-field" placeholder={isResetting ? "Create a new password" : (isRegistering ? "Create a password" : "Enter your password")} value={password} onChange={(e) => setPassword(e.target.value)} required minLength={4} />
                {password.length > 0 && (
                  <div className="input-icon-right" onClick={() => setShowPassword(!showPassword)}>
                    {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                  </div>
                )}
              </div>
            </div>
            
            {!isRegistering && !isResetting && (
              <div className="actions-row">
                <label className="checkbox-label">
                  <input type="checkbox" className="checkbox" /> Remember me
                </label>
                <span className="forgot-link" style={{cursor:'pointer'}} onClick={() => { setIsResetting(true); setError(''); }}>Forgot Password?</span>
              </div>
            )}
            
            <button type="submit" className="submit-btn" disabled={loading}>
              {loading ? 'Processing...' : (isResetting ? 'Reset Password' : (isRegistering ? 'Register' : 'Login'))}
            </button>

            <div className="toggle-link">
              {isResetting ? (
                <>
                  Remember your password?
                  <span onClick={() => { setIsResetting(false); setError(''); }}>Login</span>
                </>
              ) : (
                <>
                  {isRegistering ? "Already have an account?" : "Don't have an account?"}
                  <span onClick={() => { setIsRegistering(!isRegistering); setError(''); }}>
                    {isRegistering ? "Login" : "Register"}
                  </span>
                </>
              )}
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}
