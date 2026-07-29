import React, { useState, useEffect } from 'react';
import Home from './components/Home';
import Login from './components/Login';

function App() {
  const [user, setUser] = useState(() => {
    try {
      const saved = localStorage.getItem('nids_user');
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });

  const handleLogin = (userProfile) => {
    setUser(userProfile);
    localStorage.setItem('nids_user', JSON.stringify(userProfile));
  };

  const handleLogout = () => {
    setUser(null);
    localStorage.removeItem('nids_user');
  };

  return (
    <div className="App">
      {user ? (
        <Home user={user} onLogout={handleLogout} />
      ) : (
        <Login onLogin={handleLogin} />
      )}
    </div>
  );
}

export default App;
