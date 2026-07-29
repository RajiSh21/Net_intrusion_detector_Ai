import React, { useState } from 'react';
import Home from './components/Home';
import Login from './components/Login';

function App() {
  const [user, setUser] = useState(null);

  return (
    <div className="App">
      {user ? (
        <Home user={user} onLogout={() => setUser(null)} />
      ) : (
        <Login onLogin={(userProfile) => setUser(userProfile)} />
      )}
    </div>
  );
}

export default App;
