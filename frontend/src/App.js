import React from 'react';
import './App.css';
import Scanner from './components/Scanner';

function App() {
  return (
    <div className="app">
      <header className="app-header">
        <h1>Vulnerability Scanner</h1>
        <p>A simple security scanning tool for educational purposes</p>
      </header>
      <main>
        <Scanner />
      </main>
      <footer>
        <p>© {new Date().getFullYear()} Vulnerability Scanner - Educational Use Only</p>
      </footer>
    </div>
  );
}

export default App;
