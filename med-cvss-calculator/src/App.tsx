import React, { useState } from 'react';
import IntegratedCVSSCalculator from './components/IntegratedCVSSCalculator';
import CVSSComparison from './components/CVSSComparison';
import './App.css';

function App() {
  const [activeTab, setActiveTab] = useState<'calculator' | 'comparison'>('calculator');

  return (
    <div className='App'>
      <nav className='app-navigation'>
        <h1>Medical Device CVSS Calculator</h1>
        <div className='disclaimer'>
          <strong>Disclaimer:</strong> This tool is for educational and assessment purposes only.
          CVSS scores should be used as part of a comprehensive security assessment and not as the
          sole factor in decision-making.
        </div>
        <div className='nav-tabs'>
          <button
            className={activeTab === 'calculator' ? 'active' : ''}
            onClick={() => setActiveTab('calculator')}
          >
            CVSS Calculator
          </button>
          <button
            className={activeTab === 'comparison' ? 'active' : ''}
            onClick={() => setActiveTab('comparison')}
          >
            Before/After Comparison
          </button>
        </div>
      </nav>

      <main className='app-content'>
        {activeTab === 'calculator' && <IntegratedCVSSCalculator />}
        {activeTab === 'comparison' && <CVSSComparison />}
      </main>
    </div>
  );
}

export default App;
