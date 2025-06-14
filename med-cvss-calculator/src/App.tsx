import { Routes, Route } from 'react-router-dom';
import IntegratedCVSSCalculator from './components/IntegratedCVSSCalculator';
import ThreatAnalysis from './components/ThreatAnalysis';
import Navigation from './components/Navigation';
import Login from './components/Login';
import Signup from './components/Signup';
import ProtectedRoute from './components/ProtectedRoute';
import ErrorBoundary from './components/ErrorBoundary';
import './App.css';

function App() {
  return (
    <div className='App'>
      <Navigation />

      <main className='app-content'>
        <Routes>
          <Route
            path='/'
            element={
              <ErrorBoundary>
                <IntegratedCVSSCalculator />
              </ErrorBoundary>
            }
          />
          <Route path='/login' element={<Login />} />
          <Route path='/signup' element={<Signup />} />
          <Route
            path='/calculator'
            element={
              <ErrorBoundary>
                <IntegratedCVSSCalculator />
              </ErrorBoundary>
            }
          />
          <Route
            path='/threat-analysis'
            element={
              <ProtectedRoute>
                <ErrorBoundary>
                  <ThreatAnalysis />
                </ErrorBoundary>
              </ProtectedRoute>
            }
          />
        </Routes>
      </main>
    </div>
  );
}

export default App;
