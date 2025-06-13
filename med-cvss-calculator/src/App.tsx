import { Routes, Route } from 'react-router-dom';
import IntegratedCVSSCalculator from './components/IntegratedCVSSCalculator';
import CVSSComparison from './components/CVSSComparison';
import Navigation from './components/Navigation';
import Login from './components/Login';
import Signup from './components/Signup';
import ProtectedRoute from './components/ProtectedRoute';
import './App.css';

function App() {
  return (
    <div className='App'>
      <Navigation />

      <main className='app-content'>
        <Routes>
          <Route path='/' element={<IntegratedCVSSCalculator />} />
          <Route path='/login' element={<Login />} />
          <Route path='/signup' element={<Signup />} />
          <Route
            path='/comparison'
            element={
              <ProtectedRoute>
                <CVSSComparison />
              </ProtectedRoute>
            }
          />
        </Routes>
      </main>
    </div>
  );
}

export default App;
