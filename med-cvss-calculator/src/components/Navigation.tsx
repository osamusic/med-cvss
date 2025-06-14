import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import './Navigation.css';

const Navigation: React.FC = () => {
  const { currentUser, signout } = useAuth();
  const location = useLocation();

  const handleLogout = async () => {
    try {
      await signout();
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error('Logout error:', error);
    }
  };

  return (
    <nav className='app-navigation'>
      <h1>Medical Device CVSS Calculator</h1>
      <div className='disclaimer'>
        <strong>Disclaimer:</strong> This tool is for educational and assessment purposes only. CVSS
        scores should be used as part of a comprehensive security assessment and not as the sole
        factor in decision-making.
      </div>

      <div className='nav-content'>
        <div className='nav-tabs'>
          <Link
            to='/'
            className={
              location.pathname === '/' || location.pathname === '/calculator' ? 'active' : ''
            }
          >
            CVSS Calculator
          </Link>
          {currentUser ? (
            <Link
              to='/threat-analysis'
              className={location.pathname === '/threat-analysis' ? 'active' : ''}
            >
              AI Threat Assessment (Japanese only)
            </Link>
          ) : (
            <Link to='/login' className='login-link'>
              AI Threat Assessment (Japanese only - Sign In Required)
            </Link>
          )}
        </div>

        <div className='auth-section'>
          {currentUser ? (
            <div className='user-info'>
              <span className='user-email'>{currentUser.email}</span>
              <button onClick={handleLogout} className='logout-button'>
                Sign Out
              </button>
            </div>
          ) : (
            <div className='auth-links'>
              <Link to='/login' className='auth-link'>
                Sign In
              </Link>
              <Link to='/signup' className='auth-link'>
                Sign Up
              </Link>
            </div>
          )}
        </div>
      </div>
    </nav>
  );
};

export default Navigation;
