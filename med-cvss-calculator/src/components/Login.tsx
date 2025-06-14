import React, { useState } from 'react';
import { Navigate, useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import './Login.css';

const Login: React.FC = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { signin, signinWithGoogle, currentUser } = useAuth();
  const navigate = useNavigate();

  if (currentUser) {
    return <Navigate to='/' replace />;
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    try {
      setError('');
      setLoading(true);
      await signin(email, password);
      navigate('/threat-analysis');
    } catch (error) {
      setError('Failed to sign in. Please check your credentials.');
      // eslint-disable-next-line no-console
      console.error('Login error:', error);
    }
    setLoading(false);
  };

  const handleGoogleSignIn = async () => {
    try {
      setError('');
      setLoading(true);
      await signinWithGoogle();
      navigate('/threat-analysis');
    } catch (error) {
      setError('Failed to sign in with Google.');
      // eslint-disable-next-line no-console
      console.error('Google sign in error:', error);
    }
    setLoading(false);
  };

  return (
    <div className='login-container'>
      <div className='login-form'>
        <h2>Sign In</h2>
        <p className='login-description'>
          Sign in to access advanced features like Before/After Comparison.
          <br />
          The{' '}
          <Link to='/' className='calculator-link'>
            CVSS Calculator
          </Link>{' '}
          is available without signing in.
        </p>

        {error && <div className='error-message'>{error}</div>}

        <form onSubmit={handleSubmit}>
          <div className='form-group'>
            <label htmlFor='email'>Email</label>
            <input
              type='email'
              id='email'
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>

          <div className='form-group'>
            <label htmlFor='password'>Password</label>
            <input
              type='password'
              id='password'
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>

          <button type='submit' disabled={loading} className='signin-button'>
            {loading ? 'Signing In...' : 'Sign In'}
          </button>
        </form>

        <div className='divider'>or</div>

        <button onClick={handleGoogleSignIn} disabled={loading} className='google-signin-button'>
          {loading ? 'Signing In...' : 'Sign In with Google'}
        </button>

        <p className='signup-link'>
          Don't have an account? <Link to='/signup'>Sign Up</Link>
        </p>
      </div>
    </div>
  );
};

export default Login;
