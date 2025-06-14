import { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import {
  User,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signOut,
  onAuthStateChanged,
  sendPasswordResetEmail,
  GoogleAuthProvider,
  signInWithPopup,
} from 'firebase/auth';
import { auth, isFirebaseConfigured } from '../services/firebase';

// Use mock authentication in development mode
const isDevelopmentMode = import.meta.env.MODE === 'development';

interface AuthContextType {
  currentUser: User | null;
  loading: boolean;
  signin: (_email: string, _password: string) => Promise<void>;
  signup: (_email: string, _password: string) => Promise<void>;
  signout: () => Promise<void>;
  resetPassword: (_email: string) => Promise<void>;
  signinWithGoogle: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

interface AuthProviderProps {
  children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  async function signin(email: string, password: string): Promise<void> {
    if (isDevelopmentMode) {
      // Mock authentication for development
      const mockUser = {
        uid: 'dev-user-123',
        email: email,
        displayName: 'Development User',
        emailVerified: true,
      } as User;
      setCurrentUser(mockUser);
      return;
    }
    if (!isFirebaseConfigured) {
      throw new Error('Firebase is not configured. Please set up Firebase authentication.');
    }
    await signInWithEmailAndPassword(auth, email, password);
  }

  async function signup(email: string, password: string): Promise<void> {
    if (isDevelopmentMode) {
      // Mock signup for development
      const mockUser = {
        uid: 'dev-user-123',
        email: email,
        displayName: 'Development User',
        emailVerified: true,
      } as User;
      setCurrentUser(mockUser);
      return;
    }
    if (!isFirebaseConfigured) {
      throw new Error('Firebase is not configured. Please set up Firebase authentication.');
    }
    await createUserWithEmailAndPassword(auth, email, password);
  }

  async function signout(): Promise<void> {
    if (isDevelopmentMode) {
      setCurrentUser(null);
      return;
    }
    if (!isFirebaseConfigured) {
      setCurrentUser(null);
      return;
    }
    await signOut(auth);
  }

  async function resetPassword(email: string): Promise<void> {
    if (isDevelopmentMode) {
      // Mock password reset for development
      return;
    }
    if (!isFirebaseConfigured) {
      throw new Error('Firebase is not configured. Please set up Firebase authentication.');
    }
    await sendPasswordResetEmail(auth, email);
  }

  async function signinWithGoogle(): Promise<void> {
    if (isDevelopmentMode) {
      // Mock Google signin for development
      const mockUser = {
        uid: 'dev-user-google-123',
        email: 'dev@example.com',
        displayName: 'Development Google User',
        emailVerified: true,
      } as User;
      setCurrentUser(mockUser);
      return;
    }
    if (!isFirebaseConfigured) {
      throw new Error('Firebase is not configured. Please set up Firebase authentication.');
    }
    const provider = new GoogleAuthProvider();
    await signInWithPopup(auth, provider);
  }

  useEffect(() => {
    if (isDevelopmentMode) {
      // In development mode, auto-login as mock user
      const mockUser = {
        uid: 'dev-user-auto-123',
        email: 'dev@example.com',
        displayName: 'Auto Development User',
        emailVerified: true,
      } as User;
      setCurrentUser(mockUser);
      setLoading(false);
      return () => {}; // Return empty cleanup function
    }

    // Check if Firebase is configured
    if (!isFirebaseConfigured) {
      // Firebase not configured, no authentication required
      setCurrentUser(null);
      setLoading(false);
      return () => {};
    }

    // Use Firebase auth when configured
    try {
      const unsubscribe = onAuthStateChanged(auth, (user) => {
        setCurrentUser(user);
        setLoading(false);
      });
      return unsubscribe;
    } catch (error) {
      // Firebase auth error - silently handle in development mode
      // If Firebase fails, set to no authentication
      setCurrentUser(null);
      setLoading(false);
      return () => {};
    }
  }, []);

  const value: AuthContextType = {
    currentUser,
    loading,
    signin,
    signup,
    signout,
    resetPassword,
    signinWithGoogle,
  };

  return <AuthContext.Provider value={value}>{!loading && children}</AuthContext.Provider>;
}
