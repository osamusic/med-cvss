import { initializeApp } from 'firebase/app';
import { getFirestore } from 'firebase/firestore';
import { getAuth } from 'firebase/auth';

// Check if Firebase is configured
const isFirebaseConfigured = Boolean(process.env.REACT_APP_FIREBASE_API_KEY);

// Firebase configuration
const firebaseConfig = {
  apiKey: process.env.REACT_APP_FIREBASE_API_KEY || 'demo-api-key',
  authDomain: process.env.REACT_APP_FIREBASE_AUTH_DOMAIN || 'medical-cvss-demo.firebaseapp.com',
  projectId: process.env.REACT_APP_FIREBASE_PROJECT_ID || 'medical-cvss-demo',
  storageBucket: process.env.REACT_APP_FIREBASE_STORAGE_BUCKET || 'medical-cvss-demo.appspot.com',
  messagingSenderId: process.env.REACT_APP_FIREBASE_MESSAGING_SENDER_ID || '123456789',
  appId: process.env.REACT_APP_FIREBASE_APP_ID || 'demo-app-id',
};

// Initialize Firebase only if configured
let app: any = null;
let db: any = null;
let auth: any = null;

if (isFirebaseConfigured) {
  app = initializeApp(firebaseConfig);
  db = getFirestore(app);
  auth = getAuth(app);
} else {
  // Mock objects for development mode
  app = { name: 'mock-app' };
  db = { name: 'mock-firestore' };
  auth = { name: 'mock-auth' };
}

export { db, auth, isFirebaseConfigured };

export default app;
