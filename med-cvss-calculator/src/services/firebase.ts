import { initializeApp } from 'firebase/app';
import { getFirestore } from 'firebase/firestore';
import { getAuth } from 'firebase/auth';

// Check if Firebase is configured (exclude placeholder values)
const getFirebaseApiKey = () => {
  const viteKey = import.meta.env.VITE_FIREBASE_API_KEY;
  const reactKey = import.meta.env.REACT_APP_FIREBASE_API_KEY;

  // Exclude placeholder/demo values
  if (viteKey && !viteKey.includes('your-api-key') && !viteKey.includes('demo-api-key')) {
    return viteKey;
  }
  if (reactKey && !reactKey.includes('your-api-key') && !reactKey.includes('demo-api-key')) {
    return reactKey;
  }
  return null;
};

const isFirebaseConfigured = Boolean(getFirebaseApiKey());

// Firebase configuration
const firebaseConfig = {
  apiKey: getFirebaseApiKey() || 'demo-api-key',
  authDomain:
    import.meta.env.VITE_FIREBASE_AUTH_DOMAIN ||
    import.meta.env.REACT_APP_FIREBASE_AUTH_DOMAIN ||
    'medical-cvss-demo.firebaseapp.com',
  projectId:
    import.meta.env.VITE_FIREBASE_PROJECT_ID ||
    import.meta.env.REACT_APP_FIREBASE_PROJECT_ID ||
    'medical-cvss-demo',
  storageBucket:
    import.meta.env.VITE_FIREBASE_STORAGE_BUCKET ||
    import.meta.env.REACT_APP_FIREBASE_STORAGE_BUCKET ||
    'medical-cvss-demo.appspot.com',
  messagingSenderId:
    import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID ||
    import.meta.env.REACT_APP_FIREBASE_MESSAGING_SENDER_ID ||
    '123456789',
  appId:
    import.meta.env.VITE_FIREBASE_APP_ID ||
    import.meta.env.REACT_APP_FIREBASE_APP_ID ||
    'demo-app-id',
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
