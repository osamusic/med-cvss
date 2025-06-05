# Firebase Setup Guide for Medical Device CVSS Calculator

This guide explains how to set up Firebase for server-side storage of custom CVSS scenarios.

## 🔥 Firebase Project Setup

### 1. Create Firebase Project

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Click "Create a project"
3. Enter project name: `medical-cvss-calculator` (or your preferred name)
4. Choose your analytics preferences
5. Click "Create project"

### 2. Enable Firestore Database

1. In the Firebase console, go to **Build > Firestore Database**
2. Click "Create database"
3. Choose **"Start in test mode"** (we'll configure security rules later)
4. Select your preferred region (closest to your users)
5. Click "Done"

### 3. Enable Authentication

1. Go to **Build > Authentication**
2. Click "Get started"
3. Go to **Sign-in method** tab
4. Enable the following providers:
   - **Email/Password**: Enable and save
   - **Google**: Enable, configure OAuth consent, and save
5. Optionally add authorized domains for production

### 4. Get Firebase Configuration

1. Go to **Project Settings** (gear icon)
2. Scroll down to "Your apps" section
3. Click "Add app" → Web app (</>) icon
4. Enter app nickname: `medical-cvss-web`
5. Check "Set up Firebase Hosting" if desired
6. Click "Register app"
7. Copy the Firebase configuration object

## 🔧 Environment Variables Setup

### 1. Create Environment File

Create a `.env.local` file in the project root:

```bash
# Firebase Configuration
REACT_APP_FIREBASE_API_KEY=your_api_key_here
REACT_APP_FIREBASE_AUTH_DOMAIN=your_project_id.firebaseapp.com
REACT_APP_FIREBASE_PROJECT_ID=your_project_id
REACT_APP_FIREBASE_STORAGE_BUCKET=your_project_id.appspot.com
REACT_APP_FIREBASE_MESSAGING_SENDER_ID=your_sender_id
REACT_APP_FIREBASE_APP_ID=your_app_id

# Optional: Enable Firebase Emulator (for development)
REACT_APP_USE_FIREBASE_EMULATOR=false
```

### 2. Example Configuration

Your Firebase config object should look like this:

```javascript
const firebaseConfig = {
  apiKey: "AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  authDomain: "medical-cvss-calculator.firebaseapp.com",
  projectId: "medical-cvss-calculator",
  storageBucket: "medical-cvss-calculator.appspot.com",
  messagingSenderId: "123456789012",
  appId: "1:123456789012:web:abcdefghijklmnop"
};
```

## 🔒 Firestore Security Rules

### 1. Set Security Rules

Go to **Firestore Database > Rules** and replace the default rules with:

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Scenarios collection - users can only access their own scenarios
    match /scenarios/{scenarioId} {
      allow read, write: if request.auth != null 
        && request.auth.uid != null
        && resource.data.userId == request.auth.uid;
      
      allow create: if request.auth != null 
        && request.auth.uid != null
        && request.auth.uid == resource.data.userId;
    }
    
    // Deny all other access
    match /{document=**} {
      allow read, write: if false;
    }
  }
}
```

### 2. Publish Rules

Click "Publish" to apply the security rules.

## 📊 Data Structure

### Scenarios Collection

```typescript
// Collection: scenarios
// Document ID: auto-generated
{
  title: string;              // "Network-Connected Device Example"
  description: string;        // "Example of network isolation"
  before: {                   // CVSS vector before remediation
    AV: 'N',
    AC: 'L',
    // ... other metrics
  };
  after: {                    // CVSS vector after remediation
    AV: 'L',
    AC: 'L',
    // ... other metrics
  };
  remediationActions: string[]; // ["Network segmentation", "Authentication"]
  userId: string;             // Firebase Auth UID
  createdAt: Timestamp;       // Auto-generated
  updatedAt: Timestamp;       // Auto-updated
}
```

## 🚀 Testing the Setup

### 1. Start Development Server

```bash
npm start
```

### 2. Test Storage Provider

1. Go to the "Before/After Comparison" tab
2. Try creating a new scenario
3. Check if it appears in the Firestore console

### 3. Test Authentication

1. Try to sign in with email/password or Google
2. Verify that scenarios are user-specific

## 🔧 Troubleshooting

### Common Issues

1. **"Firebase config not found"**
   - Verify `.env.local` file exists
   - Check environment variable names start with `REACT_APP_`
   - Restart development server after adding variables

2. **"Permission denied" errors**
   - Check Firestore security rules
   - Ensure user is authenticated
   - Verify `userId` field matches `auth.uid`

3. **Authentication not working**
   - Check authorized domains in Firebase console
   - Verify OAuth configuration for Google sign-in

### Debug Mode

Add this to your `.env.local` for debug logging:

```bash
REACT_APP_FIREBASE_DEBUG=true
```

## 🌐 Production Deployment

### 1. Firebase Hosting (Optional)

```bash
npm install -g firebase-tools
firebase login
firebase init hosting
npm run build
firebase deploy
```

### 2. Environment Variables for Production

Set the same environment variables in your hosting platform (Vercel, Netlify, etc.).

### 3. Security Considerations

- Keep Firebase API keys secure
- Use HTTPS in production
- Regularly review security rules
- Monitor Firebase usage and costs
- Consider implementing user roles/permissions for organizational use

## 💡 Usage in Application

### Switch to Firebase Storage

```typescript
// In your component
const scenarioManager = useCustomScenarios('firebase', user?.uid);
```

### Handle Authentication

```typescript
import { useAuth } from '../contexts/AuthContext';

function MyComponent() {
  const { currentUser, signin, signout } = useAuth();
  
  if (!currentUser) {
    return <LoginForm onSignin={signin} />;
  }
  
  return <CVSSComparison />;
}
```

## 📝 Next Steps

1. Set up Firebase project and Firestore
2. Configure environment variables
3. Test the application with Firebase
4. Deploy to production
5. Monitor usage and performance