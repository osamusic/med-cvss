/**
 * Test script to verify MCP authentication with Bearer token
 * This script demonstrates how the authentication flow works
 */

import { auth } from '../services/firebase';
import { signInWithEmailAndPassword } from 'firebase/auth';

export async function testMCPAuthentication(email: string, password: string, serverUrl: string) {
  try {
    // 1. Sign in to Firebase
    console.log('1. Signing in to Firebase...');
    const userCredential = await signInWithEmailAndPassword(auth, email, password);
    console.log('   ✓ Signed in successfully:', userCredential.user.email);

    // 2. Get ID token
    console.log('\n2. Getting Firebase ID token...');
    const idToken = await userCredential.user.getIdToken();
    console.log('   ✓ ID token obtained (first 20 chars):', idToken.substring(0, 20) + '...');

    // 3. Test authenticated request
    console.log('\n3. Testing authenticated MCP request...');
    const response = await fetch(`${serverUrl}/extract_cvss`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${idToken}`,
      },
      body: JSON.stringify({
        threat_description: 'テスト脅威: 医療機器のBluetooth通信が暗号化されていない',
      }),
    });

    if (response.ok) {
      const result = await response.json();
      console.log('   ✓ Request successful:', result);
    } else {
      console.log('   ✗ Request failed:', response.status, response.statusText);
    }

    // 4. Test without authentication (should fail)
    console.log('\n4. Testing unauthenticated request (should fail)...');
    const unauthResponse = await fetch(`${serverUrl}/extract_cvss`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        threat_description: 'テスト脅威: 医療機器のBluetooth通信が暗号化されていない',
      }),
    });

    if (!unauthResponse.ok) {
      console.log('   ✓ Unauthenticated request correctly rejected:', unauthResponse.status);
    } else {
      console.log('   ✗ Unauthenticated request unexpectedly succeeded');
    }

    return true;
  } catch (error) {
    console.error('Test failed:', error);
    return false;
  }
}

// Usage example:
// testMCPAuthentication('test@example.com', 'password123', 'http://localhost:8000');
