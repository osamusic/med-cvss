import { calculateCVSSScore, generateVectorString } from '../utils/cvssCalculator';
import { CVSSVector } from '../types/cvss';

describe('CVSS Calculator Tests', () => {
  describe('calculateCVSSScore', () => {
    test('calculates correct base score for high severity vulnerability', () => {
      const vector: CVSSVector = {
        AV: 'N', // Network
        AC: 'L', // Low
        PR: 'N', // None
        UI: 'N', // None
        S: 'C', // Changed
        C: 'H', // High
        I: 'H', // High
        A: 'H', // High
      };

      const result = calculateCVSSScore(vector);

      expect(result.baseScore).toBeCloseTo(10.0, 1);
      expect(result.severity).toBe('Critical');
      expect(result.overallScore).toBeCloseTo(10.0, 1);
    });

    test('calculates correct base score for medium severity vulnerability', () => {
      const vector: CVSSVector = {
        AV: 'L', // Local
        AC: 'H', // High
        PR: 'L', // Low
        UI: 'R', // Required
        S: 'U', // Unchanged
        C: 'L', // Low
        I: 'L', // Low
        A: 'N', // None
      };

      const result = calculateCVSSScore(vector);

      expect(result.baseScore).toBeCloseTo(3.3, 1);
      expect(result.severity).toBe('Low');
    });

    test('calculates correct base score for low severity vulnerability', () => {
      const vector: CVSSVector = {
        AV: 'P', // Physical
        AC: 'H', // High
        PR: 'H', // High
        UI: 'R', // Required
        S: 'U', // Unchanged
        C: 'L', // Low
        I: 'N', // None
        A: 'N', // None
      };

      const result = calculateCVSSScore(vector);

      expect(result.baseScore).toBe(1.6);
      expect(result.severity).toBe('Low');
    });

    test('handles empty vector', () => {
      const vector: CVSSVector = {};
      const result = calculateCVSSScore(vector);

      expect(result.baseScore).toBe(0);
      expect(result.severity).toBe('None');
      expect(result.overallScore).toBe(0);
    });

    test('calculates temporal score when temporal metrics provided', () => {
      const vector: CVSSVector = {
        AV: 'N',
        AC: 'L',
        PR: 'N',
        UI: 'N',
        S: 'C',
        C: 'H',
        I: 'H',
        A: 'H',
        E: 'F', // Functional
        RL: 'O', // Official Fix
        RC: 'C', // Confirmed
      };

      const result = calculateCVSSScore(vector);

      expect(result.baseScore).toBeCloseTo(10.0, 1);
      expect(result.temporalScore).toBeGreaterThan(0);
      expect(result.temporalScore).toBeLessThan(result.baseScore);
    });
  });

  describe('generateVectorString', () => {
    test('generates correct CVSS vector string for base metrics only', () => {
      const vector: CVSSVector = {
        AV: 'N',
        AC: 'L',
        PR: 'N',
        UI: 'N',
        S: 'C',
        C: 'H',
        I: 'H',
        A: 'H',
      };

      const result = generateVectorString(vector);

      expect(result).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H');
    });

    test('generates correct CVSS vector string with temporal metrics', () => {
      const vector: CVSSVector = {
        AV: 'N',
        AC: 'L',
        PR: 'N',
        UI: 'N',
        S: 'C',
        C: 'H',
        I: 'H',
        A: 'H',
        E: 'F',
        RL: 'O',
        RC: 'C',
      };

      const result = generateVectorString(vector);

      expect(result).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:F/RL:O/RC:C');
    });

    test('handles partial vector', () => {
      const vector: CVSSVector = {
        AV: 'N',
        AC: 'L',
        C: 'H',
      };

      const result = generateVectorString(vector);

      expect(result).toBe('CVSS:3.1/AV:N/AC:L/C:H');
    });

    test('handles empty vector', () => {
      const vector: CVSSVector = {};
      const result = generateVectorString(vector);

      expect(result).toBe('CVSS:3.1');
    });
  });

  describe('Medical Device Specific Scenarios', () => {
    test('calculates score for network-accessible infusion pump vulnerability', () => {
      const vector: CVSSVector = {
        AV: 'N', // Network accessible
        AC: 'L', // Low complexity
        PR: 'N', // No privileges required
        UI: 'N', // No user interaction
        S: 'U', // Unchanged scope (single device)
        C: 'N', // No confidentiality impact
        I: 'H', // High integrity impact (dosage modification)
        A: 'H', // High availability impact (device shutdown)
      };

      const result = calculateCVSSScore(vector);

      expect(result.baseScore).toBeCloseTo(9.1, 1);
      expect(result.severity).toBe('Critical');
    });

    test('calculates score for Bluetooth medical device with patient data exposure', () => {
      const vector: CVSSVector = {
        AV: 'A', // Adjacent (Bluetooth)
        AC: 'L', // Low complexity
        PR: 'N', // No privileges required
        UI: 'N', // No user interaction
        S: 'U', // Unchanged scope
        C: 'H', // High confidentiality impact (patient data)
        I: 'L', // Low integrity impact
        A: 'N', // No availability impact
      };

      const result = calculateCVSSScore(vector);

      expect(result.baseScore).toBeCloseTo(7.1, 1);
      expect(result.severity).toBe('High');
    });

    test('calculates score for physical access medical device vulnerability', () => {
      const vector: CVSSVector = {
        AV: 'P', // Physical access required
        AC: 'L', // Low complexity
        PR: 'N', // No privileges required
        UI: 'N', // No user interaction
        S: 'U', // Unchanged scope
        C: 'H', // High confidentiality impact
        I: 'H', // High integrity impact
        A: 'H', // High availability impact
      };

      const result = calculateCVSSScore(vector);

      expect(result.baseScore).toBeCloseTo(6.8, 1);
      expect(result.severity).toBe('Medium');
    });

    test('calculates score for medical device requiring privileged access', () => {
      const vector: CVSSVector = {
        AV: 'N', // Network accessible
        AC: 'L', // Low complexity
        PR: 'H', // High privileges required (admin/biomedical engineer)
        UI: 'N', // No user interaction
        S: 'C', // Changed scope (affects hospital network)
        C: 'H', // High confidentiality impact
        I: 'H', // High integrity impact
        A: 'H', // High availability impact
      };

      const result = calculateCVSSScore(vector);

      expect(result.baseScore).toBe(9.1);
      expect(result.severity).toBe('Critical');
    });
  });
});
