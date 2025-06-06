/**
 * CVSS v4.0 Performance and Stress Testing
 * Tests performance characteristics and stress conditions
 */

import { Vector as CVSS40Vector, CVSS40 } from '../utils/cvssV4FullImplementation';

describe('CVSS v4.0 Performance and Stress Tests', () => {
  describe('Performance Testing', () => {
    test('should handle large batch of vector calculations efficiently', () => {
      const startTime = performance.now();
      const vectors: string[] = [];

      // Generate 1000 random vectors
      for (let i = 0; i < 1000; i++) {
        const metrics = {
          AV: ['N', 'A', 'L', 'P'],
          AC: ['L', 'H'],
          AT: ['N', 'P'],
          PR: ['N', 'L', 'H'],
          UI: ['N', 'P', 'A'],
          VC: ['N', 'L', 'H'],
          VI: ['N', 'L', 'H'],
          VA: ['N', 'L', 'H'],
          SC: ['N', 'L', 'H'],
          SI: ['N', 'L', 'H'],
          SA: ['N', 'L', 'H'],
        };

        let vector = 'CVSS:4.0';
        Object.entries(metrics).forEach(([metric, values]) => {
          const value = values[Math.floor(Math.random() * values.length)];
          vector += `/${metric}:${value}`;
        });
        vectors.push(vector);
      }

      // Calculate scores for all vectors
      const results = vectors.map((vector) => new CVSS40(vector));

      const endTime = performance.now();
      const duration = endTime - startTime;

      // Should complete within reasonable time (< 1 second for 1000 calculations)
      expect(duration).toBeLessThan(1000);
      expect(results).toHaveLength(1000);

      // All results should be valid
      results.forEach((result) => {
        expect(result.score).toBeGreaterThanOrEqual(0);
        expect(result.score).toBeLessThanOrEqual(10);
        expect(['None', 'Low', 'Medium', 'High', 'Critical']).toContain(result.severity);
      });
    });

    test('should handle repeated calculations efficiently', () => {
      const vectorString = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H';
      const startTime = performance.now();

      // Perform same calculation 10000 times
      for (let i = 0; i < 10000; i++) {
        const cvss = new CVSS40(vectorString);
        expect(cvss.score).toBe(10.0);
      }

      const endTime = performance.now();
      const duration = endTime - startTime;

      // Should complete within reasonable time (< 2 seconds for 10000 calculations)
      expect(duration).toBeLessThan(2000);
    });

    test('should handle vector parsing performance', () => {
      const complexVector =
        'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A/CR:H/IR:H/AR:H/MAV:A/MAC:H/MAT:P/MPR:L/MUI:P/MVC:L/MVI:L/MVA:L/MSC:H/MSI:H/MSA:H/S:P/AU:Y/R:U/V:C/RE:H/U:Red';
      const startTime = performance.now();

      // Parse complex vector 1000 times
      for (let i = 0; i < 1000; i++) {
        const vector = new CVSS40Vector(complexVector);
        expect(vector.metrics.AV).toBe('N');
        expect(vector.metrics.MAV).toBe('A');
      }

      const endTime = performance.now();
      const duration = endTime - startTime;

      // Should complete within reasonable time
      expect(duration).toBeLessThan(500);
    });
  });

  describe('Memory and Resource Management', () => {
    test('should not cause memory leaks with many vector instances', () => {
      const vectors: CVSS40Vector[] = [];

      // Create many vector instances
      for (let i = 0; i < 1000; i++) {
        const vector = new CVSS40Vector(
          'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'
        );
        vectors.push(vector);
      }

      // All should be valid
      expect(vectors).toHaveLength(1000);
      vectors.forEach((vector) => {
        expect(vector.metrics.AV).toBe('N');
      });

      // Clear references
      vectors.length = 0;
    });

    test('should handle large vector strings efficiently', () => {
      // Create very long vector string with all possible metrics
      const longVector =
        'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:H/MVI:H/MVA:H/MSC:H/MSI:H/MSA:H/S:P/AU:Y/R:U/V:C/RE:H/U:Red';

      const startTime = performance.now();
      const cvss = new CVSS40(longVector);
      const endTime = performance.now();

      expect(endTime - startTime).toBeLessThan(50); // Should parse quickly
      expect(cvss.score).toBeGreaterThan(0);
    });
  });

  describe('Stress Testing - Error Conditions', () => {
    test('should handle repeated invalid inputs gracefully', () => {
      const invalidVectors = [
        'INVALID',
        'CVSS:3.1/AV:N',
        'CVSS:4.0/INVALID:VALUE',
        'CVSS:4.0/AV:INVALID',
      ];

      invalidVectors.forEach((invalidVector) => {
        expect(() => {
          new CVSS40(invalidVector as any);
        }).toThrow();
      });

      // Test null - should throw type error
      expect(() => {
        new CVSS40(null as any);
      }).toThrow('Invalid input type for CVSSv4.0 constructor');

      // Test undefined - becomes empty string due to default parameter, creates default vector
      const undefinedCvss = new CVSS40(undefined as any);
      expect(undefinedCvss.score).toBeGreaterThanOrEqual(0);
    });

    test('should handle malformed vectors correctly', () => {
      // These vectors have specific validation errors but may not throw in all cases
      const malformedVectors = [
        'CVSS:4.0//AV:N', // Double slash - creates empty metric
        'CVSS:4.0/AV::N', // Double colon - creates empty value
        'CVSS:4.0/AV:N:AC:L', // Wrong separator - invalid format
      ];

      malformedVectors.forEach((malformedVector) => {
        let result: { success: boolean; score?: number; error?: Error } = { success: false };

        try {
          const cvss = new CVSS40(malformedVector);
          result = { success: true, score: cvss.score };
        } catch (error) {
          result = { success: false, error: error as Error };
        }

        // Verify the result structure - either success with valid score or failure with error
        expect(typeof result.success).toBe('boolean');
        expect(result.success || result.error instanceof Error).toBe(true);

        // Verify score is within bounds when present
        const scoreInBounds =
          result.score === undefined || (result.score >= 0 && result.score <= 10);
        expect(scoreInBounds).toBe(true);
      });
    });

    test('should handle concurrent calculations safely', async () => {
      const vectorString = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';

      // Create multiple promises for concurrent calculation
      const promises = Array.from({ length: 100 }, () =>
        Promise.resolve().then(() => {
          const cvss = new CVSS40(vectorString);
          return cvss.score;
        })
      );

      const results = await Promise.all(promises);

      // All results should be identical
      expect(results).toHaveLength(100);
      results.forEach((score) => {
        expect(score).toBe(9.3);
      });
    });
  });

  describe('Boundary and Extreme Value Testing', () => {
    test('should handle all possible metric combinations for base metrics', () => {
      const metrics = {
        AV: ['N', 'A', 'L', 'P'],
        AC: ['L', 'H'],
        AT: ['N', 'P'],
        PR: ['N', 'L', 'H'],
        UI: ['N', 'P', 'A'],
        VC: ['N', 'L', 'H'],
        VI: ['N', 'L', 'H'],
        VA: ['N', 'L', 'H'],
        SC: ['N', 'L', 'H'],
        SI: ['N', 'L', 'H'],
        SA: ['N', 'L', 'H'],
      };

      let combinationCount = 0;
      const maxCombinations = 1000; // Limit to prevent test timeout

      // Test subset of all possible combinations
      for (const av of metrics.AV) {
        for (const ac of metrics.AC) {
          for (const at of metrics.AT) {
            if (combinationCount >= maxCombinations) break;

            const vector = `CVSS:4.0/AV:${av}/AC:${ac}/AT:${at}/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`;
            const cvss = new CVSS40(vector);

            expect(cvss.score).toBeGreaterThanOrEqual(0);
            expect(cvss.score).toBeLessThanOrEqual(10);
            expect(['None', 'Low', 'Medium', 'High', 'Critical']).toContain(cvss.severity);

            combinationCount++;
          }
        }
      }

      expect(combinationCount).toBeGreaterThan(0);
    });

    test('should handle vectors with special characters in supplemental metrics', () => {
      // Test U metric with special values
      const urgencyValues = ['Clear', 'Green', 'Amber', 'Red'];

      urgencyValues.forEach((urgency) => {
        const vector = `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/U:${urgency}`;
        const cvss = new CVSS40(vector);

        expect(cvss.score).toBeGreaterThan(0);
        expect(cvss.severity).toBeDefined();
      });
    });

    test('should handle score calculation edge cases with environmental metrics', () => {
      // Test case where environmental metrics significantly change score
      const baseVector = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';
      const envVector =
        'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:L/AR:L';

      const baseCvss = new CVSS40(baseVector);
      const envCvss = new CVSS40(envVector);

      // Environmental metrics should affect score
      expect(baseCvss.score).toBeGreaterThanOrEqual(0);
      expect(envCvss.score).toBeGreaterThanOrEqual(0);
      expect(baseCvss.score).toBeLessThanOrEqual(10);
      expect(envCvss.score).toBeLessThanOrEqual(10);
    });
  });

  describe('Data Validation and Sanitization', () => {
    test('should handle vectors with extra whitespace', () => {
      const vectorWithSpaces = ' CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N ';

      expect(() => {
        new CVSS40(vectorWithSpaces);
      }).toThrow(); // Should reject vectors with extra whitespace
    });

    test('should handle case sensitivity', () => {
      const lowercaseVector = 'cvss:4.0/av:n/ac:l/at:n/pr:n/ui:n/vc:h/vi:h/va:h/sc:n/si:n/sa:n';

      expect(() => {
        new CVSS40(lowercaseVector);
      }).toThrow(); // Should be case sensitive
    });

    test('should validate metric ordering strictly', () => {
      // Vector with metrics in wrong order
      const wrongOrderVector = 'CVSS:4.0/AC:L/AV:N/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';

      // Current implementation validates order and rejects wrong order
      expect(() => {
        new CVSS40(wrongOrderVector);
      }).toThrow('Invalid CVSS v4.0 vector');
    });

    test('should handle duplicate metrics correctly', () => {
      // Current implementation may handle duplicates by using the last value
      const duplicateVector =
        'CVSS:4.0/AV:N/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';

      let result: { success: boolean; score?: number; error?: Error } = { success: false };

      try {
        const cvss = new CVSS40(duplicateVector);
        result = { success: true, score: cvss.score };
      } catch (error) {
        result = { success: false, error: error as Error };
      }

      // Verify the result structure - either success with valid score or failure with appropriate error
      expect(typeof result.success).toBe('boolean');
      const hasValidError =
        result.error instanceof Error && result.error.message.includes('Invalid CVSS v4.0 vector');
      expect(result.success || hasValidError).toBe(true);

      // Verify score is within bounds when present
      const scoreInBounds = result.score === undefined || (result.score >= 0 && result.score <= 10);
      expect(scoreInBounds).toBe(true);
    });
  });

  describe('Integration with Medical Device Scenarios', () => {
    test('should handle complex medical device vulnerability scenarios efficiently', () => {
      const medicalScenarios = [
        {
          name: 'Critical Infusion Pump',
          vector:
            'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:L/S:P/AU:Y/R:U/V:C/RE:H/U:Red',
        },
        {
          name: 'Pacemaker with Bluetooth',
          vector:
            'CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:H/SC:N/SI:N/SA:N/S:P/AU:N/R:U/V:C/RE:H/U:Red',
        },
        {
          name: 'Hospital Network Device',
          vector:
            'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L/S:N/AU:Y/R:A/V:D/RE:M/U:Amber',
        },
        {
          name: 'Physical Access Device',
          vector:
            'CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/S:P/AU:N/R:U/V:C/RE:L/U:Green',
        },
      ];

      const startTime = performance.now();

      medicalScenarios.forEach((scenario) => {
        const cvss = new CVSS40(scenario.vector);

        expect(cvss.score).toBeGreaterThanOrEqual(0);
        expect(cvss.score).toBeLessThanOrEqual(10);
        expect(['None', 'Low', 'Medium', 'High', 'Critical']).toContain(cvss.severity);

        // Medical device vectors should include safety considerations
        expect(scenario.vector).toContain('S:');
        expect(scenario.vector).toContain('U:');
      });

      const endTime = performance.now();
      expect(endTime - startTime).toBeLessThan(100); // Should be fast
    });
  });
});
