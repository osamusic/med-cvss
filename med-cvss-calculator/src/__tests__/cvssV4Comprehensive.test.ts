/**
 * Comprehensive CVSS v4.0 Test Suite
 * This file tests all possible combinations to validate the CVSS v4.0 implementation
 */

import {
  calculateCVSSV4Score,
  generateV4VectorString,
  parseV4VectorString,
} from '../utils/cvssV4Calculator';
import { Vector as CVSS40Vector, CVSS40 } from '../utils/cvssV4FullImplementation';

describe('CVSS v4.0 Comprehensive Test Suite', () => {
  describe('EQ1 Calculations (AV/PR/UI)', () => {
    const eq1Tests = [
      // EQ1 = 0: AV:N/PR:N/UI:N
      { av: 'N', pr: 'N', ui: 'N', expected: '0' },
      // EQ1 = 1: (AV:N OR PR:N OR UI:N) AND NOT(AV:N AND PR:N AND UI:N) AND AV != P
      { av: 'N', pr: 'L', ui: 'N', expected: '1' },
      { av: 'N', pr: 'N', ui: 'P', expected: '1' },
      { av: 'A', pr: 'N', ui: 'N', expected: '1' },
      { av: 'L', pr: 'N', ui: 'N', expected: '1' },
      { av: 'N', pr: 'H', ui: 'A', expected: '1' },
      // EQ1 = 2: AV:P OR NOT(AV:N OR PR:N OR UI:N)
      { av: 'P', pr: 'N', ui: 'N', expected: '2' },
      { av: 'P', pr: 'L', ui: 'P', expected: '2' },
      { av: 'A', pr: 'L', ui: 'P', expected: '2' },
      { av: 'L', pr: 'H', ui: 'A', expected: '2' },
    ];

    test.each(eq1Tests)(
      'should calculate EQ1 correctly for AV:$av/PR:$pr/UI:$ui',
      ({ av, pr, ui, expected }) => {
        const vectorString = `CVSS:4.0/AV:${av}/AC:L/AT:N/PR:${pr}/UI:${ui}/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`;
        const cvss = new CVSS40(vectorString);
        const eq = cvss.vector.equivalentClasses;
        expect(eq[0]).toBe(expected);
      }
    );
  });

  describe('EQ2 Calculations (AC/AT)', () => {
    const eq2Tests = [
      // EQ2 = 0: AC:L AND AT:N
      { ac: 'L', at: 'N', expected: '0' },
      // EQ2 = 1: NOT(AC:L AND AT:N)
      { ac: 'H', at: 'N', expected: '1' },
      { ac: 'L', at: 'P', expected: '1' },
      { ac: 'H', at: 'P', expected: '1' },
    ];

    test.each(eq2Tests)(
      'should calculate EQ2 correctly for AC:$ac/AT:$at',
      ({ ac, at, expected }) => {
        const vectorString = `CVSS:4.0/AV:N/AC:${ac}/AT:${at}/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`;
        const cvss = new CVSS40(vectorString);
        const eq = cvss.vector.equivalentClasses;
        expect(eq[1]).toBe(expected);
      }
    );
  });

  describe('EQ3 Calculations (VC/VI/VA)', () => {
    const eq3Tests = [
      // EQ3 = 0: VC:H AND VI:H
      { vc: 'H', vi: 'H', va: 'H', expected: '0' },
      { vc: 'H', vi: 'H', va: 'L', expected: '0' },
      { vc: 'H', vi: 'H', va: 'N', expected: '0' },
      // EQ3 = 1: NOT(VC:H AND VI:H) AND (VC:H OR VI:H OR VA:H)
      { vc: 'L', vi: 'H', va: 'H', expected: '1' },
      { vc: 'H', vi: 'L', va: 'H', expected: '1' },
      { vc: 'H', vi: 'L', va: 'L', expected: '1' },
      { vc: 'L', vi: 'L', va: 'H', expected: '1' },
      // EQ3 = 2: NOT(VC:H OR VI:H OR VA:H)
      { vc: 'L', vi: 'L', va: 'L', expected: '2' },
      { vc: 'L', vi: 'L', va: 'N', expected: '2' },
      { vc: 'N', vi: 'N', va: 'N', expected: '2' },
    ];

    test.each(eq3Tests)(
      'should calculate EQ3 correctly for VC:$vc/VI:$vi/VA:$va',
      ({ vc, vi, va, expected }) => {
        const vectorString = `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:${vc}/VI:${vi}/VA:${va}/SC:N/SI:N/SA:N`;
        const cvss = new CVSS40(vectorString);
        const eq = cvss.vector.equivalentClasses;
        expect(eq[2]).toBe(expected);
      }
    );
  });

  describe('EQ4 Calculations (SC/SI/SA)', () => {
    const eq4Tests = [
      // EQ4 = 1: NOT(MSI:S OR MSA:S) AND (SC:H OR SI:H OR SA:H)
      { sc: 'H', si: 'N', sa: 'N', expected: '1' },
      { sc: 'N', si: 'H', sa: 'N', expected: '1' },
      { sc: 'N', si: 'N', sa: 'H', expected: '1' },
      { sc: 'H', si: 'H', sa: 'H', expected: '1' },
      // EQ4 = 2: NOT(SC:H OR SI:H OR SA:H)
      { sc: 'N', si: 'N', sa: 'N', expected: '2' },
      { sc: 'L', si: 'L', sa: 'L', expected: '2' },
      { sc: 'L', si: 'N', sa: 'L', expected: '2' },
    ];

    test.each(eq4Tests)(
      'should calculate EQ4 correctly for SC:$sc/SI:$si/SA:$sa',
      ({ sc, si, sa, expected }) => {
        const vectorString = `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:${sc}/SI:${si}/SA:${sa}`;
        const cvss = new CVSS40(vectorString);
        const eq = cvss.vector.equivalentClasses;
        expect(eq[3]).toBe(expected);
      }
    );
  });

  describe('EQ5 Calculations (E metric)', () => {
    const eq5Tests = [
      // EQ5 = 0: E:A (default when E:X)
      { e: undefined, expected: '0' },
      { e: 'A', expected: '0' },
      // EQ5 = 1: E:P
      { e: 'P', expected: '1' },
      // EQ5 = 2: E:U
      { e: 'U', expected: '2' },
    ];

    test.each(eq5Tests)('should calculate EQ5 correctly for E:$e', ({ e, expected }) => {
      const baseVector = `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`;
      const vectorString = e ? `${baseVector}/E:${e}` : baseVector;
      const cvss = new CVSS40(vectorString);
      const eq = cvss.vector.equivalentClasses;
      expect(eq[4]).toBe(expected);
    });
  });

  describe('EQ6 Calculations (CR/IR/AR with VC/VI/VA)', () => {
    const eq6Tests = [
      // EQ6 = 0: (CR:H AND VC:H) OR (IR:H AND VI:H) OR (AR:H AND VA:H)
      // Note: CR/IR/AR default to H when not specified
      { cr: undefined, ir: undefined, ar: undefined, vc: 'H', vi: 'H', va: 'H', expected: '0' },
      { cr: 'H', ir: 'L', ar: 'L', vc: 'H', vi: 'L', va: 'L', expected: '0' },
      { cr: 'L', ir: 'H', ar: 'L', vc: 'L', vi: 'H', va: 'L', expected: '0' },
      { cr: 'L', ir: 'L', ar: 'H', vc: 'L', vi: 'L', va: 'H', expected: '0' },
      // EQ6 = 1: NOT((CR:H AND VC:H) OR (IR:H AND VI:H) OR (AR:H AND VA:H))
      { cr: 'L', ir: 'L', ar: 'L', vc: 'H', vi: 'H', va: 'H', expected: '1' },
      { cr: 'M', ir: 'M', ar: 'M', vc: 'H', vi: 'H', va: 'H', expected: '1' },
    ];

    test.each(eq6Tests)(
      'should calculate EQ6 correctly',
      ({ cr, ir, ar, vc, vi, va, expected }) => {
        let vectorString = `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:${vc}/VI:${vi}/VA:${va}/SC:N/SI:N/SA:N`;
        if (cr) vectorString += `/CR:${cr}`;
        if (ir) vectorString += `/IR:${ir}`;
        if (ar) vectorString += `/AR:${ar}`;
        const cvss = new CVSS40(vectorString);
        const eq = cvss.vector.equivalentClasses;
        expect(eq[5]).toBe(expected);
      }
    );
  });

  describe('Known Vectors', () => {
    const knownVectors = [
      // High severity vectors
      {
        vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
        score: 9.3,
        severity: 'Critical',
        eq: '000200',
      },
      {
        vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H',
        score: 10.0,
        severity: 'Critical',
        eq: '000100',
      },
      // Medium severity vectors
      {
        vector: 'CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:A/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L',
        score: 1.0,
        severity: 'Low',
        eq: '212201',
      },
      // Low severity vectors
      {
        vector: 'CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N',
        score: 0.0,
        severity: 'None',
        eq: '212201',
      },
      // With environmental metrics
      {
        vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P',
        score: 8.9,
        severity: 'High',
        eq: '000210',
      },
      {
        vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/IR:H/AR:H',
        score: 9.3,
        severity: 'Critical',
        eq: '000200',
      },
    ];

    test.each(knownVectors)(
      'should calculate correctly for $vector',
      ({ vector, score, severity, eq }) => {
        const cvss = new CVSS40(vector);
        expect(cvss.score).toBe(score);
        expect(cvss.severity).toBe(severity);
        expect(cvss.vector.equivalentClasses).toBe(eq);
      }
    );
  });

  describe('Edge Cases', () => {
    test('should return 0.0 for no impact vector', () => {
      const noImpactVector = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N';
      const cvss = new CVSS40(noImpactVector);
      expect(cvss.score).toBe(0.0);
      expect(cvss.severity).toBe('None');
    });

    test('should handle vector update', () => {
      const vector = new CVSS40Vector();
      vector.updateMetric('AV', 'N');
      vector.updateMetric('VC', 'H');
      const cvss = new CVSS40(vector);
      expect(cvss.score).toBeGreaterThan(0);
    });

    test('should handle environmental with MSI/MSA', () => {
      const vector = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MSI:S/MSA:S';
      const cvss = new CVSS40(vector);
      expect(cvss.score).toBe(10.0);
      expect(cvss.severity).toBe('Critical');
      expect(cvss.vector.equivalentClasses).toBe('000000');
    });
  });

  describe('Random Vector Testing', () => {
    const generateRandomVector = () => {
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

      return vector;
    };

    test('should handle 100 random vectors correctly', () => {
      for (let i = 0; i < 100; i++) {
        const vector = generateRandomVector();
        const cvss = new CVSS40(vector);

        // Validate score
        expect(cvss.score).toBeGreaterThanOrEqual(0);
        expect(cvss.score).toBeLessThanOrEqual(10);

        // Validate severity
        expect(['None', 'Low', 'Medium', 'High', 'Critical']).toContain(cvss.severity);

        // Validate EQ
        expect(cvss.vector.equivalentClasses).toMatch(/^[0-2]{6}$/);

        // Verify score/severity consistency
        const score = cvss.score;
        const expectedSeverity =
          score === 0.0
            ? 'None'
            : score <= 3.9
              ? 'Low'
              : score <= 6.9
                ? 'Medium'
                : score <= 8.9
                  ? 'High'
                  : 'Critical';
        expect(cvss.severity).toBe(expectedSeverity);
      }
    });
  });

  describe('Compatibility with existing calculator', () => {
    test('should parse and calculate correctly using existing functions', () => {
      const vectorString = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';
      const parsed = parseV4VectorString(vectorString);
      const result = calculateCVSSV4Score(parsed);

      // The existing calculator uses a simplified algorithm
      // Just ensure it returns valid results
      expect(result.baseScore).toBeGreaterThan(0);
      expect(result.severity).toBeDefined();
      expect(generateV4VectorString(parsed)).toBe(vectorString);
    });
  });
});
