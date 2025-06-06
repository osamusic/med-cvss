import {
  calculateCVSSV4Score,
  generateV4VectorString,
  parseV4VectorString,
} from '../utils/cvssV4Calculator';
import { CVSSV4Vector } from '../types/cvss';

describe('CVSS v4.0 Calculator', () => {
  describe('calculateCVSSV4Score', () => {
    test('calculates base score for critical vulnerability', () => {
      const vector: CVSSV4Vector = {
        AV: 'N',
        AC: 'L',
        AT: 'N',
        PR: 'N',
        UI: 'N',
        VC: 'H',
        VI: 'H',
        VA: 'H',
        SC: 'H',
        SI: 'H',
        SA: 'H',
      };

      const result = calculateCVSSV4Score(vector);

      expect(result.baseScore).toBeGreaterThan(8);
      expect(result.severity).toBe('Critical');
      expect(result.overallScore).toBe(result.baseScore);
    });

    test('calculates base score for low impact vulnerability', () => {
      const vector: CVSSV4Vector = {
        AV: 'P',
        AC: 'H',
        AT: 'P',
        PR: 'H',
        UI: 'A',
        VC: 'L',
        VI: 'L',
        VA: 'N',
        SC: 'N',
        SI: 'N',
        SA: 'N',
      };

      const result = calculateCVSSV4Score(vector);

      expect(result.baseScore).toBeLessThan(4);
      expect(result.severity).toMatch(/Low|None/);
    });

    test('calculates threat score when exploit maturity is set', () => {
      const vector: CVSSV4Vector = {
        AV: 'N',
        AC: 'L',
        AT: 'N',
        PR: 'N',
        UI: 'N',
        VC: 'H',
        VI: 'H',
        VA: 'H',
        SC: 'N',
        SI: 'N',
        SA: 'N',
        E: 'A',
      };

      const result = calculateCVSSV4Score(vector);

      expect(result.baseScore).toBeGreaterThan(0);
      expect(result.threatScore).toBeDefined();
      expect(result.threatScore).toBeGreaterThan(0);
      expect(result.overallScore).toBe(result.threatScore);
    });

    test('calculates environmental score when environmental metrics are set', () => {
      const vector: CVSSV4Vector = {
        AV: 'N',
        AC: 'L',
        AT: 'N',
        PR: 'N',
        UI: 'N',
        VC: 'H',
        VI: 'H',
        VA: 'H',
        SC: 'N',
        SI: 'N',
        SA: 'N',
        CR: 'H',
        IR: 'H',
        AR: 'M',
      };

      const result = calculateCVSSV4Score(vector);

      expect(result.baseScore).toBeGreaterThan(0);
      expect(result.environmentalScore).toBeDefined();
      expect(result.environmentalScore).toBeGreaterThan(0);
      expect(result.overallScore).toBe(result.environmentalScore);
    });

    test('handles missing required metrics gracefully', () => {
      const vector: CVSSV4Vector = {
        AV: 'N',
        AC: 'L',
      };

      const result = calculateCVSSV4Score(vector);

      expect(result.baseScore).toBeGreaterThanOrEqual(0);
      expect(result.severity).toBeDefined();
    });
  });

  describe('generateV4VectorString', () => {
    test('generates correct vector string for base metrics only', () => {
      const vector: CVSSV4Vector = {
        AV: 'N',
        AC: 'L',
        AT: 'N',
        PR: 'N',
        UI: 'N',
        VC: 'H',
        VI: 'H',
        VA: 'H',
        SC: 'N',
        SI: 'N',
        SA: 'N',
      };

      const vectorString = generateV4VectorString(vector);

      expect(vectorString).toContain('CVSS:4.0');
      expect(vectorString).toContain('AV:N');
      expect(vectorString).toContain('AC:L');
      expect(vectorString).toContain('AT:N');
      expect(vectorString).toContain('VC:H');
      expect(vectorString).toContain('SC:N');
    });

    test('generates correct vector string with threat metrics', () => {
      const vector: CVSSV4Vector = {
        AV: 'N',
        AC: 'L',
        AT: 'N',
        PR: 'N',
        UI: 'N',
        VC: 'H',
        VI: 'H',
        VA: 'H',
        SC: 'N',
        SI: 'N',
        SA: 'N',
        E: 'A',
      };

      const vectorString = generateV4VectorString(vector);

      expect(vectorString).toContain('CVSS:4.0');
      expect(vectorString).toContain('E:A');
    });

    test('excludes undefined and X values', () => {
      const vector: CVSSV4Vector = {
        AV: 'N',
        AC: 'L',
        AT: 'N',
        E: 'X',
        CR: undefined,
      };

      const vectorString = generateV4VectorString(vector);

      expect(vectorString).not.toContain('E:X');
      expect(vectorString).not.toContain('CR:');
    });
  });

  describe('parseV4VectorString', () => {
    test('parses valid CVSS v4.0 vector string', () => {
      const vectorString = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';

      const result = parseV4VectorString(vectorString);

      expect(result.AV).toBe('N');
      expect(result.AC).toBe('L');
      expect(result.AT).toBe('N');
      expect(result.VC).toBe('H');
      expect(result.SC).toBe('N');
    });

    test('parses vector string with threat metrics', () => {
      const vectorString = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A';

      const result = parseV4VectorString(vectorString);

      expect(result.E).toBe('A');
    });

    test('returns empty object for invalid vector string', () => {
      const vectorString = 'CVSS:3.1/AV:N/AC:L';

      const result = parseV4VectorString(vectorString);

      expect(Object.keys(result)).toHaveLength(0);
    });

    test('handles malformed vector components gracefully', () => {
      const vectorString = 'CVSS:4.0/AV:N/INVALID/AC:L';

      const result = parseV4VectorString(vectorString);

      expect(result.AV).toBe('N');
      expect(result.AC).toBe('L');
    });
  });

  describe('Medical Device Scenarios', () => {
    test('network-connected infusion pump vulnerability', () => {
      const vector: CVSSV4Vector = {
        AV: 'N',
        AC: 'L',
        AT: 'N',
        PR: 'N',
        UI: 'N',
        VC: 'N',
        VI: 'H',
        VA: 'H',
        SC: 'H',
        SI: 'H',
        SA: 'H',
      };

      const result = calculateCVSSV4Score(vector);

      expect(result.baseScore).toBeGreaterThan(7);
      expect(result.severity).toMatch(/High|Critical/);
    });

    test('bluetooth medical device with limited impact', () => {
      const vector: CVSSV4Vector = {
        AV: 'A',
        AC: 'L',
        AT: 'N',
        PR: 'N',
        UI: 'N',
        VC: 'H',
        VI: 'L',
        VA: 'L',
        SC: 'N',
        SI: 'N',
        SA: 'N',
      };

      const result = calculateCVSSV4Score(vector);

      expect(result.baseScore).toBeLessThan(8);
      expect(result.severity).toMatch(/Medium|High/);
    });

    test('physical access medical device', () => {
      const vector: CVSSV4Vector = {
        AV: 'P',
        AC: 'L',
        AT: 'N',
        PR: 'N',
        UI: 'N',
        VC: 'H',
        VI: 'H',
        VA: 'N',
        SC: 'N',
        SI: 'N',
        SA: 'N',
      };

      const result = calculateCVSSV4Score(vector);

      expect(result.baseScore).toBeLessThan(7);
      expect(result.severity).toMatch(/Low|Medium|High/);
    });
  });

  describe('Supplemental Metrics', () => {
    test('generates correct vector string with supplemental metrics', () => {
      const vector: CVSSV4Vector = {
        AV: 'N',
        AC: 'L',
        AT: 'N',
        PR: 'N',
        UI: 'N',
        VC: 'H',
        VI: 'H',
        VA: 'H',
        SC: 'N',
        SI: 'N',
        SA: 'N',
        S: 'P', // Safety: Present
        AU: 'Y', // Automatable: Yes
        R: 'U', // Recovery: User
        V: 'C', // Value Density: Concentrated
        RE: 'H', // Response Effort: High
        U: 'Red', // Provider Urgency: Red
      };

      const vectorString = generateV4VectorString(vector);

      expect(vectorString).toContain('CVSS:4.0');
      expect(vectorString).toContain('S:P');
      expect(vectorString).toContain('AU:Y');
      expect(vectorString).toContain('R:U');
      expect(vectorString).toContain('V:C');
      expect(vectorString).toContain('RE:H');
      expect(vectorString).toContain('U:Red');
    });

    test('excludes supplemental metrics when set to Not Defined', () => {
      const vector: CVSSV4Vector = {
        AV: 'N',
        AC: 'L',
        AT: 'N',
        PR: 'N',
        UI: 'N',
        VC: 'H',
        VI: 'H',
        VA: 'H',
        SC: 'N',
        SI: 'N',
        SA: 'N',
        S: 'X', // Safety: Not Defined
        AU: 'X', // Automatable: Not Defined
        R: 'X', // Recovery: Not Defined
      };

      const vectorString = generateV4VectorString(vector);

      expect(vectorString).toContain('CVSS:4.0');
      expect(vectorString).not.toContain('S:X');
      expect(vectorString).not.toContain('AU:X');
      expect(vectorString).not.toContain('R:X');
    });

    test('parses vector string with supplemental metrics correctly', () => {
      const vectorString =
        'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/S:P/AU:Y/R:U/V:C/RE:H/U:Red';

      const result = parseV4VectorString(vectorString);

      expect(result.S).toBe('P');
      expect(result.AU).toBe('Y');
      expect(result.R).toBe('U');
      expect(result.V).toBe('C');
      expect(result.RE).toBe('H');
      expect(result.U).toBe('Red');
    });

    test('supplemental metrics do not affect base score calculation', () => {
      const baseVector: CVSSV4Vector = {
        AV: 'N',
        AC: 'L',
        AT: 'N',
        PR: 'N',
        UI: 'N',
        VC: 'H',
        VI: 'H',
        VA: 'H',
        SC: 'N',
        SI: 'N',
        SA: 'N',
      };

      const vectorWithSupplemental: CVSSV4Vector = {
        ...baseVector,
        S: 'P',
        AU: 'Y',
        R: 'U',
        V: 'C',
        RE: 'H',
        U: 'Red',
      };

      const baseResult = calculateCVSSV4Score(baseVector);
      const supplementalResult = calculateCVSSV4Score(vectorWithSupplemental);

      // Supplemental metrics should not affect the base score
      expect(supplementalResult.baseScore).toBe(baseResult.baseScore);
      expect(supplementalResult.overallScore).toBe(baseResult.overallScore);
      expect(supplementalResult.severity).toBe(baseResult.severity);
    });
  });
});
