import { compareVectors, calculateRiskReduction, generateComparisonReport } from '../utils/cvssComparison';
import { CVSSVector } from '../types/cvss';

describe('CVSS Comparison Tests', () => {
  describe('compareVectors', () => {
    test('compares before and after vectors correctly', () => {
      const before: CVSSVector = {
        AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H'
      };
      const after: CVSSVector = {
        AV: 'L', AC: 'L', PR: 'H', UI: 'N', S: 'U', C: 'L', I: 'L', A: 'L'
      };
      const remediationActions = ['Network segmentation', 'Authentication required'];

      const comparison = compareVectors(before, after, remediationActions);

      expect(comparison.before).toEqual(before);
      expect(comparison.after).toEqual(after);
      expect(comparison.remediationActions).toEqual(remediationActions);
      expect(comparison.beforeScore.baseScore).toBeGreaterThan(comparison.afterScore.baseScore);
      expect(comparison.metricChanges.length).toBeGreaterThan(0);
    });

    test('identifies metric changes correctly', () => {
      const before: CVSSVector = {
        AV: 'N', AC: 'L', PR: 'N'
      };
      const after: CVSSVector = {
        AV: 'L', AC: 'L', PR: 'H'
      };

      const comparison = compareVectors(before, after);
      
      expect(comparison.metricChanges).toHaveLength(2);
      
      const avChange = comparison.metricChanges.find(c => c.metric === 'AV');
      expect(avChange).toBeDefined();
      expect(avChange?.before).toBe('N');
      expect(avChange?.after).toBe('L');
      
      const prChange = comparison.metricChanges.find(c => c.metric === 'PR');
      expect(prChange).toBeDefined();
      expect(prChange?.before).toBe('N');
      expect(prChange?.after).toBe('H');
    });

    test('handles identical vectors', () => {
      const vector: CVSSVector = {
        AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H'
      };

      const comparison = compareVectors(vector, vector);
      
      expect(comparison.metricChanges).toHaveLength(0);
      expect(comparison.beforeScore.baseScore).toBe(comparison.afterScore.baseScore);
    });
  });

  describe('calculateRiskReduction', () => {
    test('calculates significant risk reduction correctly', () => {
      const result = calculateRiskReduction(9.0, 2.0);
      
      expect(result.scoreReduction).toBeCloseTo(7.0, 1);
      expect(result.percentageReduction).toBeCloseTo(77.8, 1);
      expect(result.riskCategory).toBe('Significant Risk Reduction');
    });

    test('calculates moderate risk reduction correctly', () => {
      const result = calculateRiskReduction(8.0, 4.0);
      
      expect(result.scoreReduction).toBeCloseTo(4.0, 1);
      expect(result.percentageReduction).toBe(50.0);
      expect(result.riskCategory).toBe('Moderate Risk Reduction');
    });

    test('calculates minor risk reduction correctly', () => {
      const result = calculateRiskReduction(6.0, 5.0);
      
      expect(result.scoreReduction).toBeCloseTo(1.0, 1);
      expect(result.percentageReduction).toBeCloseTo(16.7, 1);
      expect(result.riskCategory).toBe('Minor Risk Reduction');
    });

    test('identifies no change', () => {
      const result = calculateRiskReduction(7.0, 7.0);
      
      expect(result.scoreReduction).toBe(0);
      expect(result.percentageReduction).toBe(0);
      expect(result.riskCategory).toBe('No Change');
    });

    test('identifies risk increase', () => {
      const result = calculateRiskReduction(5.0, 7.0);
      
      expect(result.scoreReduction).toBe(-2.0);
      expect(result.percentageReduction).toBe(-40.0);
      expect(result.riskCategory).toBe('Risk Increase');
    });

    test('handles zero baseline score', () => {
      const result = calculateRiskReduction(0, 0);
      
      expect(result.scoreReduction).toBe(0);
      expect(result.percentageReduction).toBe(0);
      expect(result.riskCategory).toBe('No Change');
    });
  });

  describe('generateComparisonReport', () => {
    test('generates comprehensive report', () => {
      const before: CVSSVector = {
        AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H'
      };
      const after: CVSSVector = {
        AV: 'L', AC: 'L', PR: 'H', UI: 'N', S: 'U', C: 'L', I: 'L', A: 'L'
      };
      const remediationActions = ['Network segmentation implemented', 'Authentication required'];

      const comparison = compareVectors(before, after, remediationActions);
      const report = generateComparisonReport(comparison);

      expect(report).toContain('CVSS Before/After Comparison Report');
      expect(report).toContain('Score Changes');
      expect(report).toContain('**Before**:');
      expect(report).toContain('**After**:');
      expect(report).toContain('**Risk Reduction**:');
      expect(report).toContain('Metric Change Details');
      expect(report).toContain('Implemented Remediation Actions');
      expect(report).toContain('Network segmentation implemented');
      expect(report).toContain('Authentication required');
    });

    test('generates report without remediation actions', () => {
      const before: CVSSVector = { AV: 'N', AC: 'L' };
      const after: CVSSVector = { AV: 'L', AC: 'L' };

      const comparison = compareVectors(before, after, []);
      const report = generateComparisonReport(comparison);

      expect(report).toContain('CVSS Before/After Comparison Report');
      expect(report).toContain('Score Changes');
      expect(report).not.toContain('Implemented Remediation Actions');
    });
  });

  describe('Medical Device Remediation Scenarios', () => {
    test('network-connected device remediation reduces score', () => {
      const before: CVSSVector = {
        AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'H', A: 'H'
      };
      const after: CVSSVector = {
        AV: 'L', AC: 'L', PR: 'H', UI: 'N', S: 'U', C: 'N', I: 'L', A: 'L'
      };

      const comparison = compareVectors(before, after);
      
      expect(comparison.beforeScore.baseScore).toBeGreaterThan(comparison.afterScore.baseScore);
      expect(comparison.metricChanges.some(c => c.metric === 'AV')).toBe(true);
      expect(comparison.metricChanges.some(c => c.metric === 'PR')).toBe(true);
    });

    test('bluetooth device encryption reduces confidentiality impact', () => {
      const before: CVSSVector = {
        AV: 'A', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'L', A: 'N'
      };
      const after: CVSSVector = {
        AV: 'A', AC: 'H', PR: 'L', UI: 'R', S: 'U', C: 'L', I: 'L', A: 'N'
      };

      const comparison = compareVectors(before, after);
      
      expect(comparison.beforeScore.baseScore).toBeGreaterThan(comparison.afterScore.baseScore);
      
      const cChange = comparison.metricChanges.find(c => c.metric === 'C');
      expect(cChange).toBeDefined();
      expect(cChange?.before).toBe('H');
      expect(cChange?.after).toBe('L');
    });

    test('physical access restrictions improve security posture', () => {
      const before: CVSSVector = {
        AV: 'P', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'L'
      };
      const after: CVSSVector = {
        AV: 'P', AC: 'H', PR: 'H', UI: 'R', S: 'U', C: 'L', I: 'L', A: 'N'
      };

      const comparison = compareVectors(before, after);
      
      expect(comparison.beforeScore.baseScore).toBeGreaterThan(comparison.afterScore.baseScore);
      expect(comparison.metricChanges.length).toBeGreaterThan(0);
    });
  });
});