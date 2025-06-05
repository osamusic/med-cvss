import { cvssMetrics, metricDescriptions } from '../data/cvssMetrics';

describe('CVSS Metrics Data Tests', () => {
  describe('cvssMetrics structure', () => {
    test('has correct number of metric groups', () => {
      expect(cvssMetrics).toHaveLength(2);
      expect(cvssMetrics[0].name).toBe('Base Score Metrics');
      expect(cvssMetrics[1].name).toBe('Temporal Score Metrics');
    });

    test('base score metrics have all required metrics', () => {
      const baseMetrics = cvssMetrics[0].metrics;
      const expectedMetrics = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];

      expectedMetrics.forEach((metric) => {
        expect(baseMetrics).toHaveProperty(metric);
        expect(Array.isArray(baseMetrics[metric])).toBe(true);
        expect(baseMetrics[metric].length).toBeGreaterThan(0);
      });
    });

    test('temporal score metrics have all required metrics', () => {
      const temporalMetrics = cvssMetrics[1].metrics;
      const expectedMetrics = ['E', 'RL', 'RC'];

      expectedMetrics.forEach((metric) => {
        expect(temporalMetrics).toHaveProperty(metric);
        expect(Array.isArray(temporalMetrics[metric])).toBe(true);
        expect(temporalMetrics[metric].length).toBeGreaterThan(0);
      });
    });

    test('all metric options have required properties', () => {
      cvssMetrics.forEach((group) => {
        Object.values(group.metrics).forEach((options) => {
          options.forEach((option) => {
            expect(option).toHaveProperty('value');
            expect(option).toHaveProperty('label');
            expect(option).toHaveProperty('score');
            expect(typeof option.value).toBe('string');
            expect(typeof option.label).toBe('string');
            expect(typeof option.score).toBe('number');
          });
        });
      });
    });

    test('attack vector values are correct', () => {
      const avOptions = cvssMetrics[0].metrics.AV;
      const expectedValues = ['N', 'A', 'L', 'P'];

      expect(avOptions).toHaveLength(4);
      expectedValues.forEach((value, index) => {
        expect(avOptions[index].value).toBe(value);
      });
    });

    test('attack complexity values are correct', () => {
      const acOptions = cvssMetrics[0].metrics.AC;
      const expectedValues = ['L', 'H'];

      expect(acOptions).toHaveLength(2);
      expectedValues.forEach((value, index) => {
        expect(acOptions[index].value).toBe(value);
      });
    });

    test('CIA impact values are correct', () => {
      const ciaMetrics = ['C', 'I', 'A'];
      const expectedValues = ['N', 'L', 'H'];

      ciaMetrics.forEach((metric) => {
        const options = cvssMetrics[0].metrics[metric];
        expect(options).toHaveLength(3);
        expectedValues.forEach((value, index) => {
          expect(options[index].value).toBe(value);
        });
      });
    });
  });

  describe('metricDescriptions', () => {
    test('has descriptions for all base metrics', () => {
      const baseMetrics = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];

      baseMetrics.forEach((metric) => {
        expect(metricDescriptions).toHaveProperty(metric);
        expect(typeof metricDescriptions[metric]).toBe('string');
        expect(metricDescriptions[metric].length).toBeGreaterThan(0);
      });
    });

    test('has descriptions for all temporal metrics', () => {
      const temporalMetrics = ['E', 'RL', 'RC'];

      temporalMetrics.forEach((metric) => {
        expect(metricDescriptions).toHaveProperty(metric);
        expect(typeof metricDescriptions[metric]).toBe('string');
        expect(metricDescriptions[metric].length).toBeGreaterThan(0);
      });
    });

    test('metric descriptions are meaningful', () => {
      expect(metricDescriptions.AV).toContain('Attack Vector');
      expect(metricDescriptions.AC).toContain('Attack Complexity');
      expect(metricDescriptions.PR).toContain('Privileges Required');
      expect(metricDescriptions.UI).toContain('User Interaction');
      expect(metricDescriptions.S).toContain('Scope');
      expect(metricDescriptions.C).toContain('Confidentiality');
      expect(metricDescriptions.I).toContain('Integrity');
      expect(metricDescriptions.A).toContain('Availability');
    });
  });

  describe('CVSS score values validation', () => {
    test('attack vector scores are in correct order (higher is more severe)', () => {
      const avOptions = cvssMetrics[0].metrics.AV;

      // Network should have highest score (most severe)
      const networkScore = avOptions.find((opt) => opt.value === 'N')?.score;
      const adjacentScore = avOptions.find((opt) => opt.value === 'A')?.score;
      const localScore = avOptions.find((opt) => opt.value === 'L')?.score;
      const physicalScore = avOptions.find((opt) => opt.value === 'P')?.score;

      expect(networkScore).toBeGreaterThan(adjacentScore!);
      expect(adjacentScore).toBeGreaterThan(localScore!);
      expect(localScore).toBeGreaterThan(physicalScore!);
    });

    test('attack complexity scores are in correct order', () => {
      const acOptions = cvssMetrics[0].metrics.AC;

      const lowScore = acOptions.find((opt) => opt.value === 'L')?.score;
      const highScore = acOptions.find((opt) => opt.value === 'H')?.score;

      // Low complexity should have higher score (more severe)
      expect(lowScore).toBeGreaterThan(highScore!);
    });

    test('CIA impact scores are in correct order', () => {
      const ciaMetrics = ['C', 'I', 'A'];

      ciaMetrics.forEach((metric) => {
        const options = cvssMetrics[0].metrics[metric];

        const noneScore = options.find((opt) => opt.value === 'N')?.score;
        const lowScore = options.find((opt) => opt.value === 'L')?.score;
        const highScore = options.find((opt) => opt.value === 'H')?.score;

        expect(highScore).toBeGreaterThan(lowScore!);
        expect(lowScore).toBeGreaterThan(noneScore!);
        expect(noneScore).toBe(0);
      });
    });

    test('temporal metrics include "Not Defined" option with score 1.0', () => {
      const temporalMetrics = ['E', 'RL', 'RC'];

      temporalMetrics.forEach((metric) => {
        const options = cvssMetrics[1].metrics[metric];
        const notDefinedOption = options.find((opt) => opt.value === 'X');

        expect(notDefinedOption).toBeDefined();
        expect(notDefinedOption?.label).toContain('Not Defined');
        expect(notDefinedOption?.score).toBe(1);
      });
    });
  });
});
