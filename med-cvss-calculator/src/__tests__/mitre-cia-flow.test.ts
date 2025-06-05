import { mitreRubricQuestions, MitreQuestion, MitreRubricAnswers } from '../data/mitreCvssRubric';

// Helper class for CIA (Confidentiality, Integrity, Availability) decision flow testing
class MitreCIAFlow {
  private questions: MitreQuestion[];
  private answers: MitreRubricAnswers = {};

  constructor() {
    this.questions = mitreRubricQuestions;
  }

  reset() {
    this.answers = {};
  }

  answerQuestion(
    questionId: string,
    answerValue: string
  ): { nextQuestion?: string; cvssValue?: string } {
    this.answers[questionId] = answerValue;

    const question = this.questions.find((q) => q.id === questionId);
    if (!question) {
      throw new Error(`Question ${questionId} not found`);
    }

    const selectedOption = question.options.find((opt) => opt.value === answerValue);
    if (!selectedOption) {
      throw new Error(`Option ${answerValue} not found for question ${questionId}`);
    }

    return {
      nextQuestion: selectedOption.nextQuestion,
      cvssValue: selectedOption.cvssValue,
    };
  }

  // Calculate final CIA values based on parallel evaluation logic
  getFinalCVSSValue(metric: 'C' | 'I' | 'A'): string {
    if (metric === 'C') {
      return this.calculateConfidentiality();
    } else if (metric === 'I') {
      return this.calculateIntegrity();
    } else if (metric === 'A') {
      return this.calculateAvailability();
    }
    return 'X';
  }

  private calculateConfidentiality(): string {
    const cQuestions = ['XCP', 'XCD', 'XCT', 'XCW', 'XCS', 'XCO'];
    const results: string[] = [];

    for (const qId of cQuestions) {
      const answer = this.answers[qId];
      if (answer === 'yes') {
        // Special case for XCP - check XCPM for scale
        if (qId === 'XCP' && this.answers['XCPM']) {
          const scale = this.answers['XCPM'];
          if (scale === 'no') {
            results.push('L'); // Less than 500 patients
          } else {
            results.push('H'); // 500+ patients or unknown
          }
        } else {
          results.push('H');
        }
      } else if (answer === 'unknown') {
        results.push('H');
      } else if (answer === 'no') {
        results.push('N');
      }
    }

    // Apply final determination logic
    if (results.includes('H')) return 'H';
    if (results.includes('L')) return 'L';
    return 'N';
  }

  private calculateIntegrity(): string {
    const iQuestions = ['XIP', 'XID', 'XIT', 'XIW', 'XIS', 'XIO'];
    const results: string[] = [];

    for (const qId of iQuestions) {
      const answer = this.answers[qId];
      if (answer === 'yes' || answer === 'unknown') {
        results.push('H');
      } else if (answer === 'no') {
        results.push('N');
      }
    }

    // Apply final determination logic
    if (results.includes('H')) return 'H';
    if (results.includes('L')) return 'L';
    return 'N';
  }

  private calculateAvailability(): string {
    const aQuestions = ['XAP', 'XAD', 'XAT', 'XAW', 'XAS', 'XAO'];
    const results: string[] = [];

    for (const qId of aQuestions) {
      const answer = this.answers[qId];
      if (answer === 'yes' || answer === 'unknown') {
        results.push('H');
      } else if (answer === 'no') {
        results.push('N');
      }
    }

    // Apply final determination logic
    if (results.includes('H')) return 'H';
    if (results.includes('L')) return 'L';
    return 'N';
  }

  getAnswers(): MitreRubricAnswers {
    return { ...this.answers };
  }
}

describe('MITRE Rubric CIA Decision Flow Tests', () => {
  let ciaFlow: MitreCIAFlow;

  beforeEach(() => {
    ciaFlow = new MitreCIAFlow();
  });

  describe('Confidentiality (C) Decision Flow', () => {
    test('C Test Case 1: PHI/PII exposure (large scale 500+) → C = High', () => {
      ciaFlow.reset();

      // XCP: PHI/PII data readable? → Yes
      ciaFlow.answerQuestion('XCP', 'yes');

      // XCPM: Large scale (500+ patients)? → Yes
      ciaFlow.answerQuestion('XCPM', 'yes');

      // All other C questions → No
      ciaFlow.answerQuestion('XCD', 'no');
      ciaFlow.answerQuestion('XCT', 'no');
      ciaFlow.answerQuestion('XCW', 'no');
      ciaFlow.answerQuestion('XCS', 'no');
      ciaFlow.answerQuestion('XCO', 'no');

      expect(ciaFlow.getFinalCVSSValue('C')).toBe('H');
    });

    test('C Test Case 2: PHI/PII exposure (small scale <500) → C = Low', () => {
      ciaFlow.reset();

      // XCP: PHI/PII data readable? → Yes
      ciaFlow.answerQuestion('XCP', 'yes');

      // XCPM: Large scale (500+ patients)? → No
      ciaFlow.answerQuestion('XCPM', 'no');

      // All other C questions → No
      ciaFlow.answerQuestion('XCD', 'no');
      ciaFlow.answerQuestion('XCT', 'no');
      ciaFlow.answerQuestion('XCW', 'no');
      ciaFlow.answerQuestion('XCS', 'no');
      ciaFlow.answerQuestion('XCO', 'no');

      expect(ciaFlow.getFinalCVSSValue('C')).toBe('L');
    });

    test('C Test Case 3: Multiple data types exposed → C = High', () => {
      ciaFlow.reset();

      // Multiple types of data exposed
      ciaFlow.answerQuestion('XCP', 'no'); // PHI/PII → No
      ciaFlow.answerQuestion('XCD', 'yes'); // Diagnosis → Yes
      ciaFlow.answerQuestion('XCT', 'yes'); // Therapy → Yes
      ciaFlow.answerQuestion('XCW', 'no'); // Workflow → No
      ciaFlow.answerQuestion('XCS', 'unknown'); // System data → Unknown
      ciaFlow.answerQuestion('XCO', 'no'); // Other → No

      expect(ciaFlow.getFinalCVSSValue('C')).toBe('H');
    });

    test('C Test Case 4: No data exposure → C = None', () => {
      ciaFlow.reset();

      // All C questions → No
      ciaFlow.answerQuestion('XCP', 'no');
      ciaFlow.answerQuestion('XCD', 'no');
      ciaFlow.answerQuestion('XCT', 'no');
      ciaFlow.answerQuestion('XCW', 'no');
      ciaFlow.answerQuestion('XCS', 'no');
      ciaFlow.answerQuestion('XCO', 'no');

      expect(ciaFlow.getFinalCVSSValue('C')).toBe('N');
    });

    test('C Test Case 5: Unknown exposure treated as High → C = High', () => {
      ciaFlow.reset();

      // Most questions No, but one Unknown
      ciaFlow.answerQuestion('XCP', 'no');
      ciaFlow.answerQuestion('XCD', 'no');
      ciaFlow.answerQuestion('XCT', 'unknown'); // Unknown treated as High
      ciaFlow.answerQuestion('XCW', 'no');
      ciaFlow.answerQuestion('XCS', 'no');
      ciaFlow.answerQuestion('XCO', 'no');

      expect(ciaFlow.getFinalCVSSValue('C')).toBe('H');
    });
  });

  describe('Integrity (I) Decision Flow', () => {
    test('I Test Case 1: PHI/PII modification possible → I = High', () => {
      ciaFlow.reset();

      // XIP: PHI/PII modifiable? → Yes
      ciaFlow.answerQuestion('XIP', 'yes');

      // All other I questions → No
      ciaFlow.answerQuestion('XID', 'no');
      ciaFlow.answerQuestion('XIT', 'no');
      ciaFlow.answerQuestion('XIW', 'no');
      ciaFlow.answerQuestion('XIS', 'no');
      ciaFlow.answerQuestion('XIO', 'no');

      expect(ciaFlow.getFinalCVSSValue('I')).toBe('H');
    });

    test('I Test Case 2: System data modification → I = High', () => {
      ciaFlow.reset();

      // Only system data modifiable
      ciaFlow.answerQuestion('XIP', 'no');
      ciaFlow.answerQuestion('XID', 'no');
      ciaFlow.answerQuestion('XIT', 'no');
      ciaFlow.answerQuestion('XIW', 'no');
      ciaFlow.answerQuestion('XIS', 'yes'); // System data modifiable
      ciaFlow.answerQuestion('XIO', 'no');

      expect(ciaFlow.getFinalCVSSValue('I')).toBe('H');
    });

    test('I Test Case 3: No data modification possible → I = None', () => {
      ciaFlow.reset();

      // All I questions → No
      ciaFlow.answerQuestion('XIP', 'no');
      ciaFlow.answerQuestion('XID', 'no');
      ciaFlow.answerQuestion('XIT', 'no');
      ciaFlow.answerQuestion('XIW', 'no');
      ciaFlow.answerQuestion('XIS', 'no');
      ciaFlow.answerQuestion('XIO', 'no');

      expect(ciaFlow.getFinalCVSSValue('I')).toBe('N');
    });

    test('I Test Case 4: Unknown modification capability → I = High', () => {
      ciaFlow.reset();

      // Unknown modification capability treated as High
      ciaFlow.answerQuestion('XIP', 'no');
      ciaFlow.answerQuestion('XID', 'unknown'); // Unknown → High
      ciaFlow.answerQuestion('XIT', 'no');
      ciaFlow.answerQuestion('XIW', 'no');
      ciaFlow.answerQuestion('XIS', 'no');
      ciaFlow.answerQuestion('XIO', 'no');

      expect(ciaFlow.getFinalCVSSValue('I')).toBe('H');
    });
  });

  describe('Availability (A) Decision Flow', () => {
    test('A Test Case 1: Therapy delivery disruption → A = High', () => {
      ciaFlow.reset();

      // XAT: Therapy delivery disruptable? → Yes
      ciaFlow.answerQuestion('XAT', 'yes');

      // All other A questions → No
      ciaFlow.answerQuestion('XAP', 'no');
      ciaFlow.answerQuestion('XAD', 'no');
      ciaFlow.answerQuestion('XAW', 'no');
      ciaFlow.answerQuestion('XAS', 'no');
      ciaFlow.answerQuestion('XAO', 'no');

      expect(ciaFlow.getFinalCVSSValue('A')).toBe('H');
    });

    test('A Test Case 2: Multiple system disruptions → A = High', () => {
      ciaFlow.reset();

      // Multiple availability impacts
      ciaFlow.answerQuestion('XAP', 'yes'); // PHI/PII inaccessible
      ciaFlow.answerQuestion('XAD', 'yes'); // Diagnosis data inaccessible
      ciaFlow.answerQuestion('XAT', 'no'); // Therapy OK
      ciaFlow.answerQuestion('XAW', 'unknown'); // Workflow unknown
      ciaFlow.answerQuestion('XAS', 'no'); // System data OK
      ciaFlow.answerQuestion('XAO', 'no'); // Other OK

      expect(ciaFlow.getFinalCVSSValue('A')).toBe('H');
    });

    test('A Test Case 3: No availability impact → A = None', () => {
      ciaFlow.reset();

      // All A questions → No
      ciaFlow.answerQuestion('XAP', 'no');
      ciaFlow.answerQuestion('XAD', 'no');
      ciaFlow.answerQuestion('XAT', 'no');
      ciaFlow.answerQuestion('XAW', 'no');
      ciaFlow.answerQuestion('XAS', 'no');
      ciaFlow.answerQuestion('XAO', 'no');

      expect(ciaFlow.getFinalCVSSValue('A')).toBe('N');
    });
  });

  describe('Medical Device CIA Scenarios', () => {
    test('Scenario: Hospital EHR system breach', () => {
      ciaFlow.reset();

      // Large-scale patient data exposure
      ciaFlow.answerQuestion('XCP', 'yes'); // PHI accessible
      ciaFlow.answerQuestion('XCPM', 'yes'); // 500+ patients
      ciaFlow.answerQuestion('XCD', 'yes'); // Diagnosis data accessible
      ciaFlow.answerQuestion('XCT', 'no'); // No therapy data
      ciaFlow.answerQuestion('XCW', 'yes'); // Workflow data accessible
      ciaFlow.answerQuestion('XCS', 'no'); // System data protected
      ciaFlow.answerQuestion('XCO', 'no'); // No other critical data

      // Data can be modified
      ciaFlow.answerQuestion('XIP', 'yes'); // PHI modifiable
      ciaFlow.answerQuestion('XID', 'yes'); // Diagnosis modifiable
      ciaFlow.answerQuestion('XIT', 'no'); // Therapy protected
      ciaFlow.answerQuestion('XIW', 'yes'); // Workflow modifiable
      ciaFlow.answerQuestion('XIS', 'no'); // System data protected
      ciaFlow.answerQuestion('XIO', 'no'); // Other protected

      // System remains available
      ciaFlow.answerQuestion('XAP', 'no'); // PHI still accessible
      ciaFlow.answerQuestion('XAD', 'no'); // Diagnosis still accessible
      ciaFlow.answerQuestion('XAT', 'no'); // Therapy unaffected
      ciaFlow.answerQuestion('XAW', 'no'); // Workflow continues
      ciaFlow.answerQuestion('XAS', 'no'); // System operational
      ciaFlow.answerQuestion('XAO', 'no'); // Other systems OK

      expect(ciaFlow.getFinalCVSSValue('C')).toBe('H'); // High confidentiality impact
      expect(ciaFlow.getFinalCVSSValue('I')).toBe('H'); // High integrity impact
      expect(ciaFlow.getFinalCVSSValue('A')).toBe('N'); // No availability impact
    });

    test('Scenario: Infusion pump DoS attack', () => {
      ciaFlow.reset();

      // No data exposure
      ciaFlow.answerQuestion('XCP', 'no');
      ciaFlow.answerQuestion('XCD', 'no');
      ciaFlow.answerQuestion('XCT', 'no');
      ciaFlow.answerQuestion('XCW', 'no');
      ciaFlow.answerQuestion('XCS', 'no');
      ciaFlow.answerQuestion('XCO', 'no');

      // No data modification
      ciaFlow.answerQuestion('XIP', 'no');
      ciaFlow.answerQuestion('XID', 'no');
      ciaFlow.answerQuestion('XIT', 'no');
      ciaFlow.answerQuestion('XIW', 'no');
      ciaFlow.answerQuestion('XIS', 'no');
      ciaFlow.answerQuestion('XIO', 'no');

      // Therapy delivery disrupted
      ciaFlow.answerQuestion('XAP', 'no');
      ciaFlow.answerQuestion('XAD', 'no');
      ciaFlow.answerQuestion('XAT', 'yes'); // Therapy delivery affected
      ciaFlow.answerQuestion('XAW', 'no');
      ciaFlow.answerQuestion('XAS', 'no');
      ciaFlow.answerQuestion('XAO', 'no');

      expect(ciaFlow.getFinalCVSSValue('C')).toBe('N'); // No confidentiality impact
      expect(ciaFlow.getFinalCVSSValue('I')).toBe('N'); // No integrity impact
      expect(ciaFlow.getFinalCVSSValue('A')).toBe('H'); // High availability impact
    });

    test('Scenario: Small clinic patient monitor compromise (PHI only)', () => {
      ciaFlow.reset();

      // Small scale PHI exposure only (<500 patients)
      ciaFlow.answerQuestion('XCP', 'yes');
      ciaFlow.answerQuestion('XCPM', 'no'); // Small clinic <500 patients
      ciaFlow.answerQuestion('XCD', 'no'); // No monitoring data exposed
      ciaFlow.answerQuestion('XCT', 'no');
      ciaFlow.answerQuestion('XCW', 'no');
      ciaFlow.answerQuestion('XCS', 'no');
      ciaFlow.answerQuestion('XCO', 'no');

      // No modification capability
      ciaFlow.answerQuestion('XIP', 'no');
      ciaFlow.answerQuestion('XID', 'no');
      ciaFlow.answerQuestion('XIT', 'no');
      ciaFlow.answerQuestion('XIW', 'no');
      ciaFlow.answerQuestion('XIS', 'no');
      ciaFlow.answerQuestion('XIO', 'no');

      // No availability impact
      ciaFlow.answerQuestion('XAP', 'no');
      ciaFlow.answerQuestion('XAD', 'no');
      ciaFlow.answerQuestion('XAT', 'no');
      ciaFlow.answerQuestion('XAW', 'no');
      ciaFlow.answerQuestion('XAS', 'no');
      ciaFlow.answerQuestion('XAO', 'no');

      expect(ciaFlow.getFinalCVSSValue('C')).toBe('L'); // Low confidentiality (small scale PHI only)
      expect(ciaFlow.getFinalCVSSValue('I')).toBe('N'); // No integrity impact
      expect(ciaFlow.getFinalCVSSValue('A')).toBe('N'); // No availability impact
    });

    test('Scenario: Small clinic with monitoring data exposed', () => {
      ciaFlow.reset();

      // Small scale but monitoring data makes it High
      ciaFlow.answerQuestion('XCP', 'yes');
      ciaFlow.answerQuestion('XCPM', 'no'); // Small clinic <500 patients (L)
      ciaFlow.answerQuestion('XCD', 'yes'); // Monitoring data exposed (H)
      ciaFlow.answerQuestion('XCT', 'no');
      ciaFlow.answerQuestion('XCW', 'no');
      ciaFlow.answerQuestion('XCS', 'no');
      ciaFlow.answerQuestion('XCO', 'no');

      expect(ciaFlow.getFinalCVSSValue('C')).toBe('H'); // High due to monitoring data (any H = overall H)
    });
  });
});
