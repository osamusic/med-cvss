import { mitreRubricQuestions, MitreQuestion, MitreRubricAnswers } from '../data/mitreCvssRubric';

// Helper function to simulate MITRE rubric decision flow
class MitreDecisionFlow {
  private questions: MitreQuestion[];
  private answers: MitreRubricAnswers = {};

  constructor() {
    this.questions = mitreRubricQuestions;
  }

  // Reset for new test case
  reset() {
    this.answers = {};
  }

  // Answer a question and return next question ID or final CVSS value
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

  // Get the final CVSS value for a metric after following decision flow
  getFinalCVSSValue(metric: 'AV' | 'C' | 'I' | 'A'): string {
    // For AV, follow the decision tree logic
    if (metric === 'AV') {
      return this.calculateAV();
    }
    // For CIA, we would implement similar logic
    return 'X'; // Not evaluated
  }

  private calculateAV(): string {
    const xavn = this.answers['XAVN'];

    if (xavn === 'yes') {
      const xavt = this.answers['XAVT'];
      if (xavt === 'yes' || xavt === 'unknown') {
        return 'N'; // Network
      } else if (xavt === 'no') {
        const xavw = this.answers['XAVW'];
        if (xavw === 'yes') {
          const xavr = this.answers['XAVR'];
          if (xavr === 'yes') {
            return 'L'; // Local
          } else {
            return 'A'; // Adjacent
          }
        } else {
          return 'A'; // Adjacent
        }
      }
    } else if (xavn === 'no') {
      const xavp = this.answers['XAVP'];
      if (xavp === 'yes') {
        return 'P'; // Physical
      } else {
        return 'L'; // Local
      }
    } else if (xavn === 'unknown') {
      return 'N'; // Network
    }

    return 'X'; // Not evaluated
  }

  getAnswers(): MitreRubricAnswers {
    return { ...this.answers };
  }
}

describe('MITRE Rubric Decision Flow Tests', () => {
  let decisionFlow: MitreDecisionFlow;

  beforeEach(() => {
    decisionFlow = new MitreDecisionFlow();
  });

  describe('Attack Vector (AV) Decision Flow', () => {
    test('AV Test Case 1: Network accessible via TCP/IP → AV = Network (N)', () => {
      decisionFlow.reset();

      // Q1: Can attacker use network? → Yes
      let result = decisionFlow.answerQuestion('XAVN', 'yes');
      expect(result.nextQuestion).toBe('XAVT');

      // Q2: Uses OSI layer 3/4 protocols? → Yes
      result = decisionFlow.answerQuestion('XAVT', 'yes');
      expect(result.cvssValue).toBe('N');

      expect(decisionFlow.getFinalCVSSValue('AV')).toBe('N');
    });

    test('AV Test Case 2: Bluetooth (short range ≤10ft) → AV = Local (L)', () => {
      decisionFlow.reset();

      // Q1: Network accessible? → Yes
      decisionFlow.answerQuestion('XAVN', 'yes');

      // Q2: OSI layer 3/4? → No (Bluetooth uses different protocols)
      decisionFlow.answerQuestion('XAVT', 'no');

      // Q3: Wireless? → Yes
      decisionFlow.answerQuestion('XAVW', 'yes');

      // Q4: Range ≤10ft? → Yes
      const result = decisionFlow.answerQuestion('XAVR', 'yes');
      expect(result.cvssValue).toBe('L');

      expect(decisionFlow.getFinalCVSSValue('AV')).toBe('L');
    });

    test('AV Test Case 3: WiFi (range >10ft) → AV = Adjacent (A)', () => {
      decisionFlow.reset();

      // Q1: Network accessible? → Yes
      decisionFlow.answerQuestion('XAVN', 'yes');

      // Q2: OSI layer 3/4? → No
      decisionFlow.answerQuestion('XAVT', 'no');

      // Q3: Wireless? → Yes
      decisionFlow.answerQuestion('XAVW', 'yes');

      // Q4: Range ≤10ft? → No
      const result = decisionFlow.answerQuestion('XAVR', 'no');
      expect(result.cvssValue).toBe('A');

      expect(decisionFlow.getFinalCVSSValue('AV')).toBe('A');
    });

    test('AV Test Case 4: Physical access required → AV = Physical (P)', () => {
      decisionFlow.reset();

      // Q1: Network accessible? → No
      decisionFlow.answerQuestion('XAVN', 'no');

      // Q5: Physical contact required? → Yes
      const result = decisionFlow.answerQuestion('XAVP', 'yes');
      expect(result.cvssValue).toBe('P');

      expect(decisionFlow.getFinalCVSSValue('AV')).toBe('P');
    });

    test('AV Test Case 5: Local access (no network, no physical) → AV = Local (L)', () => {
      decisionFlow.reset();

      // Q1: Network accessible? → No
      decisionFlow.answerQuestion('XAVN', 'no');

      // Q5: Physical contact required? → No
      const result = decisionFlow.answerQuestion('XAVP', 'no');
      expect(result.cvssValue).toBe('L');

      expect(decisionFlow.getFinalCVSSValue('AV')).toBe('L');
    });

    test('AV Test Case 6: Unknown network accessibility → AV = Network (N)', () => {
      decisionFlow.reset();

      // Q1: Network accessible? → Unknown
      const result = decisionFlow.answerQuestion('XAVN', 'unknown');
      expect(result.cvssValue).toBe('N');

      expect(decisionFlow.getFinalCVSSValue('AV')).toBe('N');
    });

    test('AV Test Case 7: Wired non-TCP/UDP connection → AV = Adjacent (A)', () => {
      decisionFlow.reset();

      // Q1: Network accessible? → Yes
      decisionFlow.answerQuestion('XAVN', 'yes');

      // Q2: OSI layer 3/4? → No (custom protocol)
      decisionFlow.answerQuestion('XAVT', 'no');

      // Q3: Wireless? → No (wired connection)
      const result = decisionFlow.answerQuestion('XAVW', 'no');
      expect(result.cvssValue).toBe('L');

      expect(decisionFlow.getFinalCVSSValue('AV')).toBe('A');
    });
  });

  describe('Medical Device Scenarios for AV', () => {
    test('Scenario: Internet-connected infusion pump → AV = Network (N)', () => {
      decisionFlow.reset();

      // Hospital network connected infusion pump using TCP/IP
      decisionFlow.answerQuestion('XAVN', 'yes');
      decisionFlow.answerQuestion('XAVT', 'yes');

      expect(decisionFlow.getFinalCVSSValue('AV')).toBe('N');
    });

    test('Scenario: Bluetooth glucose monitor (close range) → AV = Local (L)', () => {
      decisionFlow.reset();

      // Personal glucose monitor with short-range Bluetooth
      decisionFlow.answerQuestion('XAVN', 'yes');
      decisionFlow.answerQuestion('XAVT', 'no');
      decisionFlow.answerQuestion('XAVW', 'yes');
      decisionFlow.answerQuestion('XAVR', 'yes');

      expect(decisionFlow.getFinalCVSSValue('AV')).toBe('L');
    });

    test('Scenario: WiFi-enabled patient monitor → AV = Adjacent (A)', () => {
      decisionFlow.reset();

      // Bedside patient monitor with WiFi connectivity
      decisionFlow.answerQuestion('XAVN', 'yes');
      decisionFlow.answerQuestion('XAVT', 'no');
      decisionFlow.answerQuestion('XAVW', 'yes');
      decisionFlow.answerQuestion('XAVR', 'no');

      expect(decisionFlow.getFinalCVSSValue('AV')).toBe('A');
    });

    test('Scenario: Implantable pacemaker → AV = Physical (P)', () => {
      decisionFlow.reset();

      // Pacemaker requiring physical programmer contact
      decisionFlow.answerQuestion('XAVN', 'no');
      decisionFlow.answerQuestion('XAVP', 'yes');

      expect(decisionFlow.getFinalCVSSValue('AV')).toBe('P');
    });

    test('Scenario: USB-connected diagnostic device → AV = Local (L)', () => {
      decisionFlow.reset();

      // Diagnostic equipment connected via USB
      decisionFlow.answerQuestion('XAVN', 'no');
      decisionFlow.answerQuestion('XAVP', 'no');

      expect(decisionFlow.getFinalCVSSValue('AV')).toBe('L');
    });
  });
});
