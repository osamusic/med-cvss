import { CVSSMetricGroup } from '../types/cvss';

export const cvssMetrics: CVSSMetricGroup[] = [
  {
    name: 'Base Score Metrics',
    metrics: {
      AV: [
        { value: 'N', label: 'Network', score: 0.85 },
        { value: 'A', label: 'Adjacent', score: 0.62 },
        { value: 'L', label: 'Local', score: 0.55 },
        { value: 'P', label: 'Physical', score: 0.2 },
      ],
      AC: [
        { value: 'L', label: 'Low', score: 0.77 },
        { value: 'H', label: 'High', score: 0.44 },
      ],
      PR: [
        { value: 'N', label: 'None', score: 0.85 },
        { value: 'L', label: 'Low', score: 0.62 },
        { value: 'H', label: 'High', score: 0.27 },
      ],
      UI: [
        { value: 'N', label: 'None', score: 0.85 },
        { value: 'R', label: 'Required', score: 0.62 },
      ],
      S: [
        { value: 'U', label: 'Unchanged', score: 0 },
        { value: 'C', label: 'Changed', score: 1 },
      ],
      C: [
        { value: 'N', label: 'None', score: 0 },
        { value: 'L', label: 'Low', score: 0.22 },
        { value: 'H', label: 'High', score: 0.56 },
      ],
      I: [
        { value: 'N', label: 'None', score: 0 },
        { value: 'L', label: 'Low', score: 0.22 },
        { value: 'H', label: 'High', score: 0.56 },
      ],
      A: [
        { value: 'N', label: 'None', score: 0 },
        { value: 'L', label: 'Low', score: 0.22 },
        { value: 'H', label: 'High', score: 0.56 },
      ],
    },
  },
  {
    name: 'Temporal Score Metrics',
    metrics: {
      E: [
        { value: 'X', label: 'Not Defined', score: 1 },
        { value: 'U', label: 'Unproven', score: 0.91 },
        { value: 'P', label: 'Proof-of-Concept', score: 0.94 },
        { value: 'F', label: 'Functional', score: 0.97 },
        { value: 'H', label: 'High', score: 1 },
      ],
      RL: [
        { value: 'X', label: 'Not Defined', score: 1 },
        { value: 'O', label: 'Official Fix', score: 0.95 },
        { value: 'T', label: 'Temporary Fix', score: 0.96 },
        { value: 'W', label: 'Workaround', score: 0.97 },
        { value: 'U', label: 'Unavailable', score: 1 },
      ],
      RC: [
        { value: 'X', label: 'Not Defined', score: 1 },
        { value: 'U', label: 'Unknown', score: 0.92 },
        { value: 'R', label: 'Reasonable', score: 0.96 },
        { value: 'C', label: 'Confirmed', score: 1 },
      ],
    },
  },
];

export const metricDescriptions: { [key: string]: string } = {
  AV: 'Attack Vector',
  AC: 'Attack Complexity',
  PR: 'Privileges Required',
  UI: 'User Interaction',
  S: 'Scope',
  C: 'Confidentiality Impact',
  I: 'Integrity Impact',
  A: 'Availability Impact',
  E: 'Exploit Code Maturity',
  RL: 'Remediation Level',
  RC: 'Report Confidence',
};
