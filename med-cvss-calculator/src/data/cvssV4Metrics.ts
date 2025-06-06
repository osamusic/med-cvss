import { CVSSMetricGroup } from '../types/cvss';

export const cvssV4Metrics: CVSSMetricGroup[] = [
  {
    name: 'Base Score Metrics - Exploitability',
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
      AT: [
        { value: 'N', label: 'None', score: 0.85 },
        { value: 'P', label: 'Present', score: 0.7 },
      ],
      PR: [
        { value: 'N', label: 'None', score: 0.85 },
        { value: 'L', label: 'Low', score: 0.62 },
        { value: 'H', label: 'High', score: 0.27 },
      ],
      UI: [
        { value: 'N', label: 'None', score: 0.85 },
        { value: 'P', label: 'Passive', score: 0.73 },
        { value: 'A', label: 'Active', score: 0.62 },
      ],
    },
  },
  {
    name: 'Base Score Metrics - Vulnerable System Impact',
    metrics: {
      VC: [
        { value: 'N', label: 'None', score: 0 },
        { value: 'L', label: 'Low', score: 0.22 },
        { value: 'H', label: 'High', score: 0.56 },
      ],
      VI: [
        { value: 'N', label: 'None', score: 0 },
        { value: 'L', label: 'Low', score: 0.22 },
        { value: 'H', label: 'High', score: 0.56 },
      ],
      VA: [
        { value: 'N', label: 'None', score: 0 },
        { value: 'L', label: 'Low', score: 0.22 },
        { value: 'H', label: 'High', score: 0.56 },
      ],
    },
  },
  {
    name: 'Base Score Metrics - Subsequent System Impact',
    metrics: {
      SC: [
        { value: 'N', label: 'None', score: 0 },
        { value: 'L', label: 'Low', score: 0.22 },
        { value: 'H', label: 'High', score: 0.56 },
      ],
      SI: [
        { value: 'N', label: 'None', score: 0 },
        { value: 'L', label: 'Low', score: 0.22 },
        { value: 'H', label: 'High', score: 0.56 },
      ],
      SA: [
        { value: 'N', label: 'None', score: 0 },
        { value: 'L', label: 'Low', score: 0.22 },
        { value: 'H', label: 'High', score: 0.56 },
      ],
    },
  },
  {
    name: 'Threat Metrics',
    metrics: {
      E: [
        { value: 'X', label: 'Not Defined', score: 1 },
        { value: 'U', label: 'Unreported', score: 0.07 },
        { value: 'P', label: 'Proof of Concept', score: 0.94 },
        { value: 'A', label: 'Attacked', score: 0.97 },
      ],
    },
  },
  {
    name: 'Environmental Metrics - Modified Base Metrics',
    metrics: {
      MAV: [
        { value: 'X', label: 'Not Defined', score: 1 },
        { value: 'N', label: 'Network', score: 0.85 },
        { value: 'A', label: 'Adjacent', score: 0.62 },
        { value: 'L', label: 'Local', score: 0.55 },
        { value: 'P', label: 'Physical', score: 0.2 },
      ],
      MAC: [
        { value: 'X', label: 'Not Defined', score: 1 },
        { value: 'L', label: 'Low', score: 0.77 },
        { value: 'H', label: 'High', score: 0.44 },
      ],
      MAT: [
        { value: 'X', label: 'Not Defined', score: 1 },
        { value: 'N', label: 'None', score: 0.85 },
        { value: 'P', label: 'Present', score: 0.7 },
      ],
      MPR: [
        { value: 'X', label: 'Not Defined', score: 1 },
        { value: 'N', label: 'None', score: 0.85 },
        { value: 'L', label: 'Low', score: 0.62 },
        { value: 'H', label: 'High', score: 0.27 },
      ],
      MUI: [
        { value: 'X', label: 'Not Defined', score: 1 },
        { value: 'N', label: 'None', score: 0.85 },
        { value: 'P', label: 'Passive', score: 0.73 },
        { value: 'A', label: 'Active', score: 0.62 },
      ],
      MVC: [
        { value: 'X', label: 'Not Defined', score: 1 },
        { value: 'N', label: 'None', score: 0 },
        { value: 'L', label: 'Low', score: 0.22 },
        { value: 'H', label: 'High', score: 0.56 },
      ],
      MVI: [
        { value: 'X', label: 'Not Defined', score: 1 },
        { value: 'N', label: 'None', score: 0 },
        { value: 'L', label: 'Low', score: 0.22 },
        { value: 'H', label: 'High', score: 0.56 },
      ],
      MVA: [
        { value: 'X', label: 'Not Defined', score: 1 },
        { value: 'N', label: 'None', score: 0 },
        { value: 'L', label: 'Low', score: 0.22 },
        { value: 'H', label: 'High', score: 0.56 },
      ],
      MSC: [
        { value: 'X', label: 'Not Defined', score: 1 },
        { value: 'N', label: 'None', score: 0 },
        { value: 'L', label: 'Low', score: 0.22 },
        { value: 'H', label: 'High', score: 0.56 },
      ],
      MSI: [
        { value: 'X', label: 'Not Defined', score: 1 },
        { value: 'N', label: 'None', score: 0 },
        { value: 'L', label: 'Low', score: 0.22 },
        { value: 'H', label: 'High', score: 0.56 },
      ],
      MSA: [
        { value: 'X', label: 'Not Defined', score: 1 },
        { value: 'N', label: 'None', score: 0 },
        { value: 'L', label: 'Low', score: 0.22 },
        { value: 'H', label: 'High', score: 0.56 },
      ],
    },
  },
  {
    name: 'Environmental Metrics - Security Requirements',
    metrics: {
      CR: [
        { value: 'X', label: 'Not Defined', score: 1 },
        { value: 'L', label: 'Low', score: 0.5 },
        { value: 'M', label: 'Medium', score: 1 },
        { value: 'H', label: 'High', score: 1.5 },
      ],
      IR: [
        { value: 'X', label: 'Not Defined', score: 1 },
        { value: 'L', label: 'Low', score: 0.5 },
        { value: 'M', label: 'Medium', score: 1 },
        { value: 'H', label: 'High', score: 1.5 },
      ],
      AR: [
        { value: 'X', label: 'Not Defined', score: 1 },
        { value: 'L', label: 'Low', score: 0.5 },
        { value: 'M', label: 'Medium', score: 1 },
        { value: 'H', label: 'High', score: 1.5 },
      ],
    },
  },
  {
    name: 'Supplemental Metrics',
    metrics: {
      S: [
        { value: 'X', label: 'Not Defined', score: 0 },
        { value: 'N', label: 'Negligible', score: 0 },
        { value: 'P', label: 'Present', score: 0 },
      ],
      AU: [
        { value: 'X', label: 'Not Defined', score: 0 },
        { value: 'N', label: 'No', score: 0 },
        { value: 'Y', label: 'Yes', score: 0 },
      ],
      R: [
        { value: 'X', label: 'Not Defined', score: 0 },
        { value: 'A', label: 'Automatic', score: 0 },
        { value: 'U', label: 'User', score: 0 },
        { value: 'I', label: 'Irrecoverable', score: 0 },
      ],
      V: [
        { value: 'X', label: 'Not Defined', score: 0 },
        { value: 'D', label: 'Diffuse', score: 0 },
        { value: 'C', label: 'Concentrated', score: 0 },
      ],
      RE: [
        { value: 'X', label: 'Not Defined', score: 0 },
        { value: 'L', label: 'Low', score: 0 },
        { value: 'M', label: 'Moderate', score: 0 },
        { value: 'H', label: 'High', score: 0 },
      ],
      U: [
        { value: 'X', label: 'Not Defined', score: 0 },
        { value: 'Clear', label: 'Clear', score: 0 },
        { value: 'Green', label: 'Green', score: 0 },
        { value: 'Amber', label: 'Amber', score: 0 },
        { value: 'Red', label: 'Red', score: 0 },
      ],
    },
  },
];

export const cvssV4MetricDescriptions: { [key: string]: string } = {
  // Base Metrics - Exploitability
  AV: 'Attack Vector',
  AC: 'Attack Complexity',
  AT: 'Attack Requirements',
  PR: 'Privileges Required',
  UI: 'User Interaction',

  // Base Metrics - Vulnerable System Impact
  VC: 'Vulnerable System Confidentiality Impact',
  VI: 'Vulnerable System Integrity Impact',
  VA: 'Vulnerable System Availability Impact',

  // Base Metrics - Subsequent System Impact
  SC: 'Subsequent System Confidentiality Impact',
  SI: 'Subsequent System Integrity Impact',
  SA: 'Subsequent System Availability Impact',

  // Threat Metrics
  E: 'Exploit Maturity',

  // Environmental Metrics - Modified Base Metrics
  MAV: 'Modified Attack Vector',
  MAC: 'Modified Attack Complexity',
  MAT: 'Modified Attack Requirements',
  MPR: 'Modified Privileges Required',
  MUI: 'Modified User Interaction',
  MVC: 'Modified Vulnerable System Confidentiality Impact',
  MVI: 'Modified Vulnerable System Integrity Impact',
  MVA: 'Modified Vulnerable System Availability Impact',
  MSC: 'Modified Subsequent System Confidentiality Impact',
  MSI: 'Modified Subsequent System Integrity Impact',
  MSA: 'Modified Subsequent System Availability Impact',

  // Environmental Metrics - Security Requirements
  CR: 'Confidentiality Requirement',
  IR: 'Integrity Requirement',
  AR: 'Availability Requirement',

  // Supplemental Metrics
  S: 'Safety',
  AU: 'Automatable',
  R: 'Recovery',
  V: 'Value Density',
  RE: 'Vulnerability Response Effort',
  U: 'Provider Urgency',
};
