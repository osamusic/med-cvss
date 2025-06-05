export interface RemediationExample {
  metric: string;
  changeReason: string;
  example: string;
}

export interface BeforeAfterComparison {
  metric: string;
  before: string;
  after: string;
  comment: string;
}

export interface RemediationGuidance {
  purpose: string[];
  changableMetrics: RemediationExample[];
  evaluationSteps: string[];
  outputExample: BeforeAfterComparison[];
}

export const remediationGuidance: RemediationGuidance = {
  purpose: [
    'Accurately reflect risk status after implementation of risk mitigation measures',
    'Consider changes in usage conditions and impact scope rather than the vulnerability itself',
    'Contribute to risk triage, notification decisions, and clarification of residual risks',
  ],

  changableMetrics: [
    {
      metric: 'Attack Vector (AV)',
      changeReason: 'Access restricted to prevent external access',
      example: 'Internet → Local only configuration change',
    },
    {
      metric: 'Attack Complexity (AC)',
      changeReason: 'Attack only feasible under complex conditions',
      example: 'Requires specific time window or user operations',
    },
    {
      metric: 'Privileges Required (PR)',
      changeReason: 'Cannot be executed without administrator privileges',
      example: 'Privilege separation and mandatory authentication added',
    },
    {
      metric: 'User Interaction (UI)',
      changeReason: 'Attack requires user interface interaction',
      example: 'One-click vulnerability → User operation required',
    },
    {
      metric: 'Scope (S)',
      changeReason: 'Attack impact scope isolated',
      example: 'Sandbox implementation, function isolation',
    },
    {
      metric: 'Confidentiality/Integrity/Availability',
      changeReason: 'Controlled to prevent actual damage',
      example: 'Data privatization, medical function deactivation',
    },
  ],

  evaluationSteps: [
    'Confirm remediation measures: Organize configuration changes, access controls, patch applications, privilege restrictions',
    "Redefine threat scenarios: Re-examine realistic attack conditions from attacker's perspective",
    'Re-evaluate Base Metrics: Determine if reproducibility, impact, and conditions have changed (reuse original checklist)',
    'Formal evaluation of Temporal Metrics: Reflect presence of countermeasures, PoC status, confidence (initial evaluation may use placeholder values)',
    'Record Before/After comparison: Document all metric differences and reasons in an explainable format',
  ],

  outputExample: [
    {
      metric: 'AV',
      before: 'Network',
      after: 'Local',
      comment: 'External ports closed',
    },
    {
      metric: 'PR',
      before: 'None',
      after: 'High',
      comment: 'Administrator privileges required due to authentication implementation',
    },
    {
      metric: 'C',
      before: 'High',
      after: 'None',
      comment: 'Confidential data separated to different system',
    },
    {
      metric: 'Remediation',
      before: 'Unavailable',
      after: 'Official Fix',
      comment: 'Patch provided by manufacturer',
    },
  ],
};

export const medicalDeviceRemediationScenarios = [
  {
    title: 'Network-Connected Medical Device Remediation Example',
    description: 'Network isolation of infusion pump',
    before: {
      AV: 'N',
      AC: 'L',
      PR: 'N',
      UI: 'N',
      S: 'U',
      C: 'N',
      I: 'H',
      A: 'H',
    },
    after: {
      AV: 'L',
      AC: 'L',
      PR: 'H',
      UI: 'N',
      S: 'U',
      C: 'N',
      I: 'L',
      A: 'L',
    },
    remediationActions: [
      'Implement network segmentation',
      'Enforce administrator authentication',
      'Limit impact scope (separate critical functions)',
    ],
  },
  {
    title: 'Patient Data Exposure Risk Remediation Example',
    description: 'Data encryption for Bluetooth medical device',
    before: {
      AV: 'A',
      AC: 'L',
      PR: 'N',
      UI: 'N',
      S: 'U',
      C: 'H',
      I: 'L',
      A: 'N',
    },
    after: {
      AV: 'A',
      AC: 'H',
      PR: 'L',
      UI: 'R',
      S: 'U',
      C: 'L',
      I: 'L',
      A: 'N',
    },
    remediationActions: [
      'Implement end-to-end encryption',
      'Strengthen pairing authentication',
      'Add user operation confirmation',
    ],
  },
  {
    title: 'Physical Access Control Remediation Example',
    description: 'Physical access restrictions for medical devices',
    before: {
      AV: 'P',
      AC: 'L',
      PR: 'N',
      UI: 'N',
      S: 'U',
      C: 'H',
      I: 'H',
      A: 'L',
    },
    after: {
      AV: 'P',
      AC: 'H',
      PR: 'H',
      UI: 'R',
      S: 'U',
      C: 'L',
      I: 'L',
      A: 'N',
    },
    remediationActions: [
      'Seal physical access ports',
      'Restrict operations to administrator privileges',
      'Encrypt and isolate confidential data',
    ],
  },
];
