export interface CVSSMetric {
  value: string;
  label: string;
  score: number;
}

export interface CVSSMetricGroup {
  name: string;
  metrics: {
    [key: string]: CVSSMetric[];
  };
}

export interface CVSSScore {
  baseScore: number;
  temporalScore: number;
  environmentalScore: number;
  overallScore: number;
  severity: string;
}

export interface CVSSVector {
  AV?: string; // Attack Vector
  AC?: string; // Attack Complexity
  PR?: string; // Privileges Required
  UI?: string; // User Interaction
  S?: string; // Scope
  C?: string; // Confidentiality Impact
  I?: string; // Integrity Impact
  A?: string; // Availability Impact

  // Temporal Metrics
  E?: string; // Exploit Code Maturity
  RL?: string; // Remediation Level
  RC?: string; // Report Confidence

  // Environmental Metrics
  CR?: string; // Confidentiality Requirement
  IR?: string; // Integrity Requirement
  AR?: string; // Availability Requirement
  MAV?: string; // Modified Attack Vector
  MAC?: string; // Modified Attack Complexity
  MPR?: string; // Modified Privileges Required
  MUI?: string; // Modified User Interaction
  MS?: string; // Modified Scope
  MC?: string; // Modified Confidentiality
  MI?: string; // Modified Integrity
  MA?: string; // Modified Availability
}

export interface CVSSComparison {
  before: CVSSVector;
  after: CVSSVector;
  beforeScore: CVSSScore;
  afterScore: CVSSScore;
  remediationActions: string[];
  metricChanges: MetricChange[];
}

export interface MetricChange {
  metric: string;
  metricName: string;
  before: string;
  beforeLabel: string;
  after: string;
  afterLabel: string;
  comment: string;
}

export interface RemediationScenario {
  title: string;
  description: string;
  before: CVSSVector;
  after: CVSSVector;
  remediationActions: string[];
}
