export type CVSSVersion = '3.1' | '4.0';

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
  temporalScore?: number;
  threatScore?: number; // CVSS v4.0
  environmentalScore?: number; // CVSS v4.0
  overallScore: number;
  severity: string;
}

// CVSS v3.1 Vector
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
}

// CVSS v4.0 Vector
export interface CVSSV4Vector {
  // Base Metrics - Exploitability
  AV?: string; // Attack Vector
  AC?: string; // Attack Complexity
  AT?: string; // Attack Requirements
  PR?: string; // Privileges Required
  UI?: string; // User Interaction

  // Base Metrics - Vulnerable System Impact
  VC?: string; // Vulnerable System Confidentiality Impact
  VI?: string; // Vulnerable System Integrity Impact
  VA?: string; // Vulnerable System Availability Impact

  // Base Metrics - Subsequent System Impact
  SC?: string; // Subsequent System Confidentiality Impact
  SI?: string; // Subsequent System Integrity Impact
  SA?: string; // Subsequent System Availability Impact

  // Threat Metrics
  E?: string; // Exploit Maturity

  // Environmental Metrics - Modified Base Metrics
  MAV?: string; // Modified Attack Vector
  MAC?: string; // Modified Attack Complexity
  MAT?: string; // Modified Attack Requirements
  MPR?: string; // Modified Privileges Required
  MUI?: string; // Modified User Interaction
  MVC?: string; // Modified Vulnerable System Confidentiality Impact
  MVI?: string; // Modified Vulnerable System Integrity Impact
  MVA?: string; // Modified Vulnerable System Availability Impact
  MSC?: string; // Modified Subsequent System Confidentiality Impact
  MSI?: string; // Modified Subsequent System Integrity Impact
  MSA?: string; // Modified Subsequent System Availability Impact

  // Environmental Metrics - Requirements
  CR?: string; // Confidentiality Requirement
  IR?: string; // Integrity Requirement
  AR?: string; // Availability Requirement

  // Supplemental Metrics
  S?: string; // Safety
  AU?: string; // Automatable
  R?: string; // Recovery
  V?: string; // Value Density
  RE?: string; // Vulnerability Response Effort
  U?: string; // Provider Urgency
}

export interface CVSSComparison {
  version: CVSSVersion;
  before: CVSSVector | CVSSV4Vector;
  after: CVSSVector | CVSSV4Vector;
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
  version: CVSSVersion;
  before: CVSSVector | CVSSV4Vector;
  after: CVSSVector | CVSSV4Vector;
  remediationActions: string[];
}
