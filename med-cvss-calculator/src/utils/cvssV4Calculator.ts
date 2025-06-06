import { CVSSV4Vector, CVSSScore } from '../types/cvss';
import { cvssV4Metrics } from '../data/cvssV4Metrics';
import { calculateCVSSV4Score as calculateOfficialV4Score } from './cvssV4Official';

export function calculateCVSSV4Score(vector: CVSSV4Vector): CVSSScore {
  // Use the official CVSS v4.0 algorithm for base score calculation
  const baseScore = calculateOfficialV4Score(vector);
  const threatScore = calculateV4ThreatScore(baseScore, vector);
  const environmentalScore = calculateV4EnvironmentalScore(baseScore, vector);

  // Determine the overall score based on which metric groups are present
  let overallScore = baseScore;
  if (vector.E && vector.E !== 'X') {
    overallScore = threatScore || baseScore;
  }
  if (hasEnvironmentalMetrics(vector)) {
    overallScore = environmentalScore || overallScore;
  }

  const severity = getSeverityRating(overallScore);

  return {
    baseScore,
    threatScore: vector.E && vector.E !== 'X' ? threatScore : undefined,
    environmentalScore: hasEnvironmentalMetrics(vector) ? environmentalScore : undefined,
    overallScore,
    severity,
  };
}

function hasEnvironmentalMetrics(vector: CVSSV4Vector): boolean {
  const envMetrics = [
    'MAV',
    'MAC',
    'MAT',
    'MPR',
    'MUI',
    'MVC',
    'MVI',
    'MVA',
    'MSC',
    'MSI',
    'MSA',
    'CR',
    'IR',
    'AR',
  ];
  return envMetrics.some(
    (metric) => vector[metric as keyof CVSSV4Vector] && vector[metric as keyof CVSSV4Vector] !== 'X'
  );
}

function getV4MetricScore(metricKey: string, value: string): number {
  for (const group of cvssV4Metrics) {
    if (group.metrics[metricKey]) {
      const metric = group.metrics[metricKey].find((m) => m.value === value);
      if (metric) return metric.score;
    }
  }
  return 0;
}

// Legacy scoring function - replaced by MacroVector algorithm
// function calculateV4BaseScore(vector: CVSSV4Vector): number {
//   // This was a simplified implementation
//   // Now using the official MacroVector algorithm in calculateV4BaseScoreMacroVector
// }

function calculateV4ThreatScore(baseScore: number, vector: CVSSV4Vector): number {
  const E = getV4MetricScore('E', vector.E || 'X');

  if (!vector.E || vector.E === 'X') {
    return 0;
  }

  // Simplified threat score calculation
  const threatScore = baseScore * E;
  return roundUp(threatScore);
}

function calculateV4EnvironmentalScore(_baseScore: number, vector: CVSSV4Vector): number {
  if (!hasEnvironmentalMetrics(vector)) {
    return 0;
  }

  // Use modified base metrics if available, otherwise fall back to base metrics
  const MAV =
    vector.MAV && vector.MAV !== 'X'
      ? getV4MetricScore('MAV', vector.MAV)
      : getV4MetricScore('AV', vector.AV || 'N');
  const MAC =
    vector.MAC && vector.MAC !== 'X'
      ? getV4MetricScore('MAC', vector.MAC)
      : getV4MetricScore('AC', vector.AC || 'L');
  const MAT =
    vector.MAT && vector.MAT !== 'X'
      ? getV4MetricScore('MAT', vector.MAT)
      : getV4MetricScore('AT', vector.AT || 'N');
  const MPR =
    vector.MPR && vector.MPR !== 'X'
      ? getV4MetricScore('MPR', vector.MPR)
      : getV4MetricScore('PR', vector.PR || 'N');
  const MUI =
    vector.MUI && vector.MUI !== 'X'
      ? getV4MetricScore('MUI', vector.MUI)
      : getV4MetricScore('UI', vector.UI || 'N');

  const MVC =
    vector.MVC && vector.MVC !== 'X'
      ? getV4MetricScore('MVC', vector.MVC)
      : getV4MetricScore('VC', vector.VC || 'N');
  const MVI =
    vector.MVI && vector.MVI !== 'X'
      ? getV4MetricScore('MVI', vector.MVI)
      : getV4MetricScore('VI', vector.VI || 'N');
  const MVA =
    vector.MVA && vector.MVA !== 'X'
      ? getV4MetricScore('MVA', vector.MVA)
      : getV4MetricScore('VA', vector.VA || 'N');

  const MSC =
    vector.MSC && vector.MSC !== 'X'
      ? getV4MetricScore('MSC', vector.MSC)
      : getV4MetricScore('SC', vector.SC || 'N');
  const MSI =
    vector.MSI && vector.MSI !== 'X'
      ? getV4MetricScore('MSI', vector.MSI)
      : getV4MetricScore('SI', vector.SI || 'N');
  const MSA =
    vector.MSA && vector.MSA !== 'X'
      ? getV4MetricScore('MSA', vector.MSA)
      : getV4MetricScore('SA', vector.SA || 'N');

  // Security requirements
  const CR = getV4MetricScore('CR', vector.CR || 'M');
  const IR = getV4MetricScore('IR', vector.IR || 'M');
  const AR = getV4MetricScore('AR', vector.AR || 'M');

  // Simplified environmental score calculation
  const modifiedExploitability = MAV * MAC * MAT * MPR * MUI;
  const modifiedVulnImpact = 1 - (1 - MVC * CR) * (1 - MVI * IR) * (1 - MVA * AR);
  const modifiedSubsImpact = 1 - (1 - MSC * CR) * (1 - MSI * IR) * (1 - MSA * AR);

  const maxModifiedImpact = Math.max(modifiedVulnImpact, modifiedSubsImpact);

  if (maxModifiedImpact <= 0) {
    return 0;
  }

  const score = Math.min(maxModifiedImpact * 6.42 + modifiedExploitability * 8.22, 10);
  return roundUp(score);
}

function roundUp(value: number): number {
  return Math.ceil(value * 10) / 10;
}

function getSeverityRating(score: number): string {
  if (score === 0) return 'None';
  if (score <= 3.9) return 'Low';
  if (score <= 6.9) return 'Medium';
  if (score <= 8.9) return 'High';
  return 'Critical';
}

export function generateV4VectorString(vector: CVSSV4Vector): string {
  const parts: string[] = ['CVSS:4.0'];

  // Base metrics (required)
  Object.entries(vector).forEach(([key, value]) => {
    if (value && value !== 'X') {
      parts.push(`${key}:${value}`);
    }
  });

  return parts.join('/');
}

export function parseV4VectorString(vectorString: string): CVSSV4Vector {
  const vector: CVSSV4Vector = {};

  if (!vectorString.startsWith('CVSS:4.0/')) {
    return vector;
  }

  const parts = vectorString.split('/').slice(1); // Remove 'CVSS:4.0'

  parts.forEach((part) => {
    const [key, value] = part.split(':');
    if (key && value) {
      (vector as any)[key] = value;
    }
  });

  return vector;
}
