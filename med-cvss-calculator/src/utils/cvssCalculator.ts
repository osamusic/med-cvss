import { CVSSVector, CVSSScore, CVSSV4Vector, CVSSVersion } from '../types/cvss';
import { cvssMetrics } from '../data/cvssMetrics';
import {
  calculateCVSSV4Score,
  generateV4VectorString,
  parseV4VectorString,
} from './cvssV4Calculator';

export function calculateCVSSScore(vector: CVSSVector): CVSSScore {
  const baseScore = calculateBaseScore(vector);
  const temporalScore = calculateTemporalScore(baseScore, vector);

  const overallScore = temporalScore || baseScore;
  const severity = getSeverityRating(overallScore);

  return {
    baseScore,
    temporalScore,
    overallScore,
    severity,
  };
}

function getMetricScore(metricKey: string, value: string): number {
  for (const group of cvssMetrics) {
    if (group.metrics[metricKey]) {
      const metric = group.metrics[metricKey].find((m) => m.value === value);
      if (metric) return metric.score;
    }
  }
  return 0;
}

function calculateBaseScore(vector: CVSSVector): number {
  const AV = getMetricScore('AV', vector.AV || 'N');
  const AC = getMetricScore('AC', vector.AC || 'L');
  const PR = getMetricScore('PR', vector.PR || 'N');
  const UI = getMetricScore('UI', vector.UI || 'N');
  const S = vector.S || 'U';
  const C = getMetricScore('C', vector.C || 'N');
  const I = getMetricScore('I', vector.I || 'N');
  const A = getMetricScore('A', vector.A || 'N');

  // Adjust PR based on Scope
  const adjustedPR = S === 'C' ? (PR === 0.62 ? 0.68 : PR === 0.27 ? 0.5 : PR) : PR;

  const exploitability = 8.22 * AV * AC * adjustedPR * UI;

  const impactSubScore = 1 - (1 - C) * (1 - I) * (1 - A);

  let impact: number;
  if (S === 'U') {
    impact = 6.42 * impactSubScore;
  } else {
    impact = 7.52 * (impactSubScore - 0.029) - 3.25 * Math.pow(impactSubScore - 0.02, 15);
  }

  if (impact <= 0) {
    return 0;
  }

  let score: number;
  if (S === 'U') {
    score = Math.min(impact + exploitability, 10);
  } else {
    score = Math.min(1.08 * (impact + exploitability), 10);
  }

  return roundUp(score);
}

function calculateTemporalScore(baseScore: number, vector: CVSSVector): number {
  const E = getMetricScore('E', vector.E || 'X');
  const RL = getMetricScore('RL', vector.RL || 'X');
  const RC = getMetricScore('RC', vector.RC || 'X');

  if (!vector.E && !vector.RL && !vector.RC) {
    return 0;
  }

  const temporalScore = baseScore * E * RL * RC;
  return roundUp(temporalScore);
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

export function generateVectorString(vector: CVSSVector): string {
  const parts: string[] = ['CVSS:3.1'];

  Object.entries(vector).forEach(([key, value]) => {
    if (value && value !== 'X') {
      parts.push(`${key}:${value}`);
    }
  });

  return parts.join('/');
}

// Universal functions that work with both CVSS versions
export function calculateUniversalCVSSScore(
  vector: CVSSVector | CVSSV4Vector,
  version: CVSSVersion
): CVSSScore {
  if (version === '4.0') {
    return calculateCVSSV4Score(vector as CVSSV4Vector);
  } else {
    return calculateCVSSScore(vector as CVSSVector);
  }
}

export function generateUniversalVectorString(
  vector: CVSSVector | CVSSV4Vector,
  version: CVSSVersion
): string {
  if (version === '4.0') {
    return generateV4VectorString(vector as CVSSV4Vector);
  } else {
    return generateVectorString(vector as CVSSVector);
  }
}

export function parseVectorString(vectorString: string): {
  vector: CVSSVector | CVSSV4Vector;
  version: CVSSVersion;
} {
  if (vectorString.startsWith('CVSS:4.0/')) {
    return {
      vector: parseV4VectorString(vectorString),
      version: '4.0',
    };
  } else if (vectorString.startsWith('CVSS:3.1/')) {
    return {
      vector: parseV31VectorString(vectorString),
      version: '3.1',
    };
  } else {
    // Default to 3.1 for backward compatibility
    return {
      vector: parseV31VectorString(vectorString),
      version: '3.1',
    };
  }
}

function parseV31VectorString(vectorString: string): CVSSVector {
  const vector: CVSSVector = {};

  const parts = vectorString.replace('CVSS:3.1/', '').split('/');

  parts.forEach((part) => {
    const [key, value] = part.split(':');
    if (key && value) {
      (vector as any)[key] = value;
    }
  });

  return vector;
}

export function detectCVSSVersion(vectorString: string): CVSSVersion {
  if (vectorString.startsWith('CVSS:4.0')) {
    return '4.0';
  }
  return '3.1'; // Default to 3.1
}
