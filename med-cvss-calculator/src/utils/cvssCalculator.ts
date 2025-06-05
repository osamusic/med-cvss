import { CVSSVector, CVSSScore } from '../types/cvss';
import { cvssMetrics } from '../data/cvssMetrics';

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
