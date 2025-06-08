import { CVSSVector, CVSSScore, CVSSV4Vector, CVSSVersion } from '../types/cvss';
import { cvssMetrics } from '../data/cvssMetrics';
import {
  calculateCVSSV4Score,
  generateV4VectorString,
  parseV4VectorString,
} from './cvssV4Calculator';

export function calculateCVSSScore(vector: CVSSVector): CVSSScore {
  // Get base and temporal metrics from the array structure
  const baseMetrics =
    cvssMetrics.find((group) => group.name === 'Base Score Metrics')?.metrics || {};
  const temporalMetrics =
    cvssMetrics.find((group) => group.name === 'Temporal Score Metrics')?.metrics || {};

  // Base Score calculation
  const av = baseMetrics.AV?.find((m) => m.value === (vector.AV || 'N')) || { score: 0.85 };
  const ac = baseMetrics.AC?.find((m) => m.value === (vector.AC || 'L')) || { score: 0.77 };
  const ui = baseMetrics.UI?.find((m) => m.value === (vector.UI || 'N')) || { score: 0.85 };
  const s = baseMetrics.S?.find((m) => m.value === (vector.S || 'U')) || { score: 0 };
  const c = baseMetrics.C?.find((m) => m.value === (vector.C || 'N')) || { score: 0 };
  const i = baseMetrics.I?.find((m) => m.value === (vector.I || 'N')) || { score: 0 };
  const a = baseMetrics.A?.find((m) => m.value === (vector.A || 'N')) || { score: 0 };

  // PR score needs adjustment based on scope
  let pr = baseMetrics.PR?.find((m) => m.value === (vector.PR || 'N')) || { score: 0.85 };
  if (s.score === 1) {
    // Scope Changed
    // Adjust PR scores for changed scope
    const prScopeChanged: { [key: string]: number } = {
      N: 0.85,
      L: 0.68,
      H: 0.5,
    };
    pr = { ...pr, score: prScopeChanged[vector.PR || 'N'] || pr.score };
  }

  // Calculate Impact Sub Score (ISS)
  const iss = 1 - (1 - c.score) * (1 - i.score) * (1 - a.score);

  // Calculate Impact
  let impact: number;
  if (s.score === 1) {
    // Scope Changed
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  } else {
    // Scope Unchanged
    impact = 6.42 * iss;
  }

  // Calculate Exploitability
  const exploitability = 8.22 * av.score * ac.score * pr.score * ui.score;

  // Calculate Base Score
  let baseScore: number;
  if (impact <= 0) {
    baseScore = 0;
  } else if (s.score === 1) {
    // Scope Changed
    baseScore = Math.min(1.08 * (impact + exploitability), 10);
  } else {
    // Scope Unchanged
    baseScore = Math.min(impact + exploitability, 10);
  }

  // Round UP to one decimal place (CVSS v3.1 specification)
  baseScore = Math.ceil(baseScore * 10) / 10;

  // Temporal Score calculation
  let temporalScore = baseScore;
  if (vector.E || vector.RL || vector.RC) {
    const e = temporalMetrics.E?.find((m) => m.value === (vector.E || 'X')) || { score: 1 };
    const rl = temporalMetrics.RL?.find((m) => m.value === (vector.RL || 'X')) || { score: 1 };
    const rc = temporalMetrics.RC?.find((m) => m.value === (vector.RC || 'X')) || { score: 1 };

    temporalScore = baseScore * e.score * rl.score * rc.score;
    temporalScore = Math.ceil(temporalScore * 10) / 10;
  }

  // Determine severity
  const severity = getSeverity(baseScore);

  return {
    baseScore,
    temporalScore,
    overallScore: temporalScore,
    severity,
  };
}

function getSeverity(score: number): string {
  if (score === 0.0) return 'None';
  if (score >= 0.1 && score <= 3.9) return 'Low';
  if (score >= 4.0 && score <= 6.9) return 'Medium';
  if (score >= 7.0 && score <= 8.9) return 'High';
  if (score >= 9.0 && score <= 10.0) return 'Critical';
  return 'None';
}

export function generateVectorString(vector: CVSSVector): string {
  const parts: string[] = ['CVSS:3.1'];

  // Base metrics (always included if present)
  const baseOrder = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
  baseOrder.forEach((key) => {
    if (vector[key as keyof CVSSVector]) {
      parts.push(`${key}:${vector[key as keyof CVSSVector]}`);
    }
  });

  // Temporal metrics (optional)
  const temporalOrder = ['E', 'RL', 'RC'];
  temporalOrder.forEach((key) => {
    if (vector[key as keyof CVSSVector] && vector[key as keyof CVSSVector] !== 'X') {
      parts.push(`${key}:${vector[key as keyof CVSSVector]}`);
    }
  });

  return parts.join('/');
}

export function parseVectorString(vectorString: string): {
  vector: CVSSVector | CVSSV4Vector;
  version: CVSSVersion;
} {
  if (vectorString.startsWith('CVSS:4.0/')) {
    return { vector: parseV4VectorString(vectorString), version: '4.0' };
  }

  const vector: CVSSVector = {};
  const parts = vectorString.split('/');

  // Skip the first part (CVSS:3.1)
  for (let i = 1; i < parts.length; i++) {
    const [key, value] = parts[i].split(':');
    if (key && value) {
      (vector as any)[key] = value;
    }
  }

  return { vector, version: '3.1' };
}

// Universal functions that work with both CVSS versions
export function calculateUniversalCVSSScore(
  vector: CVSSVector | CVSSV4Vector,
  version: CVSSVersion
): CVSSScore {
  if (version === '4.0') {
    // Filter out v3.1 specific metrics that are not valid in v4.0
    const v4Vector: CVSSV4Vector = {};
    const v31SpecificMetrics = ['S', 'RL', 'RC']; // Scope, Remediation Level, Report Confidence

    // Map v3.1 metrics to v4.0 equivalents where possible
    Object.entries(vector).forEach(([key, value]) => {
      if (!v31SpecificMetrics.includes(key)) {
        if (key === 'C' || key === 'I' || key === 'A') {
          // In v4.0, CIA impacts are split between Vulnerable and Subsequent systems
          // For conversion, we'll set both VC/SC, VI/SI, VA/SA to the same values
          if (key === 'C') {
            (v4Vector as any)['VC'] = value;
            (v4Vector as any)['SC'] = value;
          } else if (key === 'I') {
            (v4Vector as any)['VI'] = value;
            (v4Vector as any)['SI'] = value;
          } else if (key === 'A') {
            (v4Vector as any)['VA'] = value;
            (v4Vector as any)['SA'] = value;
          }
        } else {
          (v4Vector as any)[key] = value;
        }
      }
    });

    // Add default values for mandatory v4.0 metrics not present in v3.1
    if (!v4Vector.AT) v4Vector.AT = 'N'; // Attack Requirements - default to None

    // Ensure all mandatory base metrics have values (use safe defaults)
    if (!v4Vector.AV) v4Vector.AV = 'N'; // Attack Vector - default to Network
    if (!v4Vector.AC) v4Vector.AC = 'L'; // Attack Complexity - default to Low
    if (!v4Vector.PR) v4Vector.PR = 'N'; // Privileges Required - default to None
    if (!v4Vector.UI) v4Vector.UI = 'N'; // User Interaction - default to None
    if (!v4Vector.VC) v4Vector.VC = 'N'; // Vulnerable Confidentiality - default to None
    if (!v4Vector.VI) v4Vector.VI = 'N'; // Vulnerable Integrity - default to None
    if (!v4Vector.VA) v4Vector.VA = 'N'; // Vulnerable Availability - default to None
    if (!v4Vector.SC) v4Vector.SC = 'N'; // Subsequent Confidentiality - default to None
    if (!v4Vector.SI) v4Vector.SI = 'N'; // Subsequent Integrity - default to None
    if (!v4Vector.SA) v4Vector.SA = 'N'; // Subsequent Availability - default to None

    return calculateCVSSV4Score(v4Vector);
  } else {
    return calculateCVSSScore(vector as CVSSVector);
  }
}

export function generateUniversalVectorString(
  vector: CVSSVector | CVSSV4Vector,
  version: CVSSVersion
): string {
  if (version === '4.0') {
    // Filter out v3.1 specific metrics that are not valid in v4.0
    const v4Vector: CVSSV4Vector = {};
    const v31SpecificMetrics = ['S', 'RL', 'RC']; // Scope, Remediation Level, Report Confidence

    // Map v3.1 metrics to v4.0 equivalents where possible
    Object.entries(vector).forEach(([key, value]) => {
      if (!v31SpecificMetrics.includes(key)) {
        if (key === 'C' || key === 'I' || key === 'A') {
          // In v4.0, CIA impacts are split between Vulnerable and Subsequent systems
          // For conversion, we'll set both VC/SC, VI/SI, VA/SA to the same values
          if (key === 'C') {
            (v4Vector as any)['VC'] = value;
            (v4Vector as any)['SC'] = value;
          } else if (key === 'I') {
            (v4Vector as any)['VI'] = value;
            (v4Vector as any)['SI'] = value;
          } else if (key === 'A') {
            (v4Vector as any)['VA'] = value;
            (v4Vector as any)['SA'] = value;
          }
        } else {
          (v4Vector as any)[key] = value;
        }
      }
    });

    // Add default values for mandatory v4.0 metrics not present in v3.1
    if (!v4Vector.AT) v4Vector.AT = 'N'; // Attack Requirements - default to None

    // Ensure all mandatory base metrics have values (use safe defaults)
    if (!v4Vector.AV) v4Vector.AV = 'N'; // Attack Vector - default to Network
    if (!v4Vector.AC) v4Vector.AC = 'L'; // Attack Complexity - default to Low
    if (!v4Vector.PR) v4Vector.PR = 'N'; // Privileges Required - default to None
    if (!v4Vector.UI) v4Vector.UI = 'N'; // User Interaction - default to None
    if (!v4Vector.VC) v4Vector.VC = 'N'; // Vulnerable Confidentiality - default to None
    if (!v4Vector.VI) v4Vector.VI = 'N'; // Vulnerable Integrity - default to None
    if (!v4Vector.VA) v4Vector.VA = 'N'; // Vulnerable Availability - default to None
    if (!v4Vector.SC) v4Vector.SC = 'N'; // Subsequent Confidentiality - default to None
    if (!v4Vector.SI) v4Vector.SI = 'N'; // Subsequent Integrity - default to None
    if (!v4Vector.SA) v4Vector.SA = 'N'; // Subsequent Availability - default to None

    return generateV4VectorString(v4Vector);
  } else {
    return generateVectorString(vector as CVSSVector);
  }
}

export function parseUniversalVectorString(vectorString: string): {
  vector: CVSSVector | CVSSV4Vector;
  version: CVSSVersion;
} {
  return parseVectorString(vectorString);
}
