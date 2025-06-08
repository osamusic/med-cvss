import { CVSSV4Vector, CVSSScore } from '../types/cvss';
import { CVSS40 } from './cvssV4FullImplementation';

/**
 * Calculate CVSS v4.0 score using the official implementation
 */
export function calculateCVSSV4Score(vector: CVSSV4Vector): CVSSScore {
  // Convert CVSSV4Vector to vector string and use the official CVSS v4.0 implementation
  const vectorString = generateV4VectorString(vector);
  const cvss = new CVSS40(vectorString);

  return {
    baseScore: cvss.score,
    overallScore: cvss.score,
    severity: cvss.severity,
  };
}

export function generateV4VectorString(vector: CVSSV4Vector): string {
  const parts: string[] = ['CVSS:4.0'];

  // Define the correct order for CVSS v4.0 metrics
  const metricOrder = [
    // Base metrics (mandatory)
    'AV',
    'AC',
    'AT',
    'PR',
    'UI',
    'VC',
    'VI',
    'VA',
    'SC',
    'SI',
    'SA',
    // Threat metrics
    'E',
    // Environmental metrics
    'CR',
    'IR',
    'AR',
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
    // Supplemental metrics
    'S',
    'AU',
    'R',
    'V',
    'RE',
    'U',
  ];

  // Add metrics in the correct order
  metricOrder.forEach((key) => {
    const value = vector[key as keyof CVSSV4Vector];
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
