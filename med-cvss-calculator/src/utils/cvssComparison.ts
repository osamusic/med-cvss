import { CVSSVector, CVSSComparison, MetricChange } from '../types/cvss';
import { calculateCVSSScore } from './cvssCalculator';
import { cvssMetrics } from '../data/cvssMetrics';

export function compareVectors(
  before: CVSSVector,
  after: CVSSVector,
  remediationActions: string[] = []
): CVSSComparison {
  const beforeScore = calculateCVSSScore(before);
  const afterScore = calculateCVSSScore(after);
  const metricChanges = generateMetricChanges(before, after);

  return {
    version: '3.1',
    before,
    after,
    beforeScore,
    afterScore,
    remediationActions,
    metricChanges,
  };
}

export function generateMetricChanges(before: CVSSVector, after: CVSSVector): MetricChange[] {
  const changes: MetricChange[] = [];
  const metricNames = {
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

  Object.keys(metricNames).forEach((metric) => {
    const beforeValue = before[metric as keyof CVSSVector];
    const afterValue = after[metric as keyof CVSSVector];

    if (beforeValue !== afterValue && (beforeValue || afterValue)) {
      const beforeLabel = getMetricLabel(metric, beforeValue || '');
      const afterLabel = getMetricLabel(metric, afterValue || '');

      changes.push({
        metric,
        metricName: metricNames[metric as keyof typeof metricNames],
        before: beforeValue || '',
        beforeLabel,
        after: afterValue || '',
        afterLabel,
        comment: generateChangeComment(metric, beforeValue, afterValue),
      });
    }
  });

  return changes;
}

function getMetricLabel(metricKey: string, value: string): string {
  if (!value) return '';

  for (const group of cvssMetrics) {
    if (group.metrics[metricKey]) {
      const metric = group.metrics[metricKey].find((m) => m.value === value);
      if (metric) return metric.label;
    }
  }
  return value;
}

function generateChangeComment(metric: string, beforeValue?: string, afterValue?: string): string {
  const comments: { [key: string]: { [key: string]: string } } = {
    AV: {
      'N->L': 'Restricted external network access to local only',
      'N->A': 'Restricted network access to adjacent network only',
      'N->P': 'Restricted network access to physical access only',
      'A->L': 'Restricted adjacent network access to local only',
      'A->P': 'Restricted adjacent network access to physical access only',
      'L->P': 'Restricted local access to physical access only',
    },
    AC: {
      'L->H': 'Complicated attack conditions (time restrictions, specific conditions, etc.)',
    },
    PR: {
      'N->L': 'Requires low-privilege user authentication',
      'N->H': 'Requires administrator privilege authentication',
      'L->H': 'Changed to require administrator privilege authentication',
    },
    UI: {
      'N->R': 'Made user operation confirmation mandatory',
    },
    S: {
      'U->C': 'Impact scope expanded',
      'C->U': 'Impact scope restricted to container',
    },
    RL: {
      'U->O': 'Official patch provided',
      'U->T': 'Temporary fix provided',
      'U->W': 'Workaround provided',
    },
  };

  const key = `${beforeValue}->${afterValue}`;
  return comments[metric]?.[key] || 'Configuration has been changed';
}

export function calculateRiskReduction(
  beforeScore: number,
  afterScore: number
): {
  scoreReduction: number;
  percentageReduction: number;
  riskCategory: string;
} {
  const scoreReduction = beforeScore - afterScore;
  const percentageReduction = beforeScore > 0 ? (scoreReduction / beforeScore) * 100 : 0;

  let riskCategory = '';
  if (percentageReduction >= 70) {
    riskCategory = 'Significant Risk Reduction';
  } else if (percentageReduction >= 40) {
    riskCategory = 'Moderate Risk Reduction';
  } else if (percentageReduction >= 10) {
    riskCategory = 'Minor Risk Reduction';
  } else if (percentageReduction > 0) {
    riskCategory = 'Slight Risk Reduction';
  } else if (percentageReduction === 0) {
    riskCategory = 'No Change';
  } else {
    riskCategory = 'Risk Increase';
  }

  return {
    scoreReduction,
    percentageReduction: Math.round(percentageReduction * 10) / 10,
    riskCategory,
  };
}

export function generateComparisonReport(comparison: CVSSComparison): string {
  const { beforeScore, afterScore, metricChanges, remediationActions } = comparison;
  const riskReduction = calculateRiskReduction(beforeScore.overallScore, afterScore.overallScore);

  let report = `# CVSS Before/After Comparison Report\n\n`;

  report += `## Score Changes\n`;
  report += `- **Before**: ${beforeScore.overallScore} (${beforeScore.severity})\n`;
  report += `- **After**: ${afterScore.overallScore} (${afterScore.severity})\n`;
  report += `- **Risk Reduction**: ${riskReduction.scoreReduction.toFixed(1)} points (${riskReduction.percentageReduction}% reduction)\n`;
  report += `- **Assessment**: ${riskReduction.riskCategory}\n\n`;

  if (metricChanges.length > 0) {
    report += `## Metric Change Details\n`;
    metricChanges.forEach((change) => {
      report += `### ${change.metricName} (${change.metric})\n`;
      report += `- **Before**: ${change.beforeLabel} (${change.before})\n`;
      report += `- **After**: ${change.afterLabel} (${change.after})\n`;
      report += `- **Comment**: ${change.comment}\n\n`;
    });
  }

  if (remediationActions.length > 0) {
    report += `## Implemented Remediation Actions\n`;
    remediationActions.forEach((action, index) => {
      report += `${index + 1}. ${action}\n`;
    });
  }

  return report;
}
