/**
 * CVSS v4.0 Full Implementation with Vector and CVSS40 classes
 * 
 * Based on the official RedHat CVSS v4.0 Calculator
 * Source: https://github.com/RedHatProductSecurity/cvss-v4-calculator
 * 
 * Copyright (c) FIRST.ORG, Inc., Red Hat, and contributors
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * 
 * SPDX-License-Identifier: BSD-2-Clause
 * 
 * ---
 * 
 * CUSTOMIZATIONS for med-cvss-calculator:
 * - Converted from JavaScript to TypeScript for type safety
 * - Added proper TypeScript type annotations and interfaces
 * - Integrated with existing CVSSV4Vector interface for compatibility
 * - Added ESLint compliance for code quality standards
 * - Customized for medical device security assessment use cases
 * - Maintained compatibility with existing test suites
 */

/**
 * Rounds a number to a specified number of decimal places using the "Round Half Up" method.
 */
function roundToDecimalPlaces(value: number): number {
  const EPSILON = Math.pow(10, -6);
  return Math.round((value + EPSILON) * 10) / 10;
}

/**
 * Class representing a CVSS v4.0 vector.
 */
export class Vector {
  // CVSS40 metrics with defaults values at first key
  static METRICS = {
    // Base (11 metrics)
    BASE: {
      AV: ['N', 'A', 'L', 'P'],
      AC: ['L', 'H'],
      AT: ['N', 'P'],
      PR: ['N', 'L', 'H'],
      UI: ['N', 'P', 'A'],
      VC: ['N', 'L', 'H'],
      VI: ['N', 'L', 'H'],
      VA: ['N', 'L', 'H'],
      SC: ['N', 'L', 'H'],
      SI: ['N', 'L', 'H'],
      SA: ['N', 'L', 'H'],
    },
    // Threat (1 metric)
    THREAT: {
      E: ['X', 'A', 'P', 'U'],
    },
    // Environmental (14 metrics)
    ENVIRONMENTAL: {
      CR: ['X', 'H', 'M', 'L'],
      IR: ['X', 'H', 'M', 'L'],
      AR: ['X', 'H', 'M', 'L'],
      MAV: ['X', 'N', 'A', 'L', 'P'],
      MAC: ['X', 'L', 'H'],
      MAT: ['X', 'N', 'P'],
      MPR: ['X', 'N', 'L', 'H'],
      MUI: ['X', 'N', 'P', 'A'],
      MVC: ['X', 'H', 'L', 'N'],
      MVI: ['X', 'H', 'L', 'N'],
      MVA: ['X', 'H', 'L', 'N'],
      MSC: ['X', 'H', 'L', 'N'],
      MSI: ['X', 'S', 'H', 'L', 'N'],
      MSA: ['X', 'S', 'H', 'L', 'N'],
    },
    // Supplemental (6 metrics)
    SUPPLEMENTAL: {
      S: ['X', 'N', 'P'],
      AU: ['X', 'N', 'Y'],
      R: ['X', 'A', 'U', 'I'],
      V: ['X', 'D', 'C'],
      RE: ['X', 'L', 'M', 'H'],
      U: ['X', 'Clear', 'Green', 'Amber', 'Red'],
    },
  };

  static ALL_METRICS = Object.keys(Vector.METRICS).reduce((order, category) => {
    return { ...order, ...Vector.METRICS[category as keyof typeof Vector.METRICS] };
  }, {});

  static BASE_NOMENCLATURE = 'CVSS-B';

  metrics: { [key: string]: string };

  constructor(vectorString = '') {
    // Initialize the metrics
    const selected: { [key: string]: string } = {};
    for (const category in Vector.METRICS) {
      const metricsCategory = Vector.METRICS[category as keyof typeof Vector.METRICS];
      for (const key in metricsCategory) {
        // Use the first value in the array of allowed values as the default
        selected[key] = (metricsCategory as any)[key][0];
      }
    }

    this.metrics = selected;

    if (vectorString) {
      // Remove any leading '#' symbol
      if (vectorString.startsWith('#')) {
        vectorString = vectorString.slice(1);
      }
      this.updateMetricsFromVectorString(vectorString);
    }
  }

  get raw(): string {
    // Construct the vector string dynamically based on the current state of `metrics`
    const baseString = 'CVSS:4.0';
    const metricEntries = Object.entries(this.metrics)
      .filter(([, value]) => value !== 'X') // Filter out metrics with value "X"
      .map(([key, value]) => `/${key}:${value}`)
      .join('');
    return baseString + metricEntries;
  }

  get equivalentClasses(): string {
    // Helper function to compute EQ1
    const computeEQ1 = () => {
      const AV = this.getEffectiveMetricValue('AV');
      const PR = this.getEffectiveMetricValue('PR');
      const UI = this.getEffectiveMetricValue('UI');

      if (AV === 'N' && PR === 'N' && UI === 'N') {
        return '0';
      }
      if (
        (AV === 'N' || PR === 'N' || UI === 'N') &&
        !(AV === 'N' && PR === 'N' && UI === 'N') &&
        AV !== 'P'
      ) {
        return '1';
      }
      if (AV === 'P' || !(AV === 'N' || PR === 'N' || UI === 'N')) {
        return '2';
      }
      return '0'; // Default case
    };

    // Helper function to compute EQ2
    const computeEQ2 = () => {
      const AC = this.getEffectiveMetricValue('AC');
      const AT = this.getEffectiveMetricValue('AT');

      return AC === 'L' && AT === 'N' ? '0' : '1';
    };

    // Helper function to compute EQ3
    const computeEQ3 = () => {
      const VC = this.getEffectiveMetricValue('VC');
      const VI = this.getEffectiveMetricValue('VI');
      const VA = this.getEffectiveMetricValue('VA');

      if (VC === 'H' && VI === 'H') {
        return '0';
      }
      if (!(VC === 'H' && VI === 'H') && (VC === 'H' || VI === 'H' || VA === 'H')) {
        return '1';
      }
      if (!(VC === 'H' || VI === 'H' || VA === 'H')) {
        return '2';
      }
      return '0'; // Default case
    };

    // Helper function to compute EQ4
    const computeEQ4 = () => {
      const MSI = this.getEffectiveMetricValue('MSI');
      const MSA = this.getEffectiveMetricValue('MSA');
      const SC = this.getEffectiveMetricValue('SC');
      const SI = this.getEffectiveMetricValue('SI');
      const SA = this.getEffectiveMetricValue('SA');

      if (MSI === 'S' || MSA === 'S') {
        return '0';
      }
      if (!(MSI === 'S' || MSA === 'S') && (SC === 'H' || SI === 'H' || SA === 'H')) {
        return '1';
      }
      return '2';
    };

    // Helper function to compute EQ5
    const computeEQ5 = () => {
      const E = this.getEffectiveMetricValue('E');
      if (E === 'A') return '0';
      if (E === 'P') return '1';
      if (E === 'U') return '2';
      return '0'; // Default case
    };

    // Helper function to compute EQ6
    const computeEQ6 = () => {
      const CR = this.getEffectiveMetricValue('CR');
      const VC = this.getEffectiveMetricValue('VC');
      const IR = this.getEffectiveMetricValue('IR');
      const VI = this.getEffectiveMetricValue('VI');
      const AR = this.getEffectiveMetricValue('AR');
      const VA = this.getEffectiveMetricValue('VA');

      if ((CR === 'H' && VC === 'H') || (IR === 'H' && VI === 'H') || (AR === 'H' && VA === 'H')) {
        return '0';
      }
      return '1';
    };

    // Compute all equivalency values
    const eq1 = computeEQ1();
    const eq2 = computeEQ2();
    const eq3 = computeEQ3();
    const eq4 = computeEQ4();
    const eq5 = computeEQ5();
    const eq6 = computeEQ6();

    // Combine all EQ values into the equivalent classes
    return eq1 + eq2 + eq3 + eq4 + eq5 + eq6;
  }

  get nomenclature(): string {
    let nomenclature = Vector.BASE_NOMENCLATURE;

    const hasThreatMetrics = Object.keys(Vector.METRICS.THREAT).some(
      (key) => this.metrics[key] !== 'X'
    );
    const hasEnvironmentalMetrics = Object.keys(Vector.METRICS.ENVIRONMENTAL).some(
      (key) => this.metrics[key] !== 'X'
    );

    if (hasThreatMetrics) {
      nomenclature += 'T';
    }

    if (hasEnvironmentalMetrics) {
      nomenclature += 'E';
    }

    return nomenclature;
  }

  get severityBreakdown(): { [key: string]: string } {
    const macroVector = this.equivalentClasses;

    // Define the macrovectors and their positions
    const macroVectorDetails = [
      'Exploitability',
      'Complexity',
      'Vulnerable system',
      'Subsequent system',
      'Exploitation',
      'Security requirements',
    ];

    // Define which macrovectors have only two severity options
    const macroVectorsWithTwoSeverities = ['Complexity', 'Security requirements'];

    // Lookup tables for macrovectors with two and three possible severity levels
    const threeSeverities = ['High', 'Medium', 'Low'];
    const twoSeverities = ['High', 'Low'];

    // Construct the detailed breakdown
    return Object.fromEntries(
      macroVectorDetails.map((description, index) => {
        // Determine which lookup table to use based on the macrovector description
        const macroVectorValueOptions = macroVectorsWithTwoSeverities.includes(description)
          ? twoSeverities
          : threeSeverities;

        return [description, macroVectorValueOptions[parseInt(macroVector[index])]];
      })
    );
  }

  getEffectiveMetricValue(metric: string): string {
    // Default worst-case scenarios for specific metrics
    const worstCaseDefaults: { [key: string]: string } = {
      E: 'A', // If E=X, it defaults to E=A
      CR: 'H', // If CR=X, it defaults to CR=H
      IR: 'H', // If IR=X, it defaults to IR=H
      AR: 'H', // If AR=X, it defaults to AR=H
    };

    // Check if the metric has a worst-case default
    if (
      this.metrics[metric] === 'X' &&
      Object.prototype.hasOwnProperty.call(worstCaseDefaults, metric)
    ) {
      return worstCaseDefaults[metric];
    }

    // Check for environmental metrics that overwrite score values
    const modifiedMetric = 'M' + metric;
    if (
      Object.prototype.hasOwnProperty.call(this.metrics, modifiedMetric) &&
      this.metrics[modifiedMetric] !== 'X'
    ) {
      return this.metrics[modifiedMetric];
    }

    // Return the selected value for the metric
    return this.metrics[metric];
  }

  validateStringVector(vector: string): boolean {
    const metrics = vector.split('/');

    // Check if the prefix is correct
    if (metrics.shift() !== 'CVSS:4.0') {
      // eslint-disable-next-line no-console
      console.error('Error: invalid vector, missing CVSS v4.0 prefix from vector: ' + vector);
      return false;
    }

    const expectedMetrics = Object.entries(Vector.ALL_METRICS);
    let mandatoryMetricIndex = 0;

    for (const metric of metrics) {
      const [key, value] = metric.split(':');

      // Check if there are too many metric values
      if (!expectedMetrics[mandatoryMetricIndex]) {
        // eslint-disable-next-line no-console
        console.error('Error: invalid vector, too many metric values');
        return false;
      }

      // Find the current expected metric
      while (
        expectedMetrics[mandatoryMetricIndex] &&
        expectedMetrics[mandatoryMetricIndex][0] !== key
      ) {
        // Check for missing mandatory metrics
        if (mandatoryMetricIndex < 11) {
          // eslint-disable-next-line no-console
          console.error('Error: invalid vector, missing mandatory metrics');
          return false;
        }
        mandatoryMetricIndex++;
      }

      // Check if the value is valid for the given metric
      const validValues = expectedMetrics[mandatoryMetricIndex][1] as string[];
      if (!validValues.includes(value)) {
        // eslint-disable-next-line no-console
        console.error(
          `Error: invalid vector, for key ${key}, value ${value} is not in ${expectedMetrics[mandatoryMetricIndex][1]}`
        );
        return false;
      }

      mandatoryMetricIndex++;
    }

    return true;
  }

  updateMetricsFromVectorString(vector: string): void {
    if (!vector) {
      throw new Error('The vector string cannot be null, undefined, or empty.');
    }

    // Validate the CVSS v4.0 string vector
    if (!this.validateStringVector(vector)) {
      throw new Error('Invalid CVSS v4.0 vector: ' + vector);
    }

    const metrics = vector.split('/');

    // Remove the "CVSS:4.0" prefix
    metrics.shift();

    // Iterate through each metric component and update the corresponding metric in the `metrics` object
    for (const metric of metrics) {
      const [key, value] = metric.split(':');
      this.metrics[key] = value;
    }
  }

  updateMetric(metric: string, value: string): void {
    if (Object.prototype.hasOwnProperty.call(this.metrics, metric)) {
      this.metrics[metric] = value;
    } else {
      // eslint-disable-next-line no-console
      console.error(`Metric ${metric} not found.`);
    }
  }
}

/**
 * Class representing the CVSS v4.0 scoring system.
 */
export class CVSS40 {
  // Lookup table of macro vectors and their pre-computed equivalent classes value.
  static LOOKUP_TABLE: { [key: string]: number } = {
    '000000': 10,
    '000001': 9.9,
    '000010': 9.8,
    '000011': 9.5,
    '000020': 9.5,
    '000021': 9.2,
    '000100': 10,
    '000101': 9.6,
    '000110': 9.3,
    '000111': 8.7,
    '000120': 9.1,
    '000121': 8.1,
    '000200': 9.3,
    '000201': 9,
    '000210': 8.9,
    '000211': 8,
    '000220': 8.1,
    '000221': 6.8,
    '001000': 9.8,
    '001001': 9.5,
    '001010': 9.5,
    '001011': 9.2,
    '001020': 9,
    '001021': 8.4,
    '001100': 9.3,
    '001101': 9.2,
    '001110': 8.9,
    '001111': 8.1,
    '001120': 8.1,
    '001121': 6.5,
    '001200': 8.8,
    '001201': 8,
    '001210': 7.8,
    '001211': 7,
    '001220': 6.9,
    '001221': 4.8,
    '002001': 9.2,
    '002011': 8.2,
    '002021': 7.2,
    '002101': 7.9,
    '002111': 6.9,
    '002121': 5,
    '002201': 6.9,
    '002211': 5.5,
    '002221': 2.7,
    '010000': 9.9,
    '010001': 9.7,
    '010010': 9.5,
    '010011': 9.2,
    '010020': 9.2,
    '010021': 8.5,
    '010100': 9.5,
    '010101': 9.1,
    '010110': 9,
    '010111': 8.3,
    '010120': 8.4,
    '010121': 7.1,
    '010200': 9.2,
    '010201': 8.1,
    '010210': 8.2,
    '010211': 7.1,
    '010220': 7.2,
    '010221': 5.3,
    '011000': 9.5,
    '011001': 9.3,
    '011010': 9.2,
    '011011': 8.5,
    '011020': 8.5,
    '011021': 7.3,
    '011100': 9.2,
    '011101': 8.2,
    '011110': 8,
    '011111': 7.2,
    '011120': 7,
    '011121': 5.9,
    '011200': 8.4,
    '011201': 7,
    '011210': 7.1,
    '011211': 5.2,
    '011220': 5,
    '011221': 3,
    '012001': 8.6,
    '012011': 7.5,
    '012021': 5.2,
    '012101': 7.1,
    '012111': 5.2,
    '012121': 2.9,
    '012201': 6.3,
    '012211': 2.9,
    '012221': 1.7,
    '100000': 9.8,
    '100001': 9.5,
    '100010': 9.4,
    '100011': 8.7,
    '100020': 9.1,
    '100021': 8.1,
    '100100': 9.4,
    '100101': 8.9,
    '100110': 8.6,
    '100111': 7.4,
    '100120': 7.7,
    '100121': 6.4,
    '100200': 8.7,
    '100201': 7.5,
    '100210': 7.4,
    '100211': 6.3,
    '100220': 6.3,
    '100221': 4.9,
    '101000': 9.4,
    '101001': 8.9,
    '101010': 8.8,
    '101011': 7.7,
    '101020': 7.6,
    '101021': 6.7,
    '101100': 8.6,
    '101101': 7.6,
    '101110': 7.4,
    '101111': 5.8,
    '101120': 5.9,
    '101121': 5,
    '101200': 7.2,
    '101201': 5.7,
    '101210': 5.7,
    '101211': 5.2,
    '101220': 5.2,
    '101221': 2.5,
    '102001': 8.3,
    '102011': 7,
    '102021': 5.4,
    '102101': 6.5,
    '102111': 5.8,
    '102121': 2.6,
    '102201': 5.3,
    '102211': 2.1,
    '102221': 1.3,
    '110000': 9.5,
    '110001': 9,
    '110010': 8.8,
    '110011': 7.6,
    '110020': 7.6,
    '110021': 7,
    '110100': 9,
    '110101': 7.7,
    '110110': 7.5,
    '110111': 6.2,
    '110120': 6.1,
    '110121': 5.3,
    '110200': 7.7,
    '110201': 6.6,
    '110210': 6.8,
    '110211': 5.9,
    '110220': 5.2,
    '110221': 3,
    '111000': 8.9,
    '111001': 7.8,
    '111010': 7.6,
    '111011': 6.7,
    '111020': 6.2,
    '111021': 5.8,
    '111100': 7.4,
    '111101': 5.9,
    '111110': 5.7,
    '111111': 5.7,
    '111120': 4.7,
    '111121': 2.3,
    '111200': 6.1,
    '111201': 5.2,
    '111210': 5.7,
    '111211': 2.9,
    '111220': 2.4,
    '111221': 1.6,
    '112001': 7.1,
    '112011': 5.9,
    '112021': 3,
    '112101': 5.8,
    '112111': 2.6,
    '112121': 1.5,
    '112201': 2.3,
    '112211': 1.3,
    '112221': 0.6,
    '200000': 9.3,
    '200001': 8.7,
    '200010': 8.6,
    '200011': 7.2,
    '200020': 7.5,
    '200021': 5.8,
    '200100': 8.6,
    '200101': 7.4,
    '200110': 7.4,
    '200111': 6.1,
    '200120': 5.6,
    '200121': 3.4,
    '200200': 7,
    '200201': 5.4,
    '200210': 5.2,
    '200211': 4,
    '200220': 4,
    '200221': 2.2,
    '201000': 8.5,
    '201001': 7.5,
    '201010': 7.4,
    '201011': 5.5,
    '201020': 6.2,
    '201021': 5.1,
    '201100': 7.2,
    '201101': 5.7,
    '201110': 5.5,
    '201111': 4.1,
    '201120': 4.6,
    '201121': 1.9,
    '201200': 5.3,
    '201201': 3.6,
    '201210': 3.4,
    '201211': 1.9,
    '201220': 1.9,
    '201221': 0.8,
    '202001': 6.4,
    '202011': 5.1,
    '202021': 2,
    '202101': 4.7,
    '202111': 2.1,
    '202121': 1.1,
    '202201': 2.4,
    '202211': 0.9,
    '202221': 0.4,
    '210000': 8.8,
    '210001': 7.5,
    '210010': 7.3,
    '210011': 5.3,
    '210020': 6,
    '210021': 5,
    '210100': 7.3,
    '210101': 5.5,
    '210110': 5.9,
    '210111': 4,
    '210120': 4.1,
    '210121': 2,
    '210200': 5.4,
    '210201': 4.3,
    '210210': 4.5,
    '210211': 2.2,
    '210220': 2,
    '210221': 1.1,
    '211000': 7.5,
    '211001': 5.5,
    '211010': 5.8,
    '211011': 4.5,
    '211020': 4,
    '211021': 2.1,
    '211100': 6.1,
    '211101': 5.1,
    '211110': 4.8,
    '211111': 1.8,
    '211120': 2,
    '211121': 0.9,
    '211200': 4.6,
    '211201': 1.8,
    '211210': 1.7,
    '211211': 0.7,
    '211220': 0.8,
    '211221': 0.2,
    '212001': 5.3,
    '212011': 2.4,
    '212021': 1.4,
    '212101': 2.4,
    '212111': 1.2,
    '212121': 0.5,
    '212201': 1,
    '212211': 0.3,
    '212221': 0.1,
  };

  // The following defines the index of each metric's values.
  static METRIC_LEVELS: { [key: string]: { [value: string]: number } } = {
    AV: { N: 0.0, A: 0.1, L: 0.2, P: 0.3 },
    PR: { N: 0.0, L: 0.1, H: 0.2 },
    UI: { N: 0.0, P: 0.1, A: 0.2 },
    AC: { L: 0.0, H: 0.1 },
    AT: { N: 0.0, P: 0.1 },
    VC: { H: 0.0, L: 0.1, N: 0.2 },
    VI: { H: 0.0, L: 0.1, N: 0.2 },
    VA: { H: 0.0, L: 0.1, N: 0.2 },
    SC: { H: 0.1, L: 0.2, N: 0.3 },
    SI: { S: 0.0, H: 0.1, L: 0.2, N: 0.3 },
    SA: { S: 0.0, H: 0.1, L: 0.2, N: 0.3 },
    CR: { H: 0.0, M: 0.1, L: 0.2 },
    IR: { H: 0.0, M: 0.1, L: 0.2 },
    AR: { H: 0.0, M: 0.1, L: 0.2 },
    E: { U: 0.2, P: 0.1, A: 0 },
  };

  static MAX_COMPOSED: { [key: string]: any } = {
    // EQ1
    eq1: {
      0: ['AV:N/PR:N/UI:N/'],
      1: ['AV:A/PR:N/UI:N/', 'AV:N/PR:L/UI:N/', 'AV:N/PR:N/UI:P/'],
      2: ['AV:P/PR:N/UI:N/', 'AV:A/PR:L/UI:P/'],
    },
    // EQ2
    eq2: {
      0: ['AC:L/AT:N/'],
      1: ['AC:H/AT:N/', 'AC:L/AT:P/'],
    },
    // EQ3+EQ6
    eq3: {
      0: {
        0: ['VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/'],
        1: ['VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/', 'VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/'],
      },
      1: {
        0: ['VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/', 'VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/'],
        1: [
          'VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/',
          'VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/',
          'VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/',
          'VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/',
          'VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/',
        ],
      },
      2: { 1: ['VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/'] },
    },
    // EQ4
    eq4: {
      0: ['SC:H/SI:S/SA:S/'],
      1: ['SC:H/SI:H/SA:H/'],
      2: ['SC:L/SI:L/SA:L/'],
    },
    // EQ5
    eq5: {
      0: ['E:A/'],
      1: ['E:P/'],
      2: ['E:U/'],
    },
  };

  // max severity distances in EQs MacroVectors (+1)
  static MAX_SEVERITY: { [key: string]: any } = {
    eq1: {
      0: 1,
      1: 4,
      2: 5,
    },
    eq2: {
      0: 1,
      1: 2,
    },
    eq3eq6: {
      0: { 0: 7, 1: 6 },
      1: { 0: 8, 1: 8 },
      2: { 1: 10 },
    },
    eq4: {
      0: 6,
      1: 5,
      2: 4,
    },
    eq5: {
      0: 1,
      1: 1,
      2: 1,
    },
  };

  vector: Vector;
  score: number;
  severity: string;

  constructor(input: string | Vector = '') {
    if (input instanceof Vector) {
      // If the input is a Vector object, use it directly
      this.vector = input;
    } else if (typeof input === 'string') {
      // If the input is a string, create a new Vector object from the string
      this.vector = new Vector(input);
    } else {
      throw new Error(
        'Invalid input type for CVSSv4.0 constructor. Expected a string or a Vector object'
      );
    }

    // Calculate the score
    this.score = this.calculateScore();

    // Save the severity
    this.severity = this.calculateSeverityRating(this.score);
  }

  calculateSeverityRating(score: number): string {
    if (score === 0.0) {
      return 'None';
    } else if (score >= 0.1 && score <= 3.9) {
      return 'Low';
    } else if (score >= 4.0 && score <= 6.9) {
      return 'Medium';
    } else if (score >= 7.0 && score <= 8.9) {
      return 'High';
    } else if (score >= 9.0 && score <= 10.0) {
      return 'Critical';
    }
    return 'Unknown'; // In case of an unexpected score value
  }

  calculateSeverityDistances(maxVector: string): { [key: string]: number } {
    const distances: { [key: string]: number } = {};
    for (const metric in CVSS40.METRIC_LEVELS) {
      const effectiveMetricValue = this.vector.getEffectiveMetricValue(metric);
      const extractedMetricValue = this.extractValueMetric(metric, maxVector);
      distances[metric] =
        CVSS40.METRIC_LEVELS[metric][effectiveMetricValue] -
        CVSS40.METRIC_LEVELS[metric][extractedMetricValue];
    }
    return distances;
  }

  calculateScore(): number {
    // Constants
    // When CIA triad is None
    const NO_IMPACT_METRICS = ['VC', 'VI', 'VA', 'SC', 'SI', 'SA'];
    const STEP = 0.1;

    // Exception for no impact on system
    if (NO_IMPACT_METRICS.every((metric) => this.vector.getEffectiveMetricValue(metric) === 'N')) {
      return 0.0;
    }

    // Ensure to retrieve up-to-date equivalent classes and store-it inside a variable
    const equivalentClasses = this.vector.equivalentClasses;

    const value = CVSS40.LOOKUP_TABLE[equivalentClasses];

    // 1. For each of the EQs:
    //   a. The maximal scoring difference is determined as the difference
    //      between the current MacroVector and the lower MacroVector.
    //     i. If there is no lower MacroVector the available distance is
    //        set to NaN and then ignored in the further calculations.

    // EQ values
    const [eq1, eq2, eq3, eq4, eq5, eq6] = equivalentClasses.split('').map(Number);

    // Compute the next lower macro; it may also not exist.
    const eq1_next_lower_macro = `${eq1 + 1}${eq2}${eq3}${eq4}${eq5}${eq6}`;
    const eq2_next_lower_macro = `${eq1}${eq2 + 1}${eq3}${eq4}${eq5}${eq6}`;

    let eq3eq6_next_lower_macro: string | undefined;
    let eq3eq6_next_lower_macro_left: string | undefined;
    let eq3eq6_next_lower_macro_right: string | undefined;

    // eq3 and eq6 are related
    if (eq3 === 1 && eq6 === 1) {
      // 11 --> 21
      eq3eq6_next_lower_macro = `${eq1}${eq2}${eq3 + 1}${eq4}${eq5}${eq6}`;
    } else if (eq3 === 0 && eq6 === 1) {
      // 01 --> 11
      eq3eq6_next_lower_macro = `${eq1}${eq2}${eq3 + 1}${eq4}${eq5}${eq6}`;
    } else if (eq3 === 1 && eq6 === 0) {
      // 10 --> 11
      eq3eq6_next_lower_macro = `${eq1}${eq2}${eq3}${eq4}${eq5}${eq6 + 1}`;
    } else if (eq3 === 0 && eq6 === 0) {
      // 00 --> 01
      // 00 --> 10
      eq3eq6_next_lower_macro_left = `${eq1}${eq2}${eq3}${eq4}${eq5}${eq6 + 1}`;
      eq3eq6_next_lower_macro_right = `${eq1}${eq2}${eq3 + 1}${eq4}${eq5}${eq6}`;
    } else {
      // 21 --> 32 (does not exist)
      eq3eq6_next_lower_macro = `${eq1}${eq2}${eq3 + 1}${eq4}${eq5}${eq6 + 1}`;
    }

    const eq4_next_lower_macro = `${eq1}${eq2}${eq3}${eq4 + 1}${eq5}${eq6}`;
    const eq5_next_lower_macro = `${eq1}${eq2}${eq3}${eq4}${eq5 + 1}${eq6}`;

    // get their score, if the next lower macro score do not exist the result is NaN
    const score_eq1_next_lower_macro = CVSS40.LOOKUP_TABLE[eq1_next_lower_macro];
    const score_eq2_next_lower_macro = CVSS40.LOOKUP_TABLE[eq2_next_lower_macro];

    let score_eq3eq6_next_lower_macro;
    if (eq3 === 0 && eq6 === 0) {
      // multiple path take the one with higher score
      const score_eq3eq6_next_lower_macro_left = CVSS40.LOOKUP_TABLE[eq3eq6_next_lower_macro_left!];
      const score_eq3eq6_next_lower_macro_right =
        CVSS40.LOOKUP_TABLE[eq3eq6_next_lower_macro_right!];

      score_eq3eq6_next_lower_macro = Math.max(
        score_eq3eq6_next_lower_macro_left,
        score_eq3eq6_next_lower_macro_right
      );
    } else {
      score_eq3eq6_next_lower_macro = CVSS40.LOOKUP_TABLE[eq3eq6_next_lower_macro!];
    }

    const score_eq4_next_lower_macro = CVSS40.LOOKUP_TABLE[eq4_next_lower_macro];
    const score_eq5_next_lower_macro = CVSS40.LOOKUP_TABLE[eq5_next_lower_macro];

    //   b. The severity distance of the to-be scored vector from a
    //      highest severity vector in the same MacroVector is determined.
    const eqMaxes = [
      this.getMaxSeverityVectorsForEQ(equivalentClasses, 1),
      this.getMaxSeverityVectorsForEQ(equivalentClasses, 2),
      this.getMaxSeverityVectorsForEQ(equivalentClasses, 3)[eq6],
      this.getMaxSeverityVectorsForEQ(equivalentClasses, 4),
      this.getMaxSeverityVectorsForEQ(equivalentClasses, 5),
    ];

    // Compose maximum vectors
    const maxVectors = [];
    for (const eq1Max of eqMaxes[0]) {
      for (const eq2Max of eqMaxes[1]) {
        for (const eq3Max of eqMaxes[2]) {
          for (const eq4Max of eqMaxes[3]) {
            for (const eq5Max of eqMaxes[4]) {
              maxVectors.push(eq1Max + eq2Max + eq3Max + eq4Max + eq5Max);
            }
          }
        }
      }
    }

    // Find the max vector to use i.e. one in the combination of all the highest
    // that is greater or equal (severity distance) than the to-be scored vector.
    let distances: { [key: string]: number } = {};
    for (const vector of maxVectors) {
      distances = this.calculateSeverityDistances(vector);
      if (Object.values(distances).every((distance) => distance >= 0)) {
        break;
      }
    }

    // Calculate the current severity distances
    const current_severity_distance_eq1 = distances['AV'] + distances['PR'] + distances['UI'];
    const current_severity_distance_eq2 = distances['AC'] + distances['AT'];
    const current_severity_distance_eq3eq6 =
      distances['VC'] +
      distances['VI'] +
      distances['VA'] +
      distances['CR'] +
      distances['IR'] +
      distances['AR'];
    const current_severity_distance_eq4 = distances['SC'] + distances['SI'] + distances['SA'];
    // const current_severity_distance_eq5 = 0; // EQ5 is always 0 in this context

    // if the next lower macro score do not exist the result is Nan
    // Rename to maximal scoring difference (aka MSD)
    const available_distance_eq1 = value - score_eq1_next_lower_macro;
    const available_distance_eq2 = value - score_eq2_next_lower_macro;
    const available_distance_eq3eq6 = value - score_eq3eq6_next_lower_macro;
    const available_distance_eq4 = value - score_eq4_next_lower_macro;
    const available_distance_eq5 = value - score_eq5_next_lower_macro;

    let percent_to_next_eq1_severity = 0;
    let percent_to_next_eq2_severity = 0;
    let percent_to_next_eq3eq6_severity = 0;
    let percent_to_next_eq4_severity = 0;
    let percent_to_next_eq5_severity = 0;

    // some of them do not exist, we will find them by retrieving the score. If score null then do not exist
    let n_existing_lower = 0;

    let normalized_severity_eq1 = 0;
    let normalized_severity_eq2 = 0;
    let normalized_severity_eq3eq6 = 0;
    let normalized_severity_eq4 = 0;
    let normalized_severity_eq5 = 0;

    // multiply by step because distance is pure
    const maxSeverity_eq1 = CVSS40.MAX_SEVERITY['eq1'][eq1] * STEP;
    const maxSeverity_eq2 = CVSS40.MAX_SEVERITY['eq2'][eq2] * STEP;
    const maxSeverity_eq3eq6 = CVSS40.MAX_SEVERITY['eq3eq6'][eq3][eq6] * STEP;
    const maxSeverity_eq4 = CVSS40.MAX_SEVERITY['eq4'][eq4] * STEP;

    //   c. The proportion of the distance is determined by dividing
    //      the severity distance of the to-be-scored vector by the depth
    //      of the MacroVector.
    //   d. The maximal scoring difference is multiplied by the proportion of
    //      distance.
    if (!isNaN(available_distance_eq1)) {
      n_existing_lower = n_existing_lower + 1;
      percent_to_next_eq1_severity = current_severity_distance_eq1 / maxSeverity_eq1;
      normalized_severity_eq1 = available_distance_eq1 * percent_to_next_eq1_severity;
    }

    if (!isNaN(available_distance_eq2)) {
      n_existing_lower = n_existing_lower + 1;
      percent_to_next_eq2_severity = current_severity_distance_eq2 / maxSeverity_eq2;
      normalized_severity_eq2 = available_distance_eq2 * percent_to_next_eq2_severity;
    }

    if (!isNaN(available_distance_eq3eq6)) {
      n_existing_lower = n_existing_lower + 1;
      percent_to_next_eq3eq6_severity = current_severity_distance_eq3eq6 / maxSeverity_eq3eq6;
      normalized_severity_eq3eq6 = available_distance_eq3eq6 * percent_to_next_eq3eq6_severity;
    }

    if (!isNaN(available_distance_eq4)) {
      n_existing_lower = n_existing_lower + 1;
      percent_to_next_eq4_severity = current_severity_distance_eq4 / maxSeverity_eq4;
      normalized_severity_eq4 = available_distance_eq4 * percent_to_next_eq4_severity;
    }

    if (!isNaN(available_distance_eq5)) {
      // for eq5 is always 0 the percentage
      n_existing_lower = n_existing_lower + 1;
      percent_to_next_eq5_severity = 0;
      normalized_severity_eq5 = available_distance_eq5 * percent_to_next_eq5_severity;
    }

    // 2. The mean of the above computed proportional distances is computed.
    let meanDistance;
    if (n_existing_lower === 0) {
      meanDistance = 0;
    } else {
      // sometimes we need to go up but there is nothing there, or down but there is nothing there so it's a change of 0.
      meanDistance =
        (normalized_severity_eq1 +
          normalized_severity_eq2 +
          normalized_severity_eq3eq6 +
          normalized_severity_eq4 +
          normalized_severity_eq5) /
        n_existing_lower;
    }

    // 3. The score of the vector is the score of the MacroVector
    //    (i.e. the score of the highest severity vector) minus the mean
    //    distance so computed. This score is rounded to one decimal place.
    return roundToDecimalPlaces(Math.max(0, Math.min(10, value - meanDistance)));
  }

  getMaxSeverityVectorsForEQ(macroVector: string, eqNumber: number): any {
    return CVSS40.MAX_COMPOSED['eq' + eqNumber][macroVector[eqNumber - 1]];
  }

  extractValueMetric(metric: string, str: string): string {
    const metricIndex = str.indexOf(metric) + metric.length + 1;
    const extracted = str.slice(metricIndex);
    return extracted.indexOf('/') > 0 ? extracted.substring(0, extracted.indexOf('/')) : extracted;
  }
}
