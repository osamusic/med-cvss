import React, { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { CVSSVector, CVSSScore, CVSSV4Vector, CVSSVersion } from '../types/cvss';
import { cvssMetrics, metricDescriptions } from '../data/cvssMetrics';
import { cvssV4Metrics, cvssV4MetricDescriptions } from '../data/cvssV4Metrics';
import {
  calculateUniversalCVSSScore,
  generateUniversalVectorString,
} from '../utils/cvssCalculator';
import { MitreCVSSRubric } from './MitreCVSSRubric';
import { medicalDeviceGuidance } from '../data/medicalDeviceGuidance';
import './IntegratedCVSSCalculator.css';

type ViewMode = 'calculator' | 'rubric';

const IntegratedCVSSCalculator: React.FC = () => {
  const location = useLocation();
  const prefilledMetrics = (location.state as any)?.prefilledMetrics as CVSSVector | undefined;

  const [viewMode, setViewMode] = useState<ViewMode>('calculator');
  const [version, setVersion] = useState<CVSSVersion>('3.1');
  const [vector, setVector] = useState<CVSSVector | CVSSV4Vector>(prefilledMetrics || {});
  const [score, setScore] = useState<CVSSScore>({
    baseScore: 0,
    temporalScore: 0,
    overallScore: 0,
    severity: 'None',
  });
  const [vectorString, setVectorString] = useState<string>('CVSS:3.1');
  const [collapsedMetrics, setCollapsedMetrics] = useState<Set<string>>(
    new Set(Object.keys(version === '3.1' ? metricDescriptions : cvssV4MetricDescriptions))
  );
  const [collapsedIndividualMetrics, setCollapsedIndividualMetrics] = useState<Set<string>>(
    new Set()
  );

  useEffect(() => {
    const calculatedScore = calculateUniversalCVSSScore(vector, version);
    setScore(calculatedScore);
    setVectorString(generateUniversalVectorString(vector, version));
  }, [vector, version]);

  useEffect(() => {
    // Reset vector and update collapsed metrics when version changes
    setVector({});
    setCollapsedMetrics(
      new Set(Object.keys(version === '3.1' ? metricDescriptions : cvssV4MetricDescriptions))
    );

    // Switch to calculator mode if we're in rubric mode and switching to v4.0
    if (version === '4.0' && viewMode === 'rubric') {
      setViewMode('calculator');
    }
  }, [version, viewMode]);

  // Handle prefilled metrics from navigation
  useEffect(() => {
    if (prefilledMetrics) {
      setVector(prefilledMetrics);
      // Expand base metrics section if metrics are prefilled
      setCollapsedMetrics((prev) => {
        const newSet = new Set(prev);
        newSet.delete('Base Score Metrics');
        return newSet;
      });
    }
  }, [prefilledMetrics]);

  const handleMetricChange = (metric: string, value: string) => {
    setVector((prev) => ({
      ...prev,
      [metric]: value,
    }));
  };

  const resetCalculator = () => {
    setVector({});
    // Clear both old and new rubric answers
    localStorage.removeItem('cvssRubricAnswers');
    localStorage.removeItem('mitreCvssRubricAnswers');
  };

  const getSeverityClass = (severity: string): string => {
    switch (severity) {
      case 'Critical':
        return 'severity-critical';
      case 'High':
        return 'severity-high';
      case 'Medium':
        return 'severity-medium';
      case 'Low':
        return 'severity-low';
      default:
        return 'severity-none';
    }
  };

  const allRequiredMetricsSelected = (): boolean => {
    if (version === '3.1') {
      const requiredMetrics = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
      return requiredMetrics.every((metric) => (vector as CVSSVector)[metric as keyof CVSSVector]);
    } else {
      // CVSS v4.0 base metrics
      const requiredMetrics = ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA'];
      return requiredMetrics.every(
        (metric) => (vector as CVSSV4Vector)[metric as keyof CVSSV4Vector]
      );
    }
  };

  // Quick selection presets for common medical device scenarios
  const getQuickPresets = () => {
    if (version === '3.1') {
      return [
        {
          name: 'Critical Network Attack',
          description: 'Remote network exploitation with high impact',
          vector: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'C', C: 'H', I: 'H', A: 'H' },
        },
        {
          name: 'Local Admin Compromise',
          description: 'Local access with admin privileges needed',
          vector: { AV: 'L', AC: 'L', PR: 'H', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
        },
        {
          name: 'Adjacent Network Attack',
          description: 'WiFi/Bluetooth proximity-based attack',
          vector: { AV: 'A', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'L', A: 'L' },
        },
        {
          name: 'Physical Access Attack',
          description: 'Physical device access required',
          vector: { AV: 'P', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' },
        },
        {
          name: 'Social Engineering',
          description: 'User interaction required attack',
          vector: { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'L', A: 'N' },
        },
        {
          name: 'USB Memory Attack',
          description: 'Malicious USB device with physical access',
          vector: { AV: 'L', AC: 'L', PR: 'N', UI: 'R', S: 'C', C: 'H', I: 'H', A: 'L' },
        },
      ];
    } else {
      // CVSS v4.0 presets
      return [
        {
          name: 'Critical Network Attack',
          description: 'Remote network exploitation with high impact',
          vector: {
            AV: 'N',
            AC: 'L',
            AT: 'N',
            PR: 'N',
            UI: 'N',
            VC: 'H',
            VI: 'H',
            VA: 'H',
            SC: 'H',
            SI: 'H',
            SA: 'H',
          },
        },
        {
          name: 'Local Admin Compromise',
          description: 'Local access with admin privileges needed',
          vector: {
            AV: 'L',
            AC: 'L',
            AT: 'N',
            PR: 'H',
            UI: 'N',
            VC: 'H',
            VI: 'H',
            VA: 'H',
            SC: 'N',
            SI: 'N',
            SA: 'N',
          },
        },
        {
          name: 'Adjacent Network Attack',
          description: 'WiFi/Bluetooth proximity-based attack',
          vector: {
            AV: 'A',
            AC: 'L',
            AT: 'N',
            PR: 'N',
            UI: 'N',
            VC: 'H',
            VI: 'L',
            VA: 'L',
            SC: 'N',
            SI: 'N',
            SA: 'N',
          },
        },
        {
          name: 'Physical Access Attack',
          description: 'Physical device access required',
          vector: {
            AV: 'P',
            AC: 'L',
            AT: 'N',
            PR: 'N',
            UI: 'N',
            VC: 'H',
            VI: 'H',
            VA: 'N',
            SC: 'N',
            SI: 'N',
            SA: 'N',
          },
        },
        {
          name: 'Social Engineering',
          description: 'User interaction required attack',
          vector: {
            AV: 'N',
            AC: 'L',
            AT: 'N',
            PR: 'N',
            UI: 'A',
            VC: 'L',
            VI: 'L',
            VA: 'N',
            SC: 'N',
            SI: 'N',
            SA: 'N',
          },
        },
        {
          name: 'USB Memory Attack',
          description: 'Malicious USB device with physical access',
          vector: {
            AV: 'L',
            AC: 'L',
            AT: 'N',
            PR: 'N',
            UI: 'P',
            VC: 'H',
            VI: 'H',
            VA: 'L',
            SC: 'L',
            SI: 'L',
            SA: 'N',
          },
        },
      ];
    }
  };

  const applyQuickPreset = (preset: ReturnType<typeof getQuickPresets>[0]) => {
    setVector(preset.vector);
  };

  const clearAllMetrics = () => {
    setVector({});
  };

  const toggleMetricDescription = (metricKey: string) => {
    setCollapsedMetrics((prev) => {
      const newSet = new Set(prev);
      if (newSet.has(metricKey)) {
        newSet.delete(metricKey);
      } else {
        newSet.add(metricKey);
      }
      return newSet;
    });
  };

  const toggleIndividualMetric = (metricKey: string) => {
    setCollapsedIndividualMetrics((prev) => {
      const newSet = new Set(prev);
      if (newSet.has(metricKey)) {
        newSet.delete(metricKey);
      } else {
        newSet.add(metricKey);
      }
      return newSet;
    });
  };

  const collapseAllMetrics = () => {
    const allMetricKeys = getCurrentMetrics().flatMap((group) => Object.keys(group.metrics));
    setCollapsedIndividualMetrics(new Set(allMetricKeys));
  };

  const expandAllMetrics = () => {
    setCollapsedIndividualMetrics(new Set());
  };

  const getCurrentMetrics = () => (version === '3.1' ? cvssMetrics : cvssV4Metrics);
  const getCurrentDescriptions = () =>
    version === '3.1' ? metricDescriptions : cvssV4MetricDescriptions;

  const renderCalculator = () => (
    <div className='calculator-content'>
      <div className='metrics-section'>
        {getCurrentMetrics().map((group) => {
          // For CVSS v4.0, identify Supplemental Metrics group
          const isSupplementalGroup = group.name === 'Supplemental Metrics';

          return (
            <div key={group.name} className='metric-group'>
              <div className='metric-group-header'>
                <h2>{group.name}</h2>
                {isSupplementalGroup && (
                  <div className='supplemental-note'>
                    <p>
                      <em>
                        Optional metrics for additional context. These do not affect the CVSS score
                        but provide valuable supplemental information for vulnerability assessment.
                      </em>
                    </p>
                  </div>
                )}
              </div>
              {Object.entries(group.metrics).map(([metricKey, options]) => {
                const guidance = medicalDeviceGuidance[metricKey];
                const descriptions = getCurrentDescriptions();
                const isMetricCollapsed = collapsedIndividualMetrics.has(metricKey);
                const selectedValue = (vector as any)[metricKey];
                const selectedOption = options.find((option) => option.value === selectedValue);

                return (
                  <div
                    key={metricKey}
                    className={`metric-with-guidance ${isMetricCollapsed ? 'metric-collapsed' : ''}`}
                  >
                    <div className='metric-header'>
                      <h3>
                        {descriptions[metricKey]} ({metricKey})
                        {isSupplementalGroup && (
                          <span className='supplemental-badge'>Supplemental</span>
                        )}
                      </h3>
                      <div className='metric-controls'>
                        <button
                          className='toggle-metric-btn'
                          onClick={() => toggleIndividualMetric(metricKey)}
                          aria-label={isMetricCollapsed ? 'Expand metric' : 'Collapse metric'}
                          title={isMetricCollapsed ? 'Expand metric' : 'Collapse metric'}
                        >
                          {isMetricCollapsed ? '▶' : '▼'}
                        </button>
                        {!isMetricCollapsed && (
                          <div className='toggle-guidance-container'>
                            <span className='guidance-label'>Description</span>
                            <button
                              className='toggle-description-btn'
                              onClick={() => toggleMetricDescription(metricKey)}
                              aria-label={
                                collapsedMetrics.has(metricKey)
                                  ? 'Expand description'
                                  : 'Collapse description'
                              }
                            >
                              {collapsedMetrics.has(metricKey) ? '▼' : '▲'}
                            </button>
                          </div>
                        )}
                      </div>
                    </div>

                    {isMetricCollapsed && selectedOption && (
                      <div className='metric-collapsed-display'>
                        <span className='selected-value-display'>
                          <span className='selected-option-value'>{selectedOption.value}</span>
                          <span className='selected-option-label'>{selectedOption.label}</span>
                        </span>
                      </div>
                    )}

                    {!isMetricCollapsed && (
                      <>
                        {guidance && !collapsedMetrics.has(metricKey) && (
                          <div className='metric-guidance'>
                            <div className='guidance-section'>
                              <h4>Description</h4>
                              <p>{guidance.general.description}</p>
                            </div>

                            <div className='guidance-section'>
                              <h4>Medical Device Context</h4>
                              <p>{guidance.general.medicalDeviceContext}</p>
                            </div>

                            <div className='guidance-section'>
                              <h4>Examples</h4>
                              <ul>
                                {guidance.general.examples.map((example, index) => (
                                  <li key={index}>{example}</li>
                                ))}
                              </ul>
                            </div>
                          </div>
                        )}

                        <div className='metric-options'>
                          {options.map((option) => {
                            const optionGuidance = guidance?.options.find(
                              (og) => og.value === option.value
                            );
                            return (
                              <div key={option.value} className='metric-option-wrapper'>
                                <button
                                  className={`metric-option ${(vector as any)[metricKey] === option.value ? 'selected' : ''} ${isSupplementalGroup ? 'supplemental-option' : ''}`}
                                  onClick={() => handleMetricChange(metricKey, option.value)}
                                >
                                  <span className='option-value'>{option.value}</span>
                                  <span className='option-label'>{option.label}</span>
                                </button>

                                {optionGuidance && (
                                  <div className='option-guidance'>
                                    <div className='option-guidance-text'>
                                      <strong>Guidance:</strong> {optionGuidance.guidance}
                                    </div>
                                    <div className='option-medical-example'>
                                      <strong>Medical Example:</strong>{' '}
                                      {optionGuidance.medicalExample}
                                    </div>
                                  </div>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      </>
                    )}
                  </div>
                );
              })}
            </div>
          );
        })}
      </div>
    </div>
  );

  return (
    <div className='cvss-calculator'>
      <header className='calculator-header'>
        <h1>Medical CVSS Calculator</h1>
        <p>CVSS v{version} - Common Vulnerability Scoring System</p>

        <div className='version-selector'>
          <label htmlFor='cvss-version'>CVSS Version:</label>
          <select
            id='cvss-version'
            value={version}
            onChange={(e) => setVersion(e.target.value as CVSSVersion)}
            className='version-select'
          >
            <option value='3.1'>CVSS v3.1</option>
            <option value='4.0'>CVSS v4.0</option>
          </select>
        </div>

        <div className='view-tabs'>
          <button
            className={`tab-button ${viewMode === 'calculator' ? 'active' : ''}`}
            onClick={() => setViewMode('calculator')}
          >
            Technical Calculator with Guide
          </button>
          <button
            className={`tab-button ${viewMode === 'rubric' ? 'active' : ''} ${version === '4.0' ? 'disabled' : ''}`}
            onClick={() => version === '3.1' && setViewMode('rubric')}
            disabled={version === '4.0'}
          >
            MITRE Rubric {version === '4.0' ? '(v3.1 only)' : ''}
          </button>
        </div>
      </header>

      {viewMode === 'calculator' && (
        <div className='quick-selection-section'>
          <div className='quick-selection-header'>
            <h2>Quick Metrics Selection</h2>
            <p>Choose a common scenario to quickly populate CVSS metrics</p>
          </div>

          <div className='quick-presets'>
            {getQuickPresets().map((preset, index) => (
              <button
                key={index}
                className='preset-button'
                onClick={() => applyQuickPreset(preset)}
                title={preset.description}
              >
                <div className='preset-name'>{preset.name}</div>
                <div className='preset-description'>{preset.description}</div>
              </button>
            ))}
          </div>

          <div className='quick-actions'>
            <button className='clear-all-button' onClick={clearAllMetrics}>
              Clear All Metrics
            </button>
            <button className='collapse-all-button' onClick={collapseAllMetrics}>
              Collapse All Metrics
            </button>
            <button className='expand-all-button' onClick={expandAllMetrics}>
              Expand All Metrics
            </button>
            <div className='metrics-status'>
              {allRequiredMetricsSelected() ? (
                <span className='status-complete'>✓ All base metrics selected</span>
              ) : (
                <span className='status-incomplete'>
                  {Object.keys(vector).length}/{version === '3.1' ? '8' : '11'} base metrics
                  selected
                </span>
              )}
            </div>
          </div>
        </div>
      )}

      <div className='main-content'>
        <div className='content-area'>
          {viewMode === 'calculator' && renderCalculator()}
          {viewMode === 'rubric' && (
            <MitreCVSSRubric onVectorChange={setVector} initialVector={vector} />
          )}
        </div>

        <div className='results-section'>
          <div className='score-display'>
            <h2>CVSS Scores</h2>
            <div className='scores'>
              <div className='score-item'>
                <span className='score-label'>Base Score:</span>
                <span className='score-value'>{score.baseScore.toFixed(1)}</span>
              </div>
              {version === '3.1' && score.temporalScore != null && score.temporalScore > 0 && (
                <div className='score-item'>
                  <span className='score-label'>Temporal Score:</span>
                  <span className='score-value'>{score.temporalScore.toFixed(1)}</span>
                </div>
              )}
              {version === '4.0' && score.threatScore != null && score.threatScore > 0 && (
                <div className='score-item'>
                  <span className='score-label'>Threat Score:</span>
                  <span className='score-value'>{score.threatScore.toFixed(1)}</span>
                </div>
              )}
              {version === '4.0' &&
                score.environmentalScore != null &&
                score.environmentalScore > 0 && (
                  <div className='score-item'>
                    <span className='score-label'>Environmental Score:</span>
                    <span className='score-value'>{score.environmentalScore.toFixed(1)}</span>
                  </div>
                )}
              <div className='score-item overall'>
                <span className='score-label'>Overall Score:</span>
                <span className='score-value'>{score.overallScore.toFixed(1)}</span>
              </div>
            </div>
            <div className={`severity ${getSeverityClass(score.severity)}`}>
              <span className='severity-label'>Severity:</span>
              <span className='severity-value'>{score.severity}</span>
            </div>
          </div>

          <div className='vector-display'>
            <h3>Vector String</h3>
            <div className='vector-string'>{vectorString}</div>
          </div>

          <div className='score-interpretation'>
            <h3>Score Interpretation</h3>
            <div className='interpretation-ranges'>
              <div className='range none'>0.0: None</div>
              <div className='range low'>0.1-3.9: Low</div>
              <div className='range medium'>4.0-6.9: Medium</div>
              <div className='range high'>7.0-8.9: High</div>
              <div className='range critical'>9.0-10.0: Critical</div>
            </div>
          </div>

          {viewMode === 'calculator' && !allRequiredMetricsSelected() && (
            <div className='completion-hint'>
              {version === '3.1'
                ? 'Please select options for all Base Score metrics (AV, AC, PR, UI, S, C, I, A) to see results'
                : 'Please select options for all Base Score metrics (AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA) to see results'}
            </div>
          )}

          <button className='reset-button' onClick={resetCalculator}>
            Reset Calculator
          </button>
        </div>
      </div>
    </div>
  );
};

export default IntegratedCVSSCalculator;
