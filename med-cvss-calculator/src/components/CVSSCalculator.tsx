import React, { useState, useEffect } from 'react';
import { useLocation, Link } from 'react-router-dom';
import { CVSSVector, CVSSScore } from '../types/cvss';
import { cvssMetrics, metricDescriptions } from '../data/cvssMetrics';
import { calculateCVSSScore, generateVectorString } from '../utils/cvssCalculator';
import './CVSSCalculator.css';

const CVSSCalculator: React.FC = () => {
  const location = useLocation();
  const initialVector = location.state?.vector || {};
  
  const [vector, setVector] = useState<CVSSVector>(initialVector);
  const [score, setScore] = useState<CVSSScore>({
    baseScore: 0,
    temporalScore: 0,
    environmentalScore: 0,
    overallScore: 0,
    severity: 'None'
  });
  const [vectorString, setVectorString] = useState<string>('CVSS:3.1');

  useEffect(() => {
    const calculatedScore = calculateCVSSScore(vector);
    setScore(calculatedScore);
    setVectorString(generateVectorString(vector));
  }, [vector]);

  const handleMetricChange = (metric: string, value: string) => {
    setVector(prev => ({
      ...prev,
      [metric]: value
    }));
  };

  const resetCalculator = () => {
    setVector({});
  };

  const getSeverityClass = (severity: string): string => {
    switch (severity) {
      case 'Critical': return 'severity-critical';
      case 'High': return 'severity-high';
      case 'Medium': return 'severity-medium';
      case 'Low': return 'severity-low';
      default: return 'severity-none';
    }
  };

  return (
    <div className="cvss-calculator">
      <header className="calculator-header">
        <h1>Medical CVSS Calculator</h1>
        <p>CVSS v3.1 - Common Vulnerability Scoring System</p>
        <Link to="/questionnaire" className="questionnaire-link">
          ← Back to Questionnaire
        </Link>
      </header>

      <div className="calculator-content">
        <div className="metrics-section">
          {cvssMetrics.map((group) => (
            <div key={group.name} className="metric-group">
              <h2>{group.name}</h2>
              {Object.entries(group.metrics).map(([metricKey, options]) => (
                <div key={metricKey} className="metric">
                  <h3>{metricDescriptions[metricKey]} ({metricKey})</h3>
                  <div className="metric-options">
                    {options.map((option) => (
                      <button
                        key={option.value}
                        className={`metric-option ${vector[metricKey as keyof CVSSVector] === option.value ? 'selected' : ''}`}
                        onClick={() => handleMetricChange(metricKey, option.value)}
                      >
                        <span className="option-value">{option.value}</span>
                        <span className="option-label">{option.label}</span>
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          ))}
        </div>

        <div className="results-section">
          <div className="score-display">
            <h2>CVSS Scores</h2>
            <div className="scores">
              <div className="score-item">
                <span className="score-label">Base Score:</span>
                <span className="score-value">{score.baseScore.toFixed(1)}</span>
              </div>
              {score.temporalScore > 0 && (
                <div className="score-item">
                  <span className="score-label">Temporal Score:</span>
                  <span className="score-value">{score.temporalScore.toFixed(1)}</span>
                </div>
              )}
              {score.environmentalScore > 0 && (
                <div className="score-item">
                  <span className="score-label">Environmental Score:</span>
                  <span className="score-value">{score.environmentalScore.toFixed(1)}</span>
                </div>
              )}
              <div className="score-item overall">
                <span className="score-label">Overall Score:</span>
                <span className="score-value">{score.overallScore.toFixed(1)}</span>
              </div>
            </div>
            <div className={`severity ${getSeverityClass(score.severity)}`}>
              <span className="severity-label">Severity:</span>
              <span className="severity-value">{score.severity}</span>
            </div>
          </div>

          <div className="vector-display">
            <h3>Vector String</h3>
            <div className="vector-string">{vectorString}</div>
          </div>

          <div className="score-interpretation">
            <h3>Score Interpretation</h3>
            <div className="interpretation-ranges">
              <div className="range none">0.0: None</div>
              <div className="range low">0.1-3.9: Low</div>
              <div className="range medium">4.0-6.9: Medium</div>
              <div className="range high">7.0-8.9: High</div>
              <div className="range critical">9.0-10.0: Critical</div>
            </div>
          </div>

          <button className="reset-button" onClick={resetCalculator}>
            Reset Calculator
          </button>
        </div>
      </div>
    </div>
  );
};

export default CVSSCalculator;