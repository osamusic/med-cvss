import React, { useState, useEffect } from 'react';
import { CVSSVector, CVSSScore } from '../types/cvss';
import { cvssMetrics, metricDescriptions } from '../data/cvssMetrics';
import { calculateCVSSScore, generateVectorString } from '../utils/cvssCalculator';
import { MitreCVSSRubric } from './MitreCVSSRubric';
import './IntegratedCVSSCalculator.css';

interface Question {
  id: string;
  text: string;
  metric: string;
  value: string;
}

interface MetricQuestions {
  [metricKey: string]: Question[];
}

const createDefaultQuestions = (): MetricQuestions => {
  const questions: MetricQuestions = {};
  
  questions.AV = [
    { id: 'av1', text: 'Can be exploited remotely over a network', metric: 'AV', value: 'N' },
    { id: 'av2', text: 'Requires adjacent network access (WiFi, Bluetooth)', metric: 'AV', value: 'A' },
    { id: 'av3', text: 'Requires local access to the system', metric: 'AV', value: 'L' },
    { id: 'av4', text: 'Requires physical access to the device', metric: 'AV', value: 'P' }
  ];
  
  questions.AC = [
    { id: 'ac1', text: 'Attack is simple with minimal preparation needed', metric: 'AC', value: 'L' },
    { id: 'ac2', text: 'Attack requires significant preparation or special conditions', metric: 'AC', value: 'H' }
  ];
  
  questions.PR = [
    { id: 'pr1', text: 'No authentication or privileges required', metric: 'PR', value: 'N' },
    { id: 'pr2', text: 'Requires basic user privileges', metric: 'PR', value: 'L' },
    { id: 'pr3', text: 'Requires administrative or high-level privileges', metric: 'PR', value: 'H' }
  ];
  
  questions.UI = [
    { id: 'ui1', text: 'No user interaction required for exploitation', metric: 'UI', value: 'N' },
    { id: 'ui2', text: 'Requires user interaction (clicking, opening files)', metric: 'UI', value: 'R' }
  ];
  
  questions.S = [
    { id: 's1', text: 'Impact limited to the vulnerable component', metric: 'S', value: 'U' },
    { id: 's2', text: 'Impact extends beyond the vulnerable component', metric: 'S', value: 'C' }
  ];
  
  questions.C = [
    { id: 'c1', text: 'Patient personal information can be accessed', metric: 'C', value: 'H' },
    { id: 'c2', text: 'Limited diagnostic data can be read', metric: 'C', value: 'L' },
    { id: 'c3', text: 'No confidential information is disclosed', metric: 'C', value: 'N' }
  ];
  
  questions.I = [
    { id: 'i1', text: 'Medical data or device settings can be modified', metric: 'I', value: 'H' },
    { id: 'i2', text: 'Limited system information can be modified', metric: 'I', value: 'L' },
    { id: 'i3', text: 'No data can be modified', metric: 'I', value: 'N' }
  ];
  
  questions.A = [
    { id: 'a1', text: 'Medical device services can be completely stopped', metric: 'A', value: 'H' },
    { id: 'a2', text: 'Device performance is degraded but functional', metric: 'A', value: 'L' },
    { id: 'a3', text: 'No impact on device availability', metric: 'A', value: 'N' }
  ];
  
  questions.E = [
    { id: 'e1', text: 'Exploit code is widely available and automated', metric: 'E', value: 'H' },
    { id: 'e2', text: 'Functional exploit code exists', metric: 'E', value: 'F' },
    { id: 'e3', text: 'Proof-of-concept code exists', metric: 'E', value: 'P' },
    { id: 'e4', text: 'No known exploits exist', metric: 'E', value: 'U' },
    { id: 'e5', text: 'Not evaluated', metric: 'E', value: 'X' }
  ];
  
  questions.RL = [
    { id: 'rl1', text: 'No official fix available', metric: 'RL', value: 'U' },
    { id: 'rl2', text: 'Workaround available', metric: 'RL', value: 'W' },
    { id: 'rl3', text: 'Temporary fix available', metric: 'RL', value: 'T' },
    { id: 'rl4', text: 'Official fix available', metric: 'RL', value: 'O' },
    { id: 'rl5', text: 'Not evaluated', metric: 'RL', value: 'X' }
  ];
  
  questions.RC = [
    { id: 'rc1', text: 'Vulnerability confirmed by vendor', metric: 'RC', value: 'C' },
    { id: 'rc2', text: 'Vulnerability details are reasonable', metric: 'RC', value: 'R' },
    { id: 'rc3', text: 'Vulnerability details are unknown/unconfirmed', metric: 'RC', value: 'U' },
    { id: 'rc4', text: 'Not evaluated', metric: 'RC', value: 'X' }
  ];
  
  questions.CR = [
    { id: 'cr1', text: 'Confidentiality is critical for this environment', metric: 'CR', value: 'H' },
    { id: 'cr2', text: 'Confidentiality is important for this environment', metric: 'CR', value: 'M' },
    { id: 'cr3', text: 'Confidentiality is not important for this environment', metric: 'CR', value: 'L' },
    { id: 'cr4', text: 'Not evaluated', metric: 'CR', value: 'X' }
  ];
  
  questions.IR = [
    { id: 'ir1', text: 'Integrity is critical for this environment', metric: 'IR', value: 'H' },
    { id: 'ir2', text: 'Integrity is important for this environment', metric: 'IR', value: 'M' },
    { id: 'ir3', text: 'Integrity is not important for this environment', metric: 'IR', value: 'L' },
    { id: 'ir4', text: 'Not evaluated', metric: 'IR', value: 'X' }
  ];
  
  questions.AR = [
    { id: 'ar1', text: 'Availability is critical for this environment', metric: 'AR', value: 'H' },
    { id: 'ar2', text: 'Availability is important for this environment', metric: 'AR', value: 'M' },
    { id: 'ar3', text: 'Availability is not important for this environment', metric: 'AR', value: 'L' },
    { id: 'ar4', text: 'Not evaluated', metric: 'AR', value: 'X' }
  ];
  
  return questions;
};

const loadCustomQuestions = (): MetricQuestions => {
  const saved = localStorage.getItem('cvssCustomQuestions');
  if (saved) {
    try {
      return JSON.parse(saved);
    } catch (e) {
      console.error('Failed to load custom questions:', e);
    }
  }
  return createDefaultQuestions();
};

const saveCustomQuestions = (questions: MetricQuestions) => {
  localStorage.setItem('cvssCustomQuestions', JSON.stringify(questions));
};

type ViewMode = 'questionnaire' | 'calculator' | 'rubric';

const IntegratedCVSSCalculator: React.FC = () => {
  const [viewMode, setViewMode] = useState<ViewMode>('questionnaire');
  const [vector, setVector] = useState<CVSSVector>({});
  const [score, setScore] = useState<CVSSScore>({
    baseScore: 0,
    temporalScore: 0,
    environmentalScore: 0,
    overallScore: 0,
    severity: 'None'
  });
  const [vectorString, setVectorString] = useState<string>('CVSS:3.1');
  const [customQuestions, setCustomQuestions] = useState<MetricQuestions>(loadCustomQuestions());
  const [isEditMode, setIsEditMode] = useState(false);
  const [editingQuestion, setEditingQuestion] = useState<{metric: string, questionIndex: number, text: string} | null>(null);

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
    // Clear both old and new rubric answers
    localStorage.removeItem('cvssRubricAnswers');
    localStorage.removeItem('mitreCvssRubricAnswers');
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

  const handleAddQuestion = (metric: string) => {
    const newQuestions = { ...customQuestions };
    const newId = `${metric.toLowerCase()}${newQuestions[metric].length + 1}`;
    newQuestions[metric].push({
      id: newId,
      text: 'New question',
      metric: metric,
      value: cvssMetrics.find(group => group.metrics[metric])?.metrics[metric][0].value || 'X'
    });
    setCustomQuestions(newQuestions);
    saveCustomQuestions(newQuestions);
  };

  const handleDeleteQuestion = (metric: string, questionIndex: number) => {
    const newQuestions = { ...customQuestions };
    if (newQuestions[metric].length > 1) {
      newQuestions[metric].splice(questionIndex, 1);
      setCustomQuestions(newQuestions);
      saveCustomQuestions(newQuestions);
    }
  };

  const handleEditQuestion = (metric: string, questionIndex: number, newText: string) => {
    const newQuestions = { ...customQuestions };
    newQuestions[metric][questionIndex].text = newText;
    setCustomQuestions(newQuestions);
    saveCustomQuestions(newQuestions);
    setEditingQuestion(null);
  };

  const handleResetQuestions = () => {
    if (window.confirm('Reset to default questions? Your customized questions will be lost.')) {
      const defaultQuestions = createDefaultQuestions();
      setCustomQuestions(defaultQuestions);
      saveCustomQuestions(defaultQuestions);
    }
  };

  const getSelectedQuestionForMetric = (metric: string): Question | null => {
    const value = vector[metric as keyof CVSSVector];
    if (!value || !customQuestions[metric]) return null;
    return customQuestions[metric].find(q => q.value === value) || null;
  };

  const allRequiredMetricsSelected = (): boolean => {
    const requiredMetrics = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
    return requiredMetrics.every(metric => vector[metric as keyof CVSSVector]);
  };

  const renderQuestionnaire = () => (
    <div className="questionnaire-content">
      <div className="control-buttons">
        <button 
          onClick={() => setIsEditMode(!isEditMode)}
          className="edit-mode-button"
        >
          {isEditMode ? 'Exit Edit Mode' : 'Customize Questions'}
        </button>
        {isEditMode && (
          <button 
            onClick={handleResetQuestions}
            className="reset-button"
          >
            Reset to Default
          </button>
        )}
      </div>

      <div className="metrics-grid">
        {cvssMetrics.map((group) => (
          <div key={group.name} className="metric-group">
            <h2>{group.name}</h2>
            {Object.entries(group.metrics).map(([metricKey, options]) => {
              const questions = customQuestions[metricKey] || [];
              const selectedQuestion = getSelectedQuestionForMetric(metricKey);
              
              return (
                <div key={metricKey} className="metric-section">
                  <h3>{metricDescriptions[metricKey]} ({metricKey})</h3>
                  
                  {selectedQuestion && !isEditMode && (
                    <div className="selected-scenario">
                      <strong>Selected:</strong> {selectedQuestion.text}
                    </div>
                  )}
                  
                  <div className="questions-list">
                    {questions.map((question, qIndex) => (
                      <div key={question.id} className="question-item">
                        <label className="question-label">
                          <input
                            type="radio"
                            name={metricKey}
                            value={question.value}
                            checked={vector[metricKey as keyof CVSSVector] === question.value}
                            onChange={() => handleMetricChange(metricKey, question.value)}
                            disabled={isEditMode}
                          />
                          <span className="question-content">
                            {editingQuestion?.metric === metricKey && 
                             editingQuestion?.questionIndex === qIndex ? (
                              <input
                                type="text"
                                value={editingQuestion.text}
                                onChange={(e) => setEditingQuestion({...editingQuestion, text: e.target.value})}
                                onBlur={() => handleEditQuestion(metricKey, qIndex, editingQuestion.text)}
                                onKeyDown={(e) => {
                                  if (e.key === 'Enter') {
                                    handleEditQuestion(metricKey, qIndex, editingQuestion.text);
                                  }
                                }}
                                className="edit-input"
                              />
                            ) : (
                              <span 
                                className={isEditMode ? 'editable-text' : ''}
                                onClick={() => isEditMode && setEditingQuestion({
                                  metric: metricKey,
                                  questionIndex: qIndex,
                                  text: question.text
                                })}
                              >
                                {question.text}
                              </span>
                            )}
                            <span className="option-value">({question.value})</span>
                          </span>
                        </label>
                        {isEditMode && (
                          <button
                            onClick={() => handleDeleteQuestion(metricKey, qIndex)}
                            className="delete-button"
                            disabled={questions.length <= 1}
                          >
                            Delete
                          </button>
                        )}
                      </div>
                    ))}
                    
                    {isEditMode && (
                      <button
                        onClick={() => handleAddQuestion(metricKey)}
                        className="add-question-button"
                      >
                        + Add Question
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        ))}
      </div>
    </div>
  );

  const renderCalculator = () => (
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
    </div>
  );

  return (
    <div className="cvss-calculator">
      <header className="calculator-header">
        <h1>Medical CVSS Calculator</h1>
        <p>CVSS v3.1 - Common Vulnerability Scoring System</p>
        
        <div className="view-tabs">
          <button 
            className={`tab-button ${viewMode === 'questionnaire' ? 'active' : ''}`}
            onClick={() => setViewMode('questionnaire')}
          >
            Guided Assessment
          </button>
          <button 
            className={`tab-button ${viewMode === 'rubric' ? 'active' : ''}`}
            onClick={() => setViewMode('rubric')}
          >
            MITRE Rubric
          </button>
          <button 
            className={`tab-button ${viewMode === 'calculator' ? 'active' : ''}`}
            onClick={() => setViewMode('calculator')}
          >
            Technical Calculator
          </button>
        </div>
      </header>

      <div className="main-content">
        <div className="content-area">
          {viewMode === 'questionnaire' && renderQuestionnaire()}
          {viewMode === 'rubric' && (
            <MitreCVSSRubric 
              onVectorChange={setVector}
              initialVector={vector}
            />
          )}
          {viewMode === 'calculator' && renderCalculator()}
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

          {viewMode === 'questionnaire' && !allRequiredMetricsSelected() && (
            <div className="completion-hint">
              Please select options for all Base Score metrics (AV, AC, PR, UI, S, C, I, A) to see results
            </div>
          )}

          <button className="reset-button" onClick={resetCalculator}>
            Reset Calculator
          </button>
        </div>
      </div>
    </div>
  );
};

export default IntegratedCVSSCalculator;