import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './CVSSQuestionnaire.css';
import { CVSSVector } from '../types/cvss';
import { cvssMetrics, metricDescriptions } from '../data/cvssMetrics';

interface Question {
  id: string;
  text: string;
  metric: string;
  value: string;
}

interface MetricQuestions {
  [metricKey: string]: Question[];
}

// Default questions for each metric
const createDefaultQuestions = (): MetricQuestions => {
  const questions: MetricQuestions = {};
  
  // Base Score Metrics
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
  
  // Temporal Score Metrics
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
  
  // Environmental Score Metrics
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

// Load custom questions from localStorage
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

// Save custom questions to localStorage
const saveCustomQuestions = (questions: MetricQuestions) => {
  localStorage.setItem('cvssCustomQuestions', JSON.stringify(questions));
};

export const CVSSQuestionnaire: React.FC = () => {
  const navigate = useNavigate();
  const [customQuestions, setCustomQuestions] = useState<MetricQuestions>(loadCustomQuestions());
  const [selectedValues, setSelectedValues] = useState<CVSSVector>({});
  const [isEditMode, setIsEditMode] = useState(false);
  const [editingQuestion, setEditingQuestion] = useState<{metric: string, questionIndex: number, text: string} | null>(null);

  const handleQuestionSelect = (metric: string, value: string) => {
    setSelectedValues(prev => ({ ...prev, [metric]: value }));
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
      setSelectedValues({});
    }
  };

  const handleViewResults = () => {
    navigate('/calculator', { state: { vector: selectedValues } });
  };

  const getSelectedQuestionForMetric = (metric: string): Question | null => {
    const value = selectedValues[metric as keyof CVSSVector];
    if (!value || !customQuestions[metric]) return null;
    return customQuestions[metric].find(q => q.value === value) || null;
  };

  const allRequiredMetricsSelected = (): boolean => {
    const requiredMetrics = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
    return requiredMetrics.every(metric => selectedValues[metric as keyof CVSSVector]);
  };

  return (
    <div className="questionnaire-container">
      <div className="header-section">
        <h1>Medical Device CVSS Assessment</h1>
        <p>Select the option that best describes your vulnerability scenario</p>
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
                            checked={selectedValues[metricKey as keyof CVSSVector] === question.value}
                            onChange={() => handleQuestionSelect(metricKey, question.value)}
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

      <div className="action-buttons">
        <button 
          onClick={handleViewResults}
          disabled={!allRequiredMetricsSelected() || isEditMode}
          className="view-results-button"
        >
          View CVSS Results
        </button>
        {!allRequiredMetricsSelected() && !isEditMode && (
          <p className="completion-hint">
            Please select options for all Base Score metrics (AV, AC, PR, UI, S, C, I, A) to continue
          </p>
        )}
      </div>
    </div>
  );
};