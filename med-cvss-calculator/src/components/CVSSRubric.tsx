import React, { useState, useEffect } from 'react';
import { CVSSVector } from '../types/cvss';
import { rubricCategories, calculateRubricVector, RubricAnswers } from '../data/cvssRubric';
import './CVSSRubric.css';

interface CVSSRubricProps {
  onVectorChange: (vector: CVSSVector) => void;
  initialVector?: CVSSVector;
}

// Load rubric answers from localStorage
const loadRubricAnswers = (): RubricAnswers => {
  const saved = localStorage.getItem('cvssRubricAnswers');
  if (saved) {
    try {
      return JSON.parse(saved);
    } catch (e) {
      console.error('Failed to load rubric answers:', e);
    }
  }
  return {};
};

// Save rubric answers to localStorage
const saveRubricAnswers = (answers: RubricAnswers) => {
  localStorage.setItem('cvssRubricAnswers', JSON.stringify(answers));
};

export const CVSSRubric: React.FC<CVSSRubricProps> = ({ onVectorChange }) => {
  const [answers, setAnswers] = useState<RubricAnswers>(loadRubricAnswers());
  const [completedCategories, setCompletedCategories] = useState<Set<string>>(new Set());

  useEffect(() => {
    const vector = calculateRubricVector(answers);
    onVectorChange(vector);
    
    // Update completed categories
    const completed = new Set<string>();
    rubricCategories.forEach(category => {
      const categoryQuestions = category.questions.map(q => q.id);
      const hasAnswers = categoryQuestions.some(qId => answers[qId] && answers[qId] !== 'unknown');
      if (hasAnswers) {
        completed.add(category.name);
      }
    });
    setCompletedCategories(completed);
  }, [answers, onVectorChange]);

  const handleAnswerChange = (questionId: string, value: 'yes' | 'no' | 'unknown') => {
    const newAnswers = {
      ...answers,
      [questionId]: value
    };
    setAnswers(newAnswers);
    saveRubricAnswers(newAnswers);
  };

  const resetRubric = () => {
    setAnswers({});
    saveRubricAnswers({});
  };

  const getCategoryProgress = () => {
    const totalCategories = rubricCategories.length;
    const completedCount = completedCategories.size;
    return Math.round((completedCount / totalCategories) * 100);
  };

  const getAnswerStats = () => {
    const totalQuestions = rubricCategories.reduce((sum, cat) => sum + cat.questions.length, 0);
    const answeredQuestions = Object.keys(answers).filter(key => answers[key] !== 'unknown' && answers[key]).length;
    return { answered: answeredQuestions, total: totalQuestions };
  };

  const renderQuestion = (question: any) => {
    const currentAnswer = answers[question.id];
    
    return (
      <div key={question.id} className="rubric-question">
        <div className="question-header">
          <span className="question-id">{question.id}</span>
          <h4 className="question-text">{question.text}</h4>
          {question.subcategory && (
            <span className="question-subcategory">{question.subcategory}</span>
          )}
        </div>
        
        <div className="question-options">
          {question.options.map((option: any) => (
            <label key={option.value} className="option-label">
              <input
                type="radio"
                name={question.id}
                value={option.value}
                checked={currentAnswer === option.value}
                onChange={() => handleAnswerChange(question.id, option.value)}
              />
              <span className={`option-content ${option.value}`}>
                <span className="option-indicator"></span>
                <span className="option-text">{option.label}</span>
              </span>
            </label>
          ))}
        </div>
      </div>
    );
  };

  const stats = getAnswerStats();
  const progress = getCategoryProgress();

  return (
    <div className="cvss-rubric">
      <div className="rubric-header">
        <h2>Medical Device CVSS Rubric Assessment</h2>
        <p>Answer the questions below to determine CVSS metrics for medical device vulnerabilities</p>
        
        <div className="progress-section">
          <div className="progress-stats">
            <div className="stat-item">
              <span className="stat-value">{stats.answered}</span>
              <span className="stat-label">of {stats.total} questions answered</span>
            </div>
            <div className="stat-item">
              <span className="stat-value">{progress}%</span>
              <span className="stat-label">categories with responses</span>
            </div>
          </div>
          
          <div className="progress-bar">
            <div 
              className="progress-fill" 
              style={{ width: `${(stats.answered / stats.total) * 100}%` }}
            ></div>
          </div>
        </div>
      </div>

      <div className="rubric-content">
        {rubricCategories.map((category) => (
          <div key={category.name} className={`rubric-category ${completedCategories.has(category.name) ? 'completed' : ''}`}>
            <div className="category-header">
              <h3 className="category-title">
                {category.name}
                {completedCategories.has(category.name) && (
                  <span className="completion-indicator">✓</span>
                )}
              </h3>
              <p className="category-description">{category.description}</p>
            </div>
            
            <div className="category-questions">
              {category.questions.map(renderQuestion)}
            </div>
          </div>
        ))}
      </div>

      <div className="rubric-actions">
        <button onClick={resetRubric} className="reset-rubric-button">
          Reset All Answers
        </button>
        
        <div className="completion-summary">
          {stats.answered === stats.total ? (
            <div className="completion-message success">
              ✅ All questions answered! CVSS vector has been calculated.
            </div>
          ) : (
            <div className="completion-message">
              📝 Answer more questions to refine your CVSS assessment
            </div>
          )}
        </div>
      </div>
    </div>
  );
};