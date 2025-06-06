import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { CVSSVector } from '../types/cvss';
import {
  mitreRubricQuestions,
  calculateMitreVector,
  getNextQuestion,
  MitreRubricAnswers,
  MitreQuestion,
} from '../data/mitreCvssRubric';
import './MitreCVSSRubric.css';

interface MitreCVSSRubricProps {
  onVectorChange: (vector: CVSSVector) => void;
  initialVector?: CVSSVector;
}

// Load MITRE rubric answers from localStorage
const loadMitreAnswers = (): MitreRubricAnswers => {
  const saved = localStorage.getItem('mitreCvssRubricAnswers');
  if (saved) {
    try {
      return JSON.parse(saved);
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error('Failed to load MITRE rubric answers:', e);
    }
  }
  return {};
};

// Save MITRE rubric answers to localStorage
const saveMitreAnswers = (answers: MitreRubricAnswers) => {
  localStorage.setItem('mitreCvssRubricAnswers', JSON.stringify(answers));
};

export const MitreCVSSRubric: React.FC<MitreCVSSRubricProps> = ({ onVectorChange }) => {
  const [answers, setAnswers] = useState<MitreRubricAnswers>(loadMitreAnswers());
  const [completedCategories, setCompletedCategories] = useState<Set<string>>(new Set());

  useEffect(() => {
    const vector = calculateMitreVector(answers);
    onVectorChange(vector);

    // Update completed categories
    const completed = new Set<string>();
    const categories = [
      'Attack Vector',
      'Attack Complexity',
      'Privileges Required',
      'User Interaction',
      'Scope',
      'Confidentiality Impact',
      'Integrity Impact',
      'Availability Impact',
    ];

    categories.forEach((category) => {
      const categoryQuestions = mitreRubricQuestions.filter((q) => q.category === category);
      const hasAnswers = categoryQuestions.some((q) => answers[q.id]);
      if (hasAnswers) {
        completed.add(category);
      }
    });

    setCompletedCategories(completed);
  }, [answers, onVectorChange]);

  const handleAnswerChange = (questionId: string, value: string) => {
    const newAnswers = {
      ...answers,
      [questionId]: value,
    };

    // Clear subsequent questions in the same category when changing an answer
    const question = mitreRubricQuestions.find((q) => q.id === questionId);
    if (question) {
      const categoryQuestions = mitreRubricQuestions
        .filter((q) => q.category === question.category)
        .map((q) => q.id);

      const currentIndex = categoryQuestions.indexOf(questionId);
      if (currentIndex !== -1) {
        // Clear answers for subsequent questions in this category
        categoryQuestions.slice(currentIndex + 1).forEach((qId) => {
          delete newAnswers[qId];
        });
      }
    }

    setAnswers(newAnswers);
    saveMitreAnswers(newAnswers);
  };

  const resetRubric = () => {
    setAnswers({});
    saveMitreAnswers({});
  };

  const getVisibleQuestions = useCallback((): MitreQuestion[] => {
    const visible: MitreQuestion[] = [];
    const categories = [
      'Attack Vector',
      'Attack Complexity',
      'Privileges Required',
      'User Interaction',
      'Scope',
      'Confidentiality Impact',
      'Integrity Impact',
      'Availability Impact',
    ];

    categories.forEach((category) => {
      const categoryQuestions = mitreRubricQuestions.filter((q) => q.category === category);

      // For CIA Impact categories, show all questions in parallel
      if (category.includes('Impact')) {
        // For Confidentiality Impact, show all C questions except XCPM (which depends on XCP)
        if (category === 'Confidentiality Impact') {
          categoryQuestions.forEach((q) => {
            if (q.id === 'XCPM') {
              // Only show XCPM if XCP is answered 'yes'
              if (answers.XCP === 'yes') {
                visible.push(q);
              }
            } else {
              // Show all other C questions
              visible.push(q);
            }
          });
        } else {
          // For Integrity and Availability Impact, show all questions
          visible.push(...categoryQuestions);
        }
      } else {
        // For non-CIA categories, use flowchart logic
        if (categoryQuestions.length > 0) {
          visible.push(categoryQuestions[0]);

          // Show subsequent questions based on flowchart logic
          let currentQ = categoryQuestions[0];
          while (currentQ && answers[currentQ.id]) {
            const nextQId = getNextQuestion(currentQ.id, answers[currentQ.id]);
            if (nextQId) {
              const nextQ = mitreRubricQuestions.find((q) => q.id === nextQId);
              if (nextQ && nextQ.category === category) {
                visible.push(nextQ);
                currentQ = nextQ;
              } else {
                break;
              }
            } else {
              break;
            }
          }
        }
      }
    });

    return visible;
  }, [answers]);

  const getProgressStats = useCallback(() => {
    const visibleQuestions = getVisibleQuestions();
    const answeredCount = visibleQuestions.filter((q) => answers[q.id]).length;
    return { answered: answeredCount, total: visibleQuestions.length };
  }, [getVisibleQuestions, answers]);

  const renderQuestion = (
    question: MitreQuestion,
    categoryIndex: number,
    questionIndex: number
  ) => {
    const currentAnswer = answers[question.id];
    const isAnswered = Boolean(currentAnswer);

    return (
      <div
        key={`${question.category}-${question.id}-${categoryIndex}-${questionIndex}`}
        className={`mitre-question ${isAnswered ? 'answered' : ''}`}
      >
        <div className='question-header'>
          <div className='question-meta'>
            <span className='question-id'>{question.id}</span>
            <span className={`question-type ${question.type}`}>
              {question.type === 'decision'
                ? '🔄'
                : question.type === 'classification'
                  ? '📋'
                  : '📊'}
              {question.type.charAt(0).toUpperCase() + question.type.slice(1)}
            </span>
          </div>
          <h4 className='question-text'>{question.text}</h4>

          {question.description && <p className='question-description'>{question.description}</p>}

          {question.guidance && (
            <div className='question-guidance'>
              <strong>Guidance:</strong> {question.guidance}
            </div>
          )}
        </div>

        <div className='question-options'>
          {question.options.map((option) => (
            <label key={option.value} className='mitre-option-label'>
              <input
                type='radio'
                name={question.id}
                value={option.value}
                checked={currentAnswer === option.value}
                onChange={() => handleAnswerChange(question.id, option.value)}
              />
              <span className='mitre-option-content'>
                <span className='option-indicator'></span>
                <div className='option-details'>
                  <span className='option-text'>{option.label}</span>
                  {option.cvssValue && (
                    <span className='cvss-indicator'>CVSS: {option.cvssValue}</span>
                  )}
                  {option.nextQuestion && (
                    <span className='flow-indicator'>→ Next: {option.nextQuestion}</span>
                  )}
                </div>
              </span>
            </label>
          ))}
        </div>
      </div>
    );
  };

  const visibleQuestions = useMemo(() => getVisibleQuestions(), [getVisibleQuestions]);
  const stats = useMemo(() => getProgressStats(), [getProgressStats]);
  const progress = Math.round((stats.answered / stats.total) * 100);

  // Group questions by category
  const questionsByCategory = useMemo(() => {
    return visibleQuestions.reduce(
      (acc, question) => {
        if (!acc[question.category]) {
          acc[question.category] = [];
        }
        acc[question.category].push(question);
        return acc;
      },
      {} as { [category: string]: MitreQuestion[] }
    );
  }, [visibleQuestions]);

  return (
    <div className='mitre-cvss-rubric'>
      <div className='mitre-header'>
        <h2>MITRE Medical Device CVSS Rubric</h2>
        <p>
          Structured assessment following MITRE's medical device cybersecurity evaluation framework
        </p>

        <div className='mitre-progress'>
          <div className='progress-stats'>
            <div className='stat-item'>
              <span className='stat-value'>{stats.answered}</span>
              <span className='stat-label'>of {stats.total} questions answered</span>
            </div>
            <div className='stat-item'>
              <span className='stat-value'>{completedCategories.size}</span>
              <span className='stat-label'>of 8 categories started</span>
            </div>
          </div>

          <div className='progress-bar'>
            <div className='progress-fill' style={{ width: `${progress}%` }}></div>
          </div>

          <div className='progress-text'>{progress}% Complete</div>
        </div>
      </div>

      <div className='mitre-content' key={`mitre-content-${Object.keys(answers).length}`}>
        {/* Debug: Show all expected categories */}
        {[
          'Attack Vector',
          'Attack Complexity',
          'Privileges Required',
          'User Interaction',
          'Scope',
          'Confidentiality Impact',
          'Integrity Impact',
          'Availability Impact',
        ].map((category, categoryIndex) => {
          const questions = questionsByCategory[category] || [];
          const isCompleted = completedCategories.has(category);
          const hasQuestions = questions.length > 0;

          return (
            <div
              key={`category-${category}-${categoryIndex}`}
              className={`mitre-category ${isCompleted ? 'completed' : ''}`}
            >
              <div className='category-header'>
                <h3 className='category-title'>
                  {category}
                  {isCompleted && <span className='completion-check'>✓</span>}
                  <span className='question-count'>
                    ({questions.length} question{questions.length !== 1 ? 's' : ''})
                  </span>
                </h3>
              </div>

              {hasQuestions ? (
                <div className='category-questions'>
                  {questions.map((question, questionIndex) =>
                    renderQuestion(question, categoryIndex, questionIndex)
                  )}
                </div>
              ) : (
                <div className='category-questions'>
                  <p style={{ padding: '20px', color: '#999', fontStyle: 'italic' }}>
                    No questions available for this category
                  </p>
                </div>
              )}
            </div>
          );
        })}
      </div>

      <div className='mitre-actions'>
        <button onClick={resetRubric} className='reset-mitre-button'>
          Reset Assessment
        </button>

        <div className='completion-summary'>
          {stats.answered === stats.total && stats.total > 0 ? (
            <div className='completion-message success'>
              ✅ Assessment complete! CVSS vector calculated using MITRE medical device rubric.
            </div>
          ) : (
            <div className='completion-message'>
              📋 Follow the flowchart by answering questions to complete your medical device CVSS
              assessment
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
