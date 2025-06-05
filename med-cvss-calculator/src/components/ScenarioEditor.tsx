import React, { useState, useEffect } from 'react';
import { CVSSVector } from '../types/cvss';
import { CustomScenario } from '../hooks/useCustomScenarios';
import { cvssMetrics } from '../data/cvssMetrics';
import './ScenarioEditor.css';

interface ScenarioEditorProps {
  isOpen: boolean;
  scenario?: CustomScenario | null;
  onSave: (scenario: Omit<CustomScenario, 'id' | 'createdAt' | 'updatedAt' | 'isCustom'>) => void;
  onCancel: () => void;
}

const ScenarioEditor: React.FC<ScenarioEditorProps> = ({ isOpen, scenario, onSave, onCancel }) => {
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [beforeVector, setBeforeVector] = useState<CVSSVector>({});
  const [afterVector, setAfterVector] = useState<CVSSVector>({});
  const [remediationActions, setRemediationActions] = useState<string[]>(['']);

  const isEditMode = Boolean(scenario);

  useEffect(() => {
    if (scenario) {
      setTitle(scenario.title);
      setDescription(scenario.description);
      setBeforeVector(scenario.before);
      setAfterVector(scenario.after);
      setRemediationActions(
        scenario.remediationActions.length > 0 ? scenario.remediationActions : ['']
      );
    } else {
      // Reset form for new scenario
      setTitle('');
      setDescription('');
      setBeforeVector({});
      setAfterVector({});
      setRemediationActions(['']);
    }
  }, [scenario, isOpen]);

  const handleSave = () => {
    if (!title.trim() || !description.trim()) {
      alert('Please fill in title and description');
      return;
    }

    const filteredActions = remediationActions.filter((action) => action.trim() !== '');
    if (filteredActions.length === 0) {
      alert('Please add at least one remediation action');
      return;
    }

    onSave({
      title: title.trim(),
      description: description.trim(),
      before: beforeVector,
      after: afterVector,
      remediationActions: filteredActions,
    });
  };

  const updateVector = (vector: CVSSVector, metric: string, value: string, isAfter: boolean) => {
    const updatedVector = { ...vector, [metric]: value };
    if (isAfter) {
      setAfterVector(updatedVector);
    } else {
      setBeforeVector(updatedVector);
    }
  };

  const addRemediationAction = () => {
    setRemediationActions([...remediationActions, '']);
  };

  const updateRemediationAction = (index: number, value: string) => {
    const updated = [...remediationActions];
    updated[index] = value;
    setRemediationActions(updated);
  };

  const removeRemediationAction = (index: number) => {
    if (remediationActions.length > 1) {
      setRemediationActions(remediationActions.filter((_, i) => i !== index));
    }
  };

  const renderMetricSelector = (
    metricKey: string,
    metricLabel: string,
    vector: CVSSVector,
    isAfter: boolean
  ) => {
    const metricGroup = cvssMetrics.find((group) => group.metrics[metricKey]);
    if (!metricGroup) return null;

    const options = metricGroup.metrics[metricKey];
    const currentValue = vector[metricKey as keyof CVSSVector] || '';

    return (
      <div className='metric-selector'>
        <label>
          {metricLabel} ({metricKey}):
        </label>
        <select
          value={currentValue}
          onChange={(e) => updateVector(vector, metricKey, e.target.value, isAfter)}
        >
          <option value=''>Not Set</option>
          {options.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label} ({option.value})
            </option>
          ))}
        </select>
      </div>
    );
  };

  if (!isOpen) return null;

  return (
    <div className='scenario-editor-overlay'>
      <div className='scenario-editor-modal'>
        <div className='scenario-editor-header'>
          <h2>{isEditMode ? 'Edit Scenario' : 'Add New Scenario'}</h2>
          <button className='close-button' onClick={onCancel}>
            ×
          </button>
        </div>

        <div className='scenario-editor-content'>
          {/* Basic Info */}
          <div className='form-section'>
            <h3>Basic Information</h3>
            <div className='form-group'>
              <label>Title:</label>
              <input
                type='text'
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder='Enter scenario title...'
              />
            </div>
            <div className='form-group'>
              <label>Description:</label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder='Enter scenario description...'
                rows={3}
              />
            </div>
          </div>

          {/* CVSS Vectors */}
          <div className='form-section'>
            <h3>CVSS Vectors</h3>
            <div className='vector-editors'>
              <div className='vector-editor'>
                <h4>Before Remediation</h4>
                <div className='metrics-grid'>
                  {renderMetricSelector('AV', 'Attack Vector', beforeVector, false)}
                  {renderMetricSelector('AC', 'Attack Complexity', beforeVector, false)}
                  {renderMetricSelector('PR', 'Privileges Required', beforeVector, false)}
                  {renderMetricSelector('UI', 'User Interaction', beforeVector, false)}
                  {renderMetricSelector('S', 'Scope', beforeVector, false)}
                  {renderMetricSelector('C', 'Confidentiality', beforeVector, false)}
                  {renderMetricSelector('I', 'Integrity', beforeVector, false)}
                  {renderMetricSelector('A', 'Availability', beforeVector, false)}
                </div>
              </div>

              <div className='vector-editor'>
                <h4>After Remediation</h4>
                <div className='metrics-grid'>
                  {renderMetricSelector('AV', 'Attack Vector', afterVector, true)}
                  {renderMetricSelector('AC', 'Attack Complexity', afterVector, true)}
                  {renderMetricSelector('PR', 'Privileges Required', afterVector, true)}
                  {renderMetricSelector('UI', 'User Interaction', afterVector, true)}
                  {renderMetricSelector('S', 'Scope', afterVector, true)}
                  {renderMetricSelector('C', 'Confidentiality', afterVector, true)}
                  {renderMetricSelector('I', 'Integrity', afterVector, true)}
                  {renderMetricSelector('A', 'Availability', afterVector, true)}
                </div>
              </div>
            </div>
          </div>

          {/* Remediation Actions */}
          <div className='form-section'>
            <h3>Remediation Actions</h3>
            {remediationActions.map((action, index) => (
              <div key={index} className='action-input'>
                <input
                  type='text'
                  value={action}
                  onChange={(e) => updateRemediationAction(index, e.target.value)}
                  placeholder='Enter remediation action...'
                />
                {remediationActions.length > 1 && (
                  <button
                    type='button'
                    onClick={() => removeRemediationAction(index)}
                    className='remove-action-button'
                  >
                    Remove
                  </button>
                )}
              </div>
            ))}
            <button type='button' onClick={addRemediationAction} className='add-action-button'>
              Add Action
            </button>
          </div>
        </div>

        <div className='scenario-editor-footer'>
          <button onClick={onCancel} className='cancel-button'>
            Cancel
          </button>
          <button onClick={handleSave} className='save-button'>
            {isEditMode ? 'Update Scenario' : 'Create Scenario'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default ScenarioEditor;
