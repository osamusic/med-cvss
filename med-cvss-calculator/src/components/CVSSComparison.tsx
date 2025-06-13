import React, { useState } from 'react';
import { CVSSVector, CVSSComparison, RemediationScenario } from '../types/cvss';
import {
  compareVectors,
  generateComparisonReport,
  calculateRiskReduction,
} from '../utils/cvssComparison';
import { remediationGuidance } from '../data/remediationGuidance';
import { useCustomScenarios, CustomScenario } from '../hooks/useCustomScenarios';
import ScenarioEditor from './ScenarioEditor';
import ScenarioImportExport from './ScenarioImportExport';
import './CVSSComparison.css';

interface CVSSComparisonProps {
  initialVector?: CVSSVector;
}

const CVSSComparisonComponent = React.memo<CVSSComparisonProps>(({ initialVector }) => {
  const scenarioManager = useCustomScenarios();
  const [beforeVector, setBeforeVector] = useState<CVSSVector>(initialVector || {});
  const [afterVector, setAfterVector] = useState<CVSSVector>({});
  const [remediationActions, setRemediationActions] = useState<string[]>([]);
  const [comparison, setComparison] = useState<CVSSComparison | null>(null);
  const [selectedScenario, setSelectedScenario] = useState<string>('');
  const [showEditor, setShowEditor] = useState(false);
  const [editingScenario, setEditingScenario] = useState<CustomScenario | null>(null);

  const handleCompare = () => {
    const result = compareVectors(beforeVector, afterVector, remediationActions);
    setComparison(result);
  };

  const loadScenario = (scenario: RemediationScenario | CustomScenario) => {
    setBeforeVector(scenario.before);
    setAfterVector(scenario.after);
    setRemediationActions(scenario.remediationActions);
    setSelectedScenario(scenario.title);
  };

  const handleAddScenario = () => {
    setEditingScenario(null);
    setShowEditor(true);
  };

  const handleEditScenario = (scenario: CustomScenario) => {
    setEditingScenario(scenario);
    setShowEditor(true);
  };

  const handleSaveScenario = async (
    scenarioData: Omit<CustomScenario, 'id' | 'createdAt' | 'updatedAt' | 'isCustom'>
  ) => {
    try {
      if (editingScenario) {
        await scenarioManager.updateScenario(editingScenario.id, scenarioData);
      } else {
        await scenarioManager.addScenario(scenarioData);
      }
      setShowEditor(false);
      setEditingScenario(null);
    } catch (error) {
      alert('Failed to save scenario. Please try again.');
    }
  };

  const handleDeleteScenario = async (scenario: CustomScenario) => {
    const confirmed = window.confirm(`Are you sure you want to delete "${scenario.title}"?`);
    if (confirmed) {
      try {
        await scenarioManager.deleteScenario(scenario.id);
        if (selectedScenario === scenario.title) {
          setSelectedScenario('');
        }
      } catch (error) {
        alert('Failed to delete scenario. Please try again.');
      }
    }
  };

  const isCustomScenario = (
    scenario: RemediationScenario | CustomScenario
  ): scenario is CustomScenario => {
    return 'isCustom' in scenario && scenario.isCustom === true;
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
    setRemediationActions(remediationActions.filter((_, i) => i !== index));
  };

  return (
    <div className='cvss-comparison'>
      <h2>CVSS v3.1 Before/After Evaluation Guide</h2>

      {/* Purpose Section */}
      <div className='guidance-section'>
        <h3>🎯 Purpose</h3>
        <ul>
          {remediationGuidance.purpose.map((purpose, index) => (
            <li key={index}>{purpose}</li>
          ))}
        </ul>
      </div>

      {/* Changeable Metrics Guide */}
      <div className='guidance-section'>
        <h3>🛠️ Base Metrics That May Change Due to Remediation</h3>
        <div className='metrics-table'>
          <table>
            <thead>
              <tr>
                <th>Metric</th>
                <th>Change Reason</th>
                <th>Example</th>
              </tr>
            </thead>
            <tbody>
              {remediationGuidance.changableMetrics.map((metric, index) => (
                <tr key={index}>
                  <td>{metric.metric}</td>
                  <td>{metric.changeReason}</td>
                  <td>{metric.example}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Evaluation Steps */}
      <div className='guidance-section'>
        <h3>🧭 Re-evaluation Process (Base + Temporal)</h3>
        <ol>
          {remediationGuidance.evaluationSteps.map((step, index) => (
            <li key={index}>{step}</li>
          ))}
        </ol>
      </div>

      {/* Sample Scenarios */}
      <div className='guidance-section'>
        <h3>📋 Medical Device Remediation Scenarios</h3>

        <div className='scenario-management'>
          <button onClick={handleAddScenario} className='add-scenario-button'>
            ➕ Add New Scenario
          </button>
        </div>

        <div className='scenario-list'>
          {scenarioManager.scenarios.map((scenario, index) => (
            <div
              key={`scenario-${index}-${scenario.title.replace(/\s+/g, '-').toLowerCase()}`}
              className='scenario-item'
            >
              <button
                onClick={() => loadScenario(scenario)}
                className={`scenario-load-button ${selectedScenario === scenario.title ? 'selected' : ''}`}
              >
                {scenario.title}
                {isCustomScenario(scenario) && <span className='custom-badge'>Custom</span>}
              </button>

              {isCustomScenario(scenario) && (
                <div className='scenario-actions'>
                  <button
                    onClick={() => handleEditScenario(scenario)}
                    className='edit-scenario-button'
                    title='Edit scenario'
                  >
                    ✏️
                  </button>
                  <button
                    onClick={() => handleDeleteScenario(scenario)}
                    className='delete-scenario-button'
                    title='Delete scenario'
                  >
                    🗑️
                  </button>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Import/Export Section */}
      <div className='guidance-section'>
        <ScenarioImportExport scenarioManager={scenarioManager} />
      </div>

      {/* Vector Input Forms */}
      <div className='vector-forms'>
        <div className='vector-form'>
          <h4>Before Remediation Vector</h4>
          <div className='vector-display'>
            {Object.entries(beforeVector).map(([key, value]) => (
              <span key={key} className='metric-tag'>
                {key}:{value}
              </span>
            ))}
          </div>
        </div>

        <div className='vector-form'>
          <h4>After Remediation Vector</h4>
          <div className='vector-display'>
            {Object.entries(afterVector).map(([key, value]) => (
              <span key={key} className='metric-tag'>
                {key}:{value}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Remediation Actions */}
      <div className='remediation-actions'>
        <h4>Remediation Actions</h4>
        {remediationActions.map((action, index) => (
          <div
            key={`remediation-action-${index}-${action.slice(0, 10).replace(/\s+/g, '-')}`}
            className='action-input'
          >
            <input
              type='text'
              value={action}
              onChange={(e) => updateRemediationAction(index, e.target.value)}
              placeholder='Enter remediation action...'
            />
            <button onClick={() => removeRemediationAction(index)}>Remove</button>
          </div>
        ))}
        <button onClick={addRemediationAction}>Add Action</button>
      </div>

      {/* Compare Button */}
      <div className='compare-section'>
        <button
          onClick={handleCompare}
          className='compare-button'
          disabled={Object.keys(beforeVector).length === 0 || Object.keys(afterVector).length === 0}
        >
          Compare Before/After
        </button>
      </div>

      {/* Comparison Results */}
      {comparison && (
        <div className='comparison-results'>
          <h3>📊 Comparison Results</h3>

          {/* Score Summary */}
          <div className='score-summary'>
            <div className='score-item'>
              <h4>Before Remediation</h4>
              <div className='score-value'>{comparison.beforeScore.overallScore}</div>
              <div className='severity'>{comparison.beforeScore.severity}</div>
            </div>
            <div className='score-arrow'>→</div>
            <div className='score-item'>
              <h4>After Remediation</h4>
              <div className='score-value'>{comparison.afterScore.overallScore}</div>
              <div className='severity'>{comparison.afterScore.severity}</div>
            </div>
          </div>

          {/* Risk Reduction Analysis */}
          {(() => {
            const riskReduction = calculateRiskReduction(
              comparison.beforeScore.overallScore,
              comparison.afterScore.overallScore
            );
            return (
              <div className='risk-reduction'>
                <h4>Risk Reduction Analysis</h4>
                <p>
                  <strong>Score Reduction:</strong> {riskReduction.scoreReduction.toFixed(1)} points
                </p>
                <p>
                  <strong>Percentage Reduction:</strong> {riskReduction.percentageReduction}%
                </p>
                <p>
                  <strong>Assessment:</strong> {riskReduction.riskCategory}
                </p>
              </div>
            );
          })()}

          {/* Metric Changes Table */}
          {comparison.metricChanges.length > 0 && (
            <div className='metric-changes'>
              <h4>Metric Changes</h4>
              <table>
                <thead>
                  <tr>
                    <th>Metric</th>
                    <th>Before</th>
                    <th>After</th>
                    <th>Comment</th>
                  </tr>
                </thead>
                <tbody>
                  {comparison.metricChanges.map((change, index) => (
                    <tr key={`metric-change-${change.metric}-${index}`}>
                      <td>{change.metric}</td>
                      <td>
                        {change.beforeLabel} ({change.before})
                      </td>
                      <td>
                        {change.afterLabel} ({change.after})
                      </td>
                      <td>{change.comment}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Report Generation */}
          <div className='report-section'>
            <h4>Generated Report</h4>
            <textarea
              value={generateComparisonReport(comparison)}
              readOnly
              rows={20}
              className='report-text'
            />
          </div>
        </div>
      )}

      {/* Output Example */}
      <div className='guidance-section'>
        <h3>📊 Output Example (Base Re-evaluation)</h3>
        <div className='output-example'>
          <table>
            <thead>
              <tr>
                <th>Metric</th>
                <th>Before</th>
                <th>After</th>
                <th>Comment</th>
              </tr>
            </thead>
            <tbody>
              {remediationGuidance.outputExample.map((example, index) => (
                <tr key={index}>
                  <td>{example.metric}</td>
                  <td>{example.before}</td>
                  <td>{example.after}</td>
                  <td>{example.comment}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className='note'>Score differences serve as evidence of remediation effectiveness</p>
        </div>
      </div>

      {/* Scenario Editor Modal */}
      <ScenarioEditor
        isOpen={showEditor}
        scenario={editingScenario}
        onSave={handleSaveScenario}
        onCancel={() => {
          setShowEditor(false);
          setEditingScenario(null);
        }}
      />
    </div>
  );
});

CVSSComparisonComponent.displayName = 'CVSSComparisonComponent';

export default CVSSComparisonComponent;
