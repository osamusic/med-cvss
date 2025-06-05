import React, { useRef, useState } from 'react';
import { UseCustomScenariosReturn } from '../hooks/useCustomScenarios';
import './ScenarioImportExport.css';

interface ScenarioImportExportProps {
  scenarioManager: UseCustomScenariosReturn;
}

const ScenarioImportExport: React.FC<ScenarioImportExportProps> = ({ scenarioManager }) => {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [importStatus, setImportStatus] = useState<'idle' | 'success' | 'error'>('idle');
  const [statusMessage, setStatusMessage] = useState('');

  const handleExport = () => {
    if (scenarioManager.customScenarios.length === 0) {
      alert('No custom scenarios to export.');
      return;
    }

    const exportData = scenarioManager.exportScenarios();
    const blob = new Blob([exportData], { type: 'application/json' });
    const url = URL.createObjectURL(blob);

    const link = document.createElement('a');
    link.href = url;
    link.download = `medical-device-scenarios-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleImportClick = () => {
    fileInputRef.current?.click();
  };

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const data = e.target?.result as string;
        const success = await scenarioManager.importScenarios(data);

        if (success) {
          setImportStatus('success');
          setStatusMessage('Scenarios imported successfully!');
        } else {
          setImportStatus('error');
          setStatusMessage('Failed to import scenarios. Please check the file format.');
        }
      } catch (error) {
        setImportStatus('error');
        setStatusMessage("Failed to read the file. Please ensure it's a valid JSON file.");
      }

      // Clear status after 3 seconds
      setTimeout(() => {
        setImportStatus('idle');
        setStatusMessage('');
      }, 3000);
    };

    reader.readAsText(file);

    // Reset file input
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleClearAll = async () => {
    if (scenarioManager.customScenarios.length === 0) {
      alert('No custom scenarios to clear.');
      return;
    }

    const confirmed = window.confirm(
      `Are you sure you want to delete all ${scenarioManager.customScenarios.length} custom scenarios? This action cannot be undone.`
    );

    if (confirmed) {
      try {
        await scenarioManager.clearAllCustomScenarios();
        setImportStatus('success');
        setStatusMessage('All custom scenarios have been cleared.');
      } catch (error) {
        setImportStatus('error');
        setStatusMessage('Failed to clear scenarios. Please try again.');
      }

      setTimeout(() => {
        setImportStatus('idle');
        setStatusMessage('');
      }, 3000);
    }
  };

  return (
    <div className='scenario-import-export'>
      <h4>Scenario Management</h4>

      <div className='import-export-actions'>
        <button
          onClick={handleExport}
          className='export-button'
          disabled={scenarioManager.customScenarios.length === 0}
        >
          📤 Export Scenarios ({scenarioManager.customScenarios.length})
        </button>

        <button onClick={handleImportClick} className='import-button'>
          📥 Import Scenarios
        </button>

        <button
          onClick={handleClearAll}
          className='clear-button'
          disabled={scenarioManager.customScenarios.length === 0}
        >
          🗑️ Clear All Custom
        </button>
      </div>

      <input
        ref={fileInputRef}
        type='file'
        accept='.json'
        onChange={handleFileSelect}
        style={{ display: 'none' }}
      />

      {importStatus !== 'idle' && (
        <div className={`status-message ${importStatus}`}>{statusMessage}</div>
      )}

      <div className='scenario-stats'>
        <p>
          <strong>Default scenarios:</strong>{' '}
          {scenarioManager.scenarios.length - scenarioManager.customScenarios.length}
        </p>
        <p>
          <strong>Custom scenarios:</strong> {scenarioManager.customScenarios.length}
        </p>
        <p>
          <strong>Total scenarios:</strong> {scenarioManager.scenarios.length}
        </p>
      </div>

      <div className='usage-info'>
        <h5>Import/Export Information:</h5>
        <ul>
          <li>Export saves all your custom scenarios to a JSON file</li>
          <li>Import adds scenarios from a JSON file to your existing collection</li>
          <li>Data is automatically saved in your browser's local storage</li>
          <li>Default scenarios cannot be deleted or exported</li>
        </ul>
      </div>
    </div>
  );
};

export default ScenarioImportExport;
