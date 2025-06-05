import { useState, useEffect, useMemo, useCallback } from 'react';
import { RemediationScenario } from '../types/cvss';
import { medicalDeviceRemediationScenarios } from '../data/remediationGuidance';
import {
  ScenarioStorageProvider,
  createStorageProvider,
  StorageType,
} from '../services/scenarioStorage';

export interface CustomScenario extends RemediationScenario {
  id: string;
  createdAt: string;
  updatedAt: string;
  isCustom: true;
}

export interface UseCustomScenariosReturn {
  scenarios: (RemediationScenario | CustomScenario)[];
  customScenarios: CustomScenario[];
  loading: boolean;
  error: string | null;
  addScenario: (
    scenario: Omit<CustomScenario, 'id' | 'createdAt' | 'updatedAt' | 'isCustom'>
  ) => Promise<void>;
  updateScenario: (
    id: string,
    scenario: Partial<Omit<CustomScenario, 'id' | 'createdAt' | 'isCustom'>>
  ) => Promise<void>;
  deleteScenario: (id: string) => Promise<void>;
  exportScenarios: () => string;
  importScenarios: (data: string) => Promise<boolean>;
  clearAllCustomScenarios: () => Promise<void>;
  setStorageType: (type: StorageType, userId?: string) => void;
}

export function useCustomScenarios(
  initialStorageType: StorageType = 'localStorage',
  userId?: string
): UseCustomScenariosReturn {
  const [customScenarios, setCustomScenarios] = useState<CustomScenario[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [storageType, setStorageTypeState] = useState<StorageType>(initialStorageType);
  const [currentUserId, setCurrentUserId] = useState<string | undefined>(userId);

  // Create storage provider based on current settings
  const storageProvider = useMemo<ScenarioStorageProvider>(() => {
    try {
      return createStorageProvider(storageType, currentUserId);
    } catch (err) {
      // Fallback to localStorage
      return createStorageProvider('localStorage');
    }
  }, [storageType, currentUserId]);

  // Load scenarios from storage
  const loadScenarios = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const scenarios = await storageProvider.getScenarios();
      setCustomScenarios(scenarios);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to load scenarios';
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  }, [storageProvider]);

  // Load scenarios when provider changes
  useEffect(() => {
    loadScenarios();
  }, [storageProvider, loadScenarios]);

  const addScenario = async (
    scenario: Omit<CustomScenario, 'id' | 'createdAt' | 'updatedAt' | 'isCustom'>
  ) => {
    setLoading(true);
    setError(null);
    try {
      const newScenario = await storageProvider.addScenario(scenario);
      setCustomScenarios((prev) => [...prev, newScenario]);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to add scenario';
      setError(errorMessage);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const updateScenario = async (
    id: string,
    updates: Partial<Omit<CustomScenario, 'id' | 'createdAt' | 'isCustom'>>
  ) => {
    setLoading(true);
    setError(null);
    try {
      const updatedScenario = await storageProvider.updateScenario(id, updates);
      setCustomScenarios((prev) =>
        prev.map((scenario) => (scenario.id === id ? updatedScenario : scenario))
      );
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to update scenario';
      setError(errorMessage);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const deleteScenario = async (id: string) => {
    setLoading(true);
    setError(null);
    try {
      await storageProvider.deleteScenario(id);
      setCustomScenarios((prev) => prev.filter((scenario) => scenario.id !== id));
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to delete scenario';
      setError(errorMessage);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const exportScenarios = (): string => {
    const exportData = {
      version: '1.0',
      exportedAt: new Date().toISOString(),
      scenarios: customScenarios,
    };
    return JSON.stringify(exportData, null, 2);
  };

  const importScenarios = async (data: string): Promise<boolean> => {
    setLoading(true);
    setError(null);
    try {
      const parsed = JSON.parse(data);

      if (!parsed.scenarios || !Array.isArray(parsed.scenarios)) {
        setError('Invalid import data format');
        return false;
      }

      // Validate scenario structure
      const validScenarios = parsed.scenarios.filter((scenario: any) => {
        return (
          scenario.title &&
          scenario.description &&
          scenario.before &&
          scenario.after &&
          Array.isArray(scenario.remediationActions)
        );
      });

      if (validScenarios.length === 0) {
        setError('No valid scenarios found in import data');
        return false;
      }

      const importedScenarios = await storageProvider.importScenarios(validScenarios);
      setCustomScenarios((prev) => [...prev, ...importedScenarios]);
      return true;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to import scenarios';
      setError(errorMessage);
      return false;
    } finally {
      setLoading(false);
    }
  };

  const clearAllCustomScenarios = async () => {
    setLoading(true);
    setError(null);
    try {
      await storageProvider.clearAllScenarios();
      setCustomScenarios([]);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to clear scenarios';
      setError(errorMessage);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const setStorageType = (type: StorageType, userId?: string) => {
    setStorageTypeState(type);
    setCurrentUserId(userId);
  };

  // Combine default and custom scenarios
  const allScenarios = [...medicalDeviceRemediationScenarios, ...customScenarios];

  return {
    scenarios: allScenarios,
    customScenarios,
    loading,
    error,
    addScenario,
    updateScenario,
    deleteScenario,
    exportScenarios,
    importScenarios,
    clearAllCustomScenarios,
    setStorageType,
  };
}
