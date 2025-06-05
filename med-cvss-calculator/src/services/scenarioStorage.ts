import { CustomScenario } from '../hooks/useCustomScenarios';
import {
  collection,
  doc,
  getDocs,
  addDoc,
  updateDoc,
  deleteDoc,
  query,
  where,
  orderBy,
  Timestamp,
} from 'firebase/firestore';
import { db } from './firebase';

export interface ScenarioStorageProvider {
  getScenarios(): Promise<CustomScenario[]>;
  addScenario(
    scenario: Omit<CustomScenario, 'id' | 'createdAt' | 'updatedAt' | 'isCustom'>
  ): Promise<CustomScenario>;
  updateScenario(
    id: string,
    updates: Partial<Omit<CustomScenario, 'id' | 'createdAt' | 'isCustom'>>
  ): Promise<CustomScenario>;
  deleteScenario(id: string): Promise<void>;
  importScenarios(scenarios: CustomScenario[]): Promise<CustomScenario[]>;
  clearAllScenarios(): Promise<void>;
}

// LocalStorage implementation
export class LocalStorageProvider implements ScenarioStorageProvider {
  private readonly storageKey = 'medical-device-custom-scenarios';

  async getScenarios(): Promise<CustomScenario[]> {
    try {
      const stored = localStorage.getItem(this.storageKey);
      if (stored) {
        const parsed = JSON.parse(stored);
        if (Array.isArray(parsed)) {
          return parsed;
        }
      }
    } catch (error) {
      console.error('Failed to load scenarios from localStorage:', error);
    }
    return [];
  }

  async addScenario(
    scenario: Omit<CustomScenario, 'id' | 'createdAt' | 'updatedAt' | 'isCustom'>
  ): Promise<CustomScenario> {
    const scenarios = await this.getScenarios();
    const now = new Date().toISOString();
    const newScenario: CustomScenario = {
      ...scenario,
      id: `custom-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      createdAt: now,
      updatedAt: now,
      isCustom: true,
    };

    const updated = [...scenarios, newScenario];
    await this.saveScenarios(updated);
    return newScenario;
  }

  async updateScenario(
    id: string,
    updates: Partial<Omit<CustomScenario, 'id' | 'createdAt' | 'isCustom'>>
  ): Promise<CustomScenario> {
    const scenarios = await this.getScenarios();
    const index = scenarios.findIndex((s) => s.id === id);

    if (index === -1) {
      throw new Error(`Scenario with id ${id} not found`);
    }

    const updatedScenario = {
      ...scenarios[index],
      ...updates,
      updatedAt: new Date().toISOString(),
    };

    scenarios[index] = updatedScenario;
    await this.saveScenarios(scenarios);
    return updatedScenario;
  }

  async deleteScenario(id: string): Promise<void> {
    const scenarios = await this.getScenarios();
    const filtered = scenarios.filter((s) => s.id !== id);
    await this.saveScenarios(filtered);
  }

  async importScenarios(importedScenarios: CustomScenario[]): Promise<CustomScenario[]> {
    const existingScenarios = await this.getScenarios();
    const now = new Date().toISOString();

    const newScenarios = importedScenarios.map((scenario) => ({
      ...scenario,
      id: `imported-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      createdAt: now,
      updatedAt: now,
      isCustom: true as const,
    }));

    const allScenarios = [...existingScenarios, ...newScenarios];
    await this.saveScenarios(allScenarios);
    return newScenarios;
  }

  async clearAllScenarios(): Promise<void> {
    await this.saveScenarios([]);
  }

  private async saveScenarios(scenarios: CustomScenario[]): Promise<void> {
    try {
      localStorage.setItem(this.storageKey, JSON.stringify(scenarios));
    } catch (error) {
      console.error('Failed to save scenarios to localStorage:', error);
      throw error;
    }
  }
}

// Firebase implementation
export class FirebaseStorageProvider implements ScenarioStorageProvider {
  private readonly collectionName = 'scenarios';

  constructor(private userId: string) {}

  async getScenarios(): Promise<CustomScenario[]> {
    try {
      const q = query(
        collection(db, this.collectionName),
        where('userId', '==', this.userId),
        orderBy('createdAt', 'desc')
      );

      const querySnapshot = await getDocs(q);
      const scenarios: CustomScenario[] = [];

      querySnapshot.forEach((doc) => {
        const data = doc.data();
        scenarios.push({
          id: doc.id,
          title: data.title,
          description: data.description,
          before: data.before,
          after: data.after,
          remediationActions: data.remediationActions,
          createdAt: data.createdAt.toDate().toISOString(),
          updatedAt: data.updatedAt.toDate().toISOString(),
          isCustom: true,
        });
      });

      return scenarios;
    } catch (error) {
      console.error('Failed to load scenarios from Firebase:', error);
      throw error;
    }
  }

  async addScenario(
    scenario: Omit<CustomScenario, 'id' | 'createdAt' | 'updatedAt' | 'isCustom'>
  ): Promise<CustomScenario> {
    try {
      const now = Timestamp.now();
      const docRef = await addDoc(collection(db, this.collectionName), {
        ...scenario,
        userId: this.userId,
        createdAt: now,
        updatedAt: now,
      });

      return {
        ...scenario,
        id: docRef.id,
        createdAt: now.toDate().toISOString(),
        updatedAt: now.toDate().toISOString(),
        isCustom: true,
      };
    } catch (error) {
      console.error('Failed to add scenario to Firebase:', error);
      throw error;
    }
  }

  async updateScenario(
    id: string,
    updates: Partial<Omit<CustomScenario, 'id' | 'createdAt' | 'isCustom'>>
  ): Promise<CustomScenario> {
    try {
      const docRef = doc(db, this.collectionName, id);
      const now = Timestamp.now();

      await updateDoc(docRef, {
        ...updates,
        updatedAt: now,
      });

      // Get the existing scenario to return the complete updated scenario
      const scenarios = await this.getScenarios();
      const updatedScenario = scenarios.find((s) => s.id === id);

      if (!updatedScenario) {
        throw new Error(`Scenario with id ${id} not found after update`);
      }

      return updatedScenario;
    } catch (error) {
      console.error('Failed to update scenario in Firebase:', error);
      throw error;
    }
  }

  async deleteScenario(id: string): Promise<void> {
    try {
      await deleteDoc(doc(db, this.collectionName, id));
    } catch (error) {
      console.error('Failed to delete scenario from Firebase:', error);
      throw error;
    }
  }

  async importScenarios(importedScenarios: CustomScenario[]): Promise<CustomScenario[]> {
    try {
      const newScenarios: CustomScenario[] = [];

      for (const scenario of importedScenarios) {
        const { id, createdAt, updatedAt, isCustom, ...scenarioData } = scenario;
        const newScenario = await this.addScenario(scenarioData);
        newScenarios.push(newScenario);
      }

      return newScenarios;
    } catch (error) {
      console.error('Failed to import scenarios to Firebase:', error);
      throw error;
    }
  }

  async clearAllScenarios(): Promise<void> {
    try {
      const scenarios = await this.getScenarios();

      for (const scenario of scenarios) {
        await this.deleteScenario(scenario.id);
      }
    } catch (error) {
      console.error('Failed to clear scenarios from Firebase:', error);
      throw error;
    }
  }
}

// Storage configuration
export type StorageType = 'localStorage' | 'firebase';

export function createStorageProvider(type: StorageType, userId?: string): ScenarioStorageProvider {
  switch (type) {
    case 'localStorage':
      return new LocalStorageProvider();
    case 'firebase':
      if (!userId) {
        throw new Error('Firebase storage provider requires a user ID');
      }
      return new FirebaseStorageProvider(userId);
    default:
      throw new Error(`Unknown storage type: ${type}`);
  }
}

// Default storage provider
export const defaultStorageProvider = createStorageProvider('localStorage');
