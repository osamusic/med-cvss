import { CVSSVector } from '../types/cvss';
import { auth } from './firebase';

export interface MCPThreatExtractionResult {
  threat_description: string;
  cvss_metrics: CVSSVector;
  base_score: number;
  severity: string;
  extracted_features: string[];
  decision_logic: string;
  user?: string; // Firebase UID
}

export interface MCPBatchResult {
  results: MCPThreatExtractionResult[];
  statistics: {
    Critical: number;
    High: number;
    Medium: number;
    Low: number;
    None: number;
  };
  user?: string; // Firebase UID
}

/**
 * MCP Client for threat extraction
 * This service communicates with the med-mcp-threat server via the MCP protocol
 */
class MCPThreatExtractionClient {
  private serverName = process.env.REACT_APP_MCP_THREAT_SERVER || 'threat-extraction';
  private serverUrl = process.env.REACT_APP_MCP_SERVER_URL || '';
  private isConnected = false;
  private useHttpApi = Boolean(process.env.REACT_APP_MCP_SERVER_URL);

  /**
   * Initialize connection to MCP server
   */
  async connect(): Promise<boolean> {
    try {
      const mcpAvailable = await this.checkMCPAvailability();
      this.isConnected = mcpAvailable;
      return mcpAvailable;
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error('Failed to connect to MCP server:', error);
      this.isConnected = false;
      return false;
    }
  }

  /**
   * Get Firebase ID token for authentication
   */
  private async getAuthToken(): Promise<string | null> {
    try {
      // Check if we're in development mode without Firebase
      const isDevelopmentMode =
        process.env.NODE_ENV === 'development' && !process.env.REACT_APP_FIREBASE_API_KEY;

      if (isDevelopmentMode) {
        // Return a mock token for development
        return 'dev-mock-token-123';
      }

      const currentUser = auth.currentUser;
      if (currentUser && typeof currentUser.getIdToken === 'function') {
        return await currentUser.getIdToken();
      }
      return null;
    } catch (error) {
      // eslint-disable-next-line no-console
      console.warn('Failed to get Firebase ID token:', error);
      return null;
    }
  }

  /**
   * Check if MCP tools are available
   */
  private async checkMCPAvailability(): Promise<boolean> {
    if (this.useHttpApi) {
      // Check HTTP API availability
      try {
        const response = await fetch(`${this.serverUrl}/`, {
          method: 'GET',
          headers: {
            'Content-Type': 'application/json',
          },
        });
        return response.ok;
      } catch (error) {
        // eslint-disable-next-line no-console
        console.warn('HTTP API health check failed:', error);
        return false;
      }
    } else {
      // Check if we're running in Claude Desktop environment
      return typeof (window as any).use_mcp_tool === 'function';
    }
  }

  /**
   * Extract CVSS metrics from a single threat description
   */
  async extractCVSS(threatDescription: string): Promise<MCPThreatExtractionResult> {
    if (!this.isConnected) {
      throw new Error('MCP client is not connected. Please call connect() first.');
    }

    try {
      if (this.useHttpApi) {
        // Use HTTP API for threat extraction
        const token = await this.getAuthToken();
        const headers: Record<string, string> = {
          'Content-Type': 'application/json',
        };

        if (token) {
          headers['Authorization'] = `Bearer ${token}`;
        }

        const response = await fetch(`${this.serverUrl}/extract_cvss`, {
          method: 'POST',
          headers,
          body: JSON.stringify({
            threat_description: threatDescription,
          }),
        });

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const result = await response.json();

        return this.transformMCPResult(result, threatDescription);
      } else {
        // Use Claude Desktop MCP tool
        const result = await (window as any).use_mcp_tool(this.serverName, 'extract_cvss', {
          threat_description: threatDescription,
        });

        return this.transformMCPResult(result, threatDescription);
      }
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error('MCP extraction error:', error);
      throw new Error(`Failed to extract CVSS metrics: ${error}`);
    }
  }

  /**
   * Extract CVSS metrics from multiple threat descriptions
   */
  async extractCVSSBatch(threatDescriptions: string[]): Promise<MCPBatchResult> {
    if (!this.isConnected) {
      throw new Error('MCP client is not connected. Please call connect() first.');
    }

    try {
      if (this.useHttpApi) {
        // Use HTTP API for batch processing
        const token = await this.getAuthToken();
        const headers: Record<string, string> = {
          'Content-Type': 'application/json',
        };

        if (token) {
          headers['Authorization'] = `Bearer ${token}`;
        }

        const response = await fetch(`${this.serverUrl}/extract_cvss_batch`, {
          method: 'POST',
          headers,
          body: JSON.stringify({
            threat_descriptions: threatDescriptions,
          }),
        });

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const result = await response.json();

        return this.transformMCPBatchResult(result);
      } else {
        // Use Claude Desktop MCP tool for batch processing
        const result = await (window as any).use_mcp_tool(this.serverName, 'extract_cvss_batch', {
          threat_descriptions: threatDescriptions,
        });

        return this.transformMCPBatchResult(result);
      }
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error('MCP batch extraction error:', error);
      throw new Error(`Failed to extract CVSS metrics in batch: ${error}`);
    }
  }

  /**
   * Transform MCP server result to our interface format
   */
  private transformMCPResult(mcpResult: any, threatDescription: string): MCPThreatExtractionResult {
    // Map MCP result structure to our expected format
    const cvssMetrics: CVSSVector = {};

    // Extract CVSS metrics from MCP result
    if (mcpResult.cvss_metrics) {
      Object.keys(mcpResult.cvss_metrics).forEach((key) => {
        if (mcpResult.cvss_metrics[key] !== undefined) {
          (cvssMetrics as any)[key] = mcpResult.cvss_metrics[key];
        }
      });
    }

    // Handle extracted_features which can be an object or array
    let extractedFeatures: string[] = [];

    if (Array.isArray(mcpResult.extracted_features)) {
      extractedFeatures = mcpResult.extracted_features;
    } else if (mcpResult.extracted_features && typeof mcpResult.extracted_features === 'object') {
      // Convert object to human-readable feature list
      const features = mcpResult.extracted_features;

      if (features.attack_vector) {
        extractedFeatures.push(`攻撃ベクトル: ${features.attack_vector}`);
      }
      if (features.device_type) {
        extractedFeatures.push(`デバイスタイプ: ${features.device_type}`);
      }
      if (features.attack_type) {
        extractedFeatures.push(`攻撃タイプ: ${features.attack_type}`);
      }
      if (features.requires_authentication !== undefined) {
        extractedFeatures.push(`認証要求: ${features.requires_authentication ? '必要' : '不要'}`);
      }
      if (features.requires_user_interaction !== undefined) {
        extractedFeatures.push(
          `ユーザー操作: ${features.requires_user_interaction ? '必要' : '不要'}`
        );
      }
      if (features.asset_category) {
        extractedFeatures.push(`資産カテゴリ: ${features.asset_category}`);
      }
      if (features.data_type && Array.isArray(features.data_type)) {
        extractedFeatures.push(`データタイプ: ${features.data_type.join(', ')}`);
      }
      if (features.impact_type && Array.isArray(features.impact_type)) {
        extractedFeatures.push(`影響タイプ: ${features.impact_type.join(', ')}`);
      }
    }

    // Handle decision_logic from logic_tree_paths if present
    let decisionLogic = mcpResult.decision_logic || 'MCP extraction completed';

    if (mcpResult.logic_tree_paths && typeof mcpResult.logic_tree_paths === 'object') {
      const paths = mcpResult.logic_tree_paths;
      const logicSummary: string[] = [];

      Object.entries(paths).forEach(([metric, info]: [string, any]) => {
        if (info && info.result) {
          logicSummary.push(`${metric}: ${info.result} - ${info.reasoning || ''}`);
        }
      });

      if (logicSummary.length > 0) {
        decisionLogic = logicSummary.join('\n');
      }
    }

    return {
      threat_description: threatDescription,
      cvss_metrics: cvssMetrics,
      base_score: mcpResult.base_score || mcpResult.cvss_metrics?.base_score || 0,
      severity: mcpResult.severity || mcpResult.cvss_metrics?.severity || 'None',
      extracted_features: extractedFeatures,
      decision_logic: decisionLogic,
      user: mcpResult.user, // Firebase UIDを保持
    };
  }

  /**
   * Transform MCP batch result to our interface format
   */
  private transformMCPBatchResult(mcpResult: any): MCPBatchResult {
    const results =
      mcpResult.results?.map((result: any, index: number) =>
        this.transformMCPResult(result, result.threat_description || `脅威 ${index + 1}`)
      ) || [];

    // Calculate statistics if not provided
    let statistics = mcpResult.statistics || { Critical: 0, High: 0, Medium: 0, Low: 0, None: 0 };

    if (!mcpResult.statistics) {
      statistics = results.reduce(
        (acc: any, result: MCPThreatExtractionResult) => {
          acc[result.severity]++;
          return acc;
        },
        { Critical: 0, High: 0, Medium: 0, Low: 0, None: 0 }
      );
    }

    return {
      results,
      statistics,
      user: mcpResult.user, // Firebase UIDを保持
    };
  }

  /**
   * Check if the client is connected to MCP server
   */
  isConnectedToMCP(): boolean {
    return this.isConnected;
  }

  /**
   * Disconnect from MCP server
   */
  disconnect(): void {
    this.isConnected = false;
  }
}

// Singleton instance
export const mcpThreatClient = new MCPThreatExtractionClient();

/**
 * Helper function to check if MCP is available in the current environment
 */
export const isMCPAvailable = (): boolean => {
  const serverUrl = process.env.REACT_APP_MCP_SERVER_URL;

  if (serverUrl) {
    // For HTTP API mode, we assume it's available if URL is configured
    // Actual availability check happens in connect()
    return true;
  } else {
    // For Claude Desktop mode, check for use_mcp_tool function
    return typeof (window as any).use_mcp_tool === 'function';
  }
};

/**
 * Initialize MCP client and return connection status
 */
export const initializeMCPClient = async (): Promise<boolean> => {
  try {
    return await mcpThreatClient.connect();
  } catch (error) {
    // eslint-disable-next-line no-console
    console.warn('MCP client initialization failed:', error);
    return false;
  }
};
