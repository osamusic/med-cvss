import { CVSSVector } from '../types/cvss';

export interface MCPThreatExtractionResult {
  threat_description: string;
  cvss_metrics: CVSSVector;
  base_score: number;
  severity: string;
  extracted_features: string[];
  decision_logic: string;
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
}

/**
 * MCP Client for threat extraction
 * This service communicates with the med-mcp-threat server via the MCP protocol
 */
class MCPThreatExtractionClient {
  private serverName = 'threat-extraction';
  private isConnected = false;

  /**
   * Initialize connection to MCP server
   */
  async connect(): Promise<boolean> {
    try {
      // In a real implementation, this would establish a connection to the MCP server
      // For now, we'll simulate checking if the MCP tools are available
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
   * Check if MCP tools are available
   */
  private async checkMCPAvailability(): Promise<boolean> {
    // Check if we're running in an environment that supports MCP
    // This could be Claude Desktop or another MCP-enabled client
    return typeof (window as any).use_mcp_tool === 'function';
  }

  /**
   * Extract CVSS metrics from a single threat description
   */
  async extractCVSS(threatDescription: string): Promise<MCPThreatExtractionResult> {
    if (!this.isConnected) {
      throw new Error('MCP client is not connected. Please call connect() first.');
    }

    try {
      // Use the MCP tool to extract CVSS metrics
      const result = await (window as any).use_mcp_tool(this.serverName, 'extract_cvss', {
        threat_description: threatDescription,
      });

      // Transform the result to match our interface
      return this.transformMCPResult(result, threatDescription);
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
      // Use the MCP tool for batch processing
      const result = await (window as any).use_mcp_tool(this.serverName, 'extract_cvss_batch', {
        threat_descriptions: threatDescriptions,
      });

      // Transform the batch result
      return this.transformMCPBatchResult(result);
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

    return {
      threat_description: threatDescription,
      cvss_metrics: cvssMetrics,
      base_score: mcpResult.base_score || 0,
      severity: mcpResult.severity || 'None',
      extracted_features: mcpResult.extracted_features || [],
      decision_logic: mcpResult.decision_logic || 'MCP extraction completed',
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
  return typeof (window as any).use_mcp_tool === 'function';
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
