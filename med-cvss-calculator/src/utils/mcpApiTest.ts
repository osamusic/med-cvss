/**
 * MCP API Test Utilities
 * Test compatibility with med-mcp-threat server API
 */

export interface APITestResult {
  success: boolean;
  endpoint: string;
  error?: string;
  response?: any;
}

/**
 * Test MCP API endpoints for compatibility
 */
export class MCPAPITester {
  constructor(private baseUrl: string) {}

  /**
   * Test health check endpoint
   */
  async testHealth(): Promise<APITestResult> {
    try {
      const response = await fetch(`${this.baseUrl}/`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        return {
          success: false,
          endpoint: 'GET /',
          error: `HTTP ${response.status}: ${response.statusText}`,
        };
      }

      const data = await response.json();
      return {
        success: true,
        endpoint: 'GET /',
        response: data,
      };
    } catch (error) {
      return {
        success: false,
        endpoint: 'GET /',
        error: `Network error: ${error}`,
      };
    }
  }

  /**
   * Test single threat extraction
   */
  async testExtractCVSS(threatDescription: string): Promise<APITestResult> {
    try {
      const response = await fetch(`${this.baseUrl}/extract_cvss`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          threat_description: threatDescription,
        }),
      });

      if (!response.ok) {
        return {
          success: false,
          endpoint: 'POST /extract_cvss',
          error: `HTTP ${response.status}: ${response.statusText}`,
        };
      }

      const data = await response.json();
      return {
        success: true,
        endpoint: 'POST /extract_cvss',
        response: data,
      };
    } catch (error) {
      return {
        success: false,
        endpoint: 'POST /extract_cvss',
        error: `Network error: ${error}`,
      };
    }
  }

  /**
   * Test batch threat extraction
   */
  async testExtractCVSSBatch(threatDescriptions: string[]): Promise<APITestResult> {
    try {
      const response = await fetch(`${this.baseUrl}/extract_cvss_batch`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          threat_descriptions: threatDescriptions,
        }),
      });

      if (!response.ok) {
        return {
          success: false,
          endpoint: 'POST /extract_cvss_batch',
          error: `HTTP ${response.status}: ${response.statusText}`,
        };
      }

      const data = await response.json();
      return {
        success: true,
        endpoint: 'POST /extract_cvss_batch',
        response: data,
      };
    } catch (error) {
      return {
        success: false,
        endpoint: 'POST /extract_cvss_batch',
        error: `Network error: ${error}`,
      };
    }
  }

  /**
   * Run all API tests
   */
  async runAllTests(): Promise<APITestResult[]> {
    const results: APITestResult[] = [];

    // Test health check
    results.push(await this.testHealth());

    // Test single extraction with sample threat
    const sampleThreat = '外部ネットワークからAPIに未認証アクセスされ、患者データが漏洩した。';
    results.push(await this.testExtractCVSS(sampleThreat));

    // Test batch extraction
    const sampleThreats = [
      '外部ネットワークからAPIに未認証アクセスされ、患者データが漏洩した。',
      '攻撃者がUSBメモリを介して輸液ポンプにマルウェアを仕込み、不正操作を可能にした。',
    ];
    results.push(await this.testExtractCVSSBatch(sampleThreats));

    return results;
  }
}

/**
 * Validate response format matches expected structure
 */
export function validateResponseFormat(response: any, type: 'single' | 'batch'): boolean {
  if (type === 'single') {
    return (
      response &&
      typeof response.threat_description === 'string' &&
      typeof response.cvss_metrics === 'object' &&
      typeof response.base_score === 'number' &&
      typeof response.severity === 'string' &&
      Array.isArray(response.extracted_features) &&
      typeof response.decision_logic === 'string'
    );
  } else if (type === 'batch') {
    return (
      response &&
      Array.isArray(response.results) &&
      typeof response.statistics === 'object' &&
      typeof response.statistics.Critical === 'number' &&
      typeof response.statistics.High === 'number' &&
      typeof response.statistics.Medium === 'number' &&
      typeof response.statistics.Low === 'number' &&
      typeof response.statistics.None === 'number'
    );
  }

  return false;
}