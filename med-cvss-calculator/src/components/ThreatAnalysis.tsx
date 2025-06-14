import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { CVSSVector } from '../types/cvss';
import { mcpThreatClient, initializeMCPClient, isMCPAvailable } from '../services/mcpClient';
import './ThreatAnalysis.css';

interface ThreatExtractionResult {
  threat_description: string;
  cvss_metrics: CVSSVector;
  base_score: number;
  severity: string;
  extracted_features: string[];
  decision_logic: string;
}

const ThreatAnalysis = React.memo(() => {
  const navigate = useNavigate();
  const [threatDescription, setThreatDescription] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ThreatExtractionResult | null>(null);
  const [mcpAvailable, setMcpAvailable] = useState(false);
  const [mcpConnected, setMcpConnected] = useState(false);
  const [mcpInitializing, setMcpInitializing] = useState(true);
  const [analysisStep, setAnalysisStep] = useState(0);

  // Sample threat descriptions for users to try
  const sampleThreats = {
    network: '外部ネットワークからAPIに未認証アクセスされ、患者データが漏洩した。',
    physical: '攻撃者がUSBメモリを介して輸液ポンプにマルウェアを仕込み、不正操作を可能にした。',
    firmware: '手術ロボットのファームウェアを改ざんすることで、手術中の誤動作を引き起こした。',
    bluetooth:
      'Bluetooth接続を介して心臓ペースメーカーの設定を不正に変更できる脆弱性が発見された。',
  };

  // Initialize MCP client on component mount with proper cleanup
  useEffect(() => {
    let cancelled = false;

    const initializeMCP = async () => {
      if (cancelled) return;

      // Show initialization loading
      setMcpInitializing(true);

      // Add small delay to show initialization animation
      await new Promise((resolve) => setTimeout(resolve, 800));

      const available = isMCPAvailable();
      if (!cancelled) {
        setMcpAvailable(available);
      }

      if (available && !cancelled) {
        try {
          // Add delay for connection animation
          await new Promise((resolve) => setTimeout(resolve, 1200));

          const connected = await initializeMCPClient();
          if (!cancelled) {
            setMcpConnected(connected);
          }
        } catch (error) {
          // eslint-disable-next-line no-console
          console.warn('MCP initialization failed:', error);
          if (!cancelled) {
            setMcpConnected(false);
          }
        }
      }

      // Complete initialization
      if (!cancelled) {
        setMcpInitializing(false);
      }
    };

    initializeMCP();

    // Cleanup function to prevent state updates after unmount
    return () => {
      cancelled = true;
    };
  }, []);

  // Restore previous assessment results on component mount
  useEffect(() => {
    const savedAssessment = localStorage.getItem('latestThreatAssessment');
    if (savedAssessment) {
      try {
        const assessmentData = JSON.parse(savedAssessment);
        // Restore the result state - the metrics are already in calculator format
        const restoredResult: ThreatExtractionResult = {
          threat_description: assessmentData.threatDescription,
          cvss_metrics: assessmentData.cvssMetrics, // These are already converted
          base_score: assessmentData.baseScore,
          severity: assessmentData.severity,
          extracted_features: assessmentData.extractedFeatures,
          decision_logic: assessmentData.decisionLogic,
        };
        setResult(restoredResult);
        // Also restore the threat description
        setThreatDescription(assessmentData.threatDescription);
      } catch (error) {
        // Silently ignore parse errors
      }
    }
  }, []);

  const extractCVSS = async () => {
    setIsLoading(true);
    setError(null);
    setResult(null);
    setAnalysisStep(0);

    try {
      if (!mcpConnected || !mcpAvailable) {
        throw new Error('MCP接続が必要です。Claude DesktopまたはMCP対応環境で実行してください。');
      }

      // Step 1: Analyzing threat document
      setAnalysisStep(1);
      await new Promise((resolve) => setTimeout(resolve, 800));

      // Step 2: Extracting CVSS metrics
      setAnalysisStep(2);
      await new Promise((resolve) => setTimeout(resolve, 600));

      // Step 3: Calculating security score
      setAnalysisStep(3);

      // Use real MCP client for threat extraction
      const mcpResult = await mcpThreatClient.extractCVSS(threatDescription);

      // Brief pause to show completion
      await new Promise((resolve) => setTimeout(resolve, 400));

      setResult(mcpResult);

      // Save to localStorage for sync with Calculator
      if (mcpResult && mcpResult.cvss_metrics) {
        // Convert metrics to calculator format
        const calculatorMetrics = mapThreatMetricsToCalculator(mcpResult.cvss_metrics);

        const threatAssessmentData = {
          timestamp: new Date().toISOString(),
          threatDescription: mcpResult.threat_description,
          cvssMetrics: calculatorMetrics, // Save converted metrics
          baseScore: mcpResult.base_score,
          severity: mcpResult.severity,
          extractedFeatures: mcpResult.extracted_features,
          decisionLogic: mcpResult.decision_logic,
        };
        localStorage.setItem('latestThreatAssessment', JSON.stringify(threatAssessmentData));

        // Also save just the CVSS metrics for direct calculator sync
        localStorage.setItem('prefilledCVSSMetrics', JSON.stringify(calculatorMetrics));
      }
    } catch (err) {
      const errorMessage =
        err instanceof Error ? err.message : 'MCP脅威分析中にエラーが発生しました。';
      setError(errorMessage);
    } finally {
      setIsLoading(false);
      setAnalysisStep(0);
    }
  };

  // Convert descriptive metric names to CVSS abbreviations
  const mapThreatMetricsToCalculator = (metrics: any): CVSSVector => {
    const mapping: { [key: string]: string } = {
      attack_vector: 'AV',
      attack_complexity: 'AC',
      privileges_required: 'PR',
      user_interaction: 'UI',
      scope: 'S',
      confidentiality_impact: 'C',
      integrity_impact: 'I',
      availability_impact: 'A',
      // Temporal metrics
      exploit_code_maturity: 'E',
      remediation_level: 'RL',
      report_confidence: 'RC',
    };

    const mappedMetrics: CVSSVector = {};

    // Handle both formats - if it's already in the correct format, use as-is
    // If it's in descriptive format, convert it
    Object.entries(metrics).forEach(([key, value]) => {
      if (mapping[key]) {
        // Convert descriptive name to abbreviation
        mappedMetrics[mapping[key] as keyof CVSSVector] = value as string;
      } else if (['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A', 'E', 'RL', 'RC'].includes(key)) {
        // Already in correct format
        mappedMetrics[key as keyof CVSSVector] = value as string;
      }
    });

    return mappedMetrics;
  };

  // Convert CVSS abbreviations to readable names for display
  const getDisplayName = (key: string): string => {
    const displayMapping: { [key: string]: string } = {
      AV: 'Attack Vector',
      AC: 'Attack Complexity',
      PR: 'Privileges Required',
      UI: 'User Interaction',
      S: 'Scope',
      C: 'Confidentiality Impact',
      I: 'Integrity Impact',
      A: 'Availability Impact',
      E: 'Exploit Code Maturity',
      RL: 'Remediation Level',
      RC: 'Report Confidence',
      // Original descriptive names (fallback)
      attack_vector: 'Attack Vector',
      attack_complexity: 'Attack Complexity',
      privileges_required: 'Privileges Required',
      user_interaction: 'User Interaction',
      scope: 'Scope',
      confidentiality_impact: 'Confidentiality Impact',
      integrity_impact: 'Integrity Impact',
      availability_impact: 'Availability Impact',
    };

    return displayMapping[key] || key;
  };

  const navigateToCalculator = () => {
    // Ensure metrics are saved to localStorage before navigation
    if (result && result.cvss_metrics) {
      // Convert metrics to calculator format
      const calculatorMetrics = mapThreatMetricsToCalculator(result.cvss_metrics);
      localStorage.setItem('prefilledCVSSMetrics', JSON.stringify(calculatorMetrics));

      // Also save the full assessment data for persistence
      const threatAssessmentData = {
        timestamp: new Date().toISOString(),
        threatDescription: result.threat_description,
        cvssMetrics: calculatorMetrics, // Save the converted metrics
        baseScore: result.base_score,
        severity: result.severity,
        extractedFeatures: result.extracted_features,
        decisionLogic: result.decision_logic,
      };
      localStorage.setItem('latestThreatAssessment', JSON.stringify(threatAssessmentData));
    }
    navigate('/calculator');
  };

  const clearAssessment = () => {
    setResult(null);
    setThreatDescription('');
    setError(null);
    // Clear localStorage data
    localStorage.removeItem('latestThreatAssessment');
    localStorage.removeItem('prefilledCVSSMetrics');
  };

  return (
    <div className='threat-analysis-container'>
      <h1>AI脅威インテリジェンス</h1>
      <p className='description'>
        次世代AIが医療機器セキュリティ脅威を瞬時に解析し、精密なCVSSリスクスコアを算出します。
      </p>

      <div className='single-analysis'>
        <div className='input-section'>
          <h2>セキュリティ脅威の詳細</h2>
          <textarea
            value={threatDescription}
            onChange={(e) => setThreatDescription(e.target.value)}
            placeholder='医療機器に対するセキュリティ脅威を詳しく記述してください...'
            rows={4}
            className='threat-input'
          />

          <div className='sample-threats'>
            <h3>脅威シナリオ例:</h3>
            <div className='sample-buttons'>
              {Object.entries(sampleThreats).map(([key, threat]) => (
                <button
                  key={key}
                  onClick={() => setThreatDescription(threat)}
                  className='sample-button'
                >
                  {key === 'network' && 'ネットワーク攻撃'}
                  {key === 'physical' && '物理的攻撃'}
                  {key === 'firmware' && 'ファームウェア改ざん'}
                  {key === 'bluetooth' && 'Bluetooth脆弱性'}
                </button>
              ))}
            </div>
          </div>

          <button
            onClick={extractCVSS}
            disabled={isLoading || !threatDescription.trim() || !mcpConnected || !mcpAvailable}
            className='analyze-button'
          >
            {isLoading ? 'AI解析中...' : !mcpConnected ? 'AI接続が必要' : '脅威を解析'}
          </button>
        </div>

        {error && <div className='error-message'>{error}</div>}

        {mcpInitializing && (
          <div className='mcp-initialization-loading'>
            <div className='loading-header'>
              <div className='ai-icon'>🔗</div>
              <h2>AI システム初期化中...</h2>
            </div>

            <div className='loading-animation'>
              <div className='connection-network'>
                <div className='server-node'></div>
                <div className='connection-lines'>
                  <div className='connection-line line-1'></div>
                  <div className='connection-line line-2'></div>
                  <div className='connection-line line-3'></div>
                </div>
                <div className='client-node'></div>
              </div>
            </div>

            <div className='initialization-steps'>
              <div className='init-step active'>
                <div className='step-indicator'></div>
                <span>AIエンジン起動中</span>
              </div>
              <div className={`init-step ${mcpAvailable ? 'active' : ''}`}>
                <div className='step-indicator'></div>
                <span>接続プロトコル確立中</span>
              </div>
              <div className={`init-step ${mcpConnected ? 'active' : ''}`}>
                <div className='step-indicator'></div>
                <span>脅威解析モジュール準備中</span>
              </div>
            </div>

            <div className='loading-message'>
              <p>MedScore.ai の高度なAI脅威解析システムを準備しています...</p>
              <div className='progress-dots'>
                <span></span>
                <span></span>
                <span></span>
              </div>
            </div>
          </div>
        )}

        {isLoading && (
          <div className='ai-analysis-loading'>
            <div className='loading-header'>
              <div className='ai-icon'>🤖</div>
              <h2>AI脅威分析中...</h2>
            </div>

            <div className='loading-animation'>
              <div className='neural-network'>
                <div className='node node-1'></div>
                <div className='node node-2'></div>
                <div className='node node-3'></div>
                <div className='node node-4'></div>
                <div className='connection connection-1'></div>
                <div className='connection connection-2'></div>
                <div className='connection connection-3'></div>
              </div>
            </div>

            <div className='analysis-steps'>
              <div
                className={`step ${analysisStep >= 1 ? 'active' : ''} ${analysisStep > 1 ? 'completed' : ''}`}
              >
                <div className='step-indicator'></div>
                <span>脅威文書を解析中</span>
              </div>
              <div
                className={`step ${analysisStep >= 2 ? 'active' : ''} ${analysisStep > 2 ? 'completed' : ''}`}
              >
                <div className='step-indicator'></div>
                <span>CVSSメトリクスを抽出中</span>
              </div>
              <div className={`step ${analysisStep >= 3 ? 'active' : ''}`}>
                <div className='step-indicator'></div>
                <span>セキュリティスコアを計算中</span>
              </div>
            </div>

            <div className='loading-message'>
              <p>医療機器セキュリティのエキスパートAIが脅威を詳細分析しています...</p>
              <div className='progress-dots'>
                <span></span>
                <span></span>
                <span></span>
              </div>
            </div>
          </div>
        )}

        {result && (
          <div className='result-section'>
            <h2>AI脅威解析レポート</h2>
            <div className='result-card'>
              <div className='score-display'>
                <div className='score-value'>{result.base_score.toFixed(1)}</div>
                <div className={`severity ${result.severity.toLowerCase()}`}>{result.severity}</div>
              </div>

              <div className='metrics-display'>
                <h3>検出されたリスク要素:</h3>
                <ul>
                  {Object.entries(result.cvss_metrics).map(
                    ([key, value]) =>
                      key !== 'version' && (
                        <li key={key}>
                          <strong>
                            {getDisplayName(key)} ({key}):
                          </strong>{' '}
                          {value}
                        </li>
                      )
                  )}
                </ul>
              </div>

              <div className='features-display'>
                <h3>脅威の特徴:</h3>
                <ul>
                  {result.extracted_features.map((feature, index) => (
                    <li key={index}>{feature}</li>
                  ))}
                </ul>
              </div>

              <div className='logic-display'>
                <h3>AI解析プロセス:</h3>
                <p>{result.decision_logic}</p>
              </div>

              <div className='result-actions'>
                <button onClick={navigateToCalculator} className='navigate-button'>
                  詳細分析へ移動
                </button>
                <button onClick={clearAssessment} className='clear-assessment-button'>
                  結果をクリア
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      <div className='info-section'>
        <h3>利用上の注意</h3>
        <ul>
          <li>日本語の医療機器セキュリティ脅威に特化したAI解析エンジンを使用</li>
          <li>AI解析結果は推定値のため、必要に応じて詳細分析で手動調整を推奨</li>
          <li>最終的なリスク評価は専門知識に基づく総合的判断を行ってください</li>
          <li>複雑な脅威シナリオには詳細分析モードでの精密設定を推奨</li>
        </ul>
      </div>

      {/* MCP接続状態を小さく下部に表示 */}
      <div className='mcp-status-footer'>
        <details className='mcp-details'>
          <summary className='mcp-summary'>
            AI接続状態: {mcpConnected && mcpAvailable ? '✓ 接続済み' : '⚠ 未接続'}
          </summary>
          <div className='status-indicators-small'>
            <div className={`status-item-small ${mcpAvailable ? 'available' : 'unavailable'}`}>
              MCP利用可能: {mcpAvailable ? '✓' : '✗'}
            </div>
            <div className={`status-item-small ${mcpConnected ? 'connected' : 'disconnected'}`}>
              MCP接続済み: {mcpConnected ? '✓' : '✗'}
            </div>
            {!mcpAvailable && (
              <p className='mcp-note-small'>
                Claude
                Desktopでmed-mcp-threatサーバーを設定すると、高度なAI脅威分析機能を利用できます。
              </p>
            )}
          </div>
        </details>
      </div>
    </div>
  );
});

ThreatAnalysis.displayName = 'ThreatAnalysis';

export default ThreatAnalysis;
