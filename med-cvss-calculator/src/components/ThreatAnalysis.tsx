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

      const available = isMCPAvailable();
      if (!cancelled) {
        setMcpAvailable(available);
      }

      if (available && !cancelled) {
        try {
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
    };

    initializeMCP();

    // Cleanup function to prevent state updates after unmount
    return () => {
      cancelled = true;
    };
  }, []);

  const extractCVSS = async () => {
    setIsLoading(true);
    setError(null);
    setResult(null);

    try {
      if (!mcpConnected || !mcpAvailable) {
        throw new Error('MCP接続が必要です。Claude DesktopまたはMCP対応環境で実行してください。');
      }

      // Use real MCP client for threat extraction
      const mcpResult = await mcpThreatClient.extractCVSS(threatDescription);
      setResult(mcpResult);

      // Save to localStorage for sync with Calculator
      if (mcpResult && mcpResult.cvss_metrics) {
        const threatAssessmentData = {
          timestamp: new Date().toISOString(),
          threatDescription: mcpResult.threat_description,
          cvssMetrics: mcpResult.cvss_metrics,
          baseScore: mcpResult.base_score,
          severity: mcpResult.severity,
          extractedFeatures: mcpResult.extracted_features,
          decisionLogic: mcpResult.decision_logic,
        };
        localStorage.setItem('latestThreatAssessment', JSON.stringify(threatAssessmentData));

        // Also save just the CVSS metrics for direct calculator sync
        localStorage.setItem('prefilledCVSSMetrics', JSON.stringify(mcpResult.cvss_metrics));
      }
    } catch (err) {
      const errorMessage =
        err instanceof Error ? err.message : 'MCP脅威分析中にエラーが発生しました。';
      setError(errorMessage);
    } finally {
      setIsLoading(false);
    }
  };

  const navigateToCalculator = () => {
    // localStorage is already set in extractCVSS, just navigate
    navigate('/calculator');
  };

  return (
    <div className='threat-analysis-container'>
      <h1>脅威分析によるCVSS自動算出</h1>
      <p className='description'>
        医療機器の脅威説明文を入力すると、AIが自動的にCVSSメトリクスを抽出し、セキュリティスコアを計算します。
      </p>

      <div className='single-analysis'>
        <div className='input-section'>
          <h2>脅威の説明</h2>
          <textarea
            value={threatDescription}
            onChange={(e) => setThreatDescription(e.target.value)}
            placeholder='例: 外部ネットワークからAPIに未認証アクセスされ、患者データが漏洩した。'
            rows={4}
            className='threat-input'
          />

          <div className='sample-threats'>
            <h3>サンプル脅威:</h3>
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
            {isLoading ? '分析中...' : !mcpConnected ? 'MCP接続が必要' : 'CVSSを分析'}
          </button>
        </div>

        {error && <div className='error-message'>{error}</div>}

        {result && (
          <div className='result-section'>
            <h2>分析結果</h2>
            <div className='result-card'>
              <div className='score-display'>
                <div className='score-value'>{result.base_score.toFixed(1)}</div>
                <div className={`severity ${result.severity.toLowerCase()}`}>{result.severity}</div>
              </div>

              <div className='metrics-display'>
                <h3>抽出されたCVSSメトリクス:</h3>
                <ul>
                  {Object.entries(result.cvss_metrics).map(
                    ([key, value]) =>
                      key !== 'version' && (
                        <li key={key}>
                          <strong>{key}:</strong> {value}
                        </li>
                      )
                  )}
                </ul>
              </div>

              <div className='features-display'>
                <h3>識別された特徴:</h3>
                <ul>
                  {result.extracted_features.map((feature, index) => (
                    <li key={index}>{feature}</li>
                  ))}
                </ul>
              </div>

              <div className='logic-display'>
                <h3>判定ロジック:</h3>
                <p>{result.decision_logic}</p>
              </div>

              <button onClick={navigateToCalculator} className='navigate-button'>
                CVSS計算機で詳細を確認
              </button>
            </div>
          </div>
        )}
      </div>

      <div className='info-section'>
        <h3>注意事項</h3>
        <ul>
          <li>この機能は日本語の医療機器脅威説明文に特化したAI分析を行います</li>
          <li>
            自動抽出されたCVSSメトリクスは推定値です。必要に応じて計算機で手動調整してください
          </li>
          <li>分析結果は参考情報として活用し、最終的な評価は専門知識に基づいて判断してください</li>
          <li>複雑な脅威シナリオの場合は、CVSS計算機での詳細設定をお勧めします</li>
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
