import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { CVSSVector } from '../types/cvss';
import { mcpThreatClient, initializeMCPClient, isMCPAvailable } from '../services/mcpClient';
import { MCPDebug } from './MCPDebug';
import './ThreatAnalysis.css';

interface ThreatExtractionResult {
  threat_description: string;
  cvss_metrics: CVSSVector;
  base_score: number;
  severity: string;
  extracted_features: string[];
  decision_logic: string;
}

interface BatchResult {
  results: ThreatExtractionResult[];
  statistics: {
    Critical: number;
    High: number;
    Medium: number;
    Low: number;
    None: number;
  };
}

const ThreatAnalysis = React.memo(() => {
  const navigate = useNavigate();
  const [threatDescription, setThreatDescription] = useState('');
  const [batchDescriptions, setBatchDescriptions] = useState<string[]>(['']);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ThreatExtractionResult | null>(null);
  const [batchResults, setBatchResults] = useState<BatchResult | null>(null);
  const [mode, setMode] = useState<'single' | 'batch'>('single');
  const [mcpAvailable, setMcpAvailable] = useState(false);
  const [mcpConnected, setMcpConnected] = useState(false);
  const [showDebug, setShowDebug] = useState(false);

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
    } catch (err) {
      const errorMessage =
        err instanceof Error ? err.message : 'MCP脅威分析中にエラーが発生しました。';
      setError(errorMessage);
    } finally {
      setIsLoading(false);
    }
  };

  const extractBatchCVSS = async () => {
    setIsLoading(true);
    setError(null);
    setBatchResults(null);

    try {
      if (!mcpConnected || !mcpAvailable) {
        throw new Error('MCP接続が必要です。Claude DesktopまたはMCP対応環境で実行してください。');
      }

      const validDescriptions = batchDescriptions.filter((desc) => desc.trim() !== '');

      // Use real MCP client for batch processing
      const mcpBatchResult = await mcpThreatClient.extractCVSSBatch(validDescriptions);
      setBatchResults(mcpBatchResult);
    } catch (err) {
      const errorMessage =
        err instanceof Error ? err.message : 'MCPバッチ処理中にエラーが発生しました。';
      setError(errorMessage);
    } finally {
      setIsLoading(false);
    }
  };

  const navigateToCalculator = (metrics: CVSSVector) => {
    navigate('/calculator', { state: { prefilledMetrics: metrics } });
  };

  const addBatchDescription = () => {
    setBatchDescriptions([...batchDescriptions, '']);
  };

  const updateBatchDescription = (index: number, value: string) => {
    const updated = [...batchDescriptions];
    updated[index] = value;
    setBatchDescriptions(updated);
  };

  const removeBatchDescription = (index: number) => {
    setBatchDescriptions(batchDescriptions.filter((_, i) => i !== index));
  };

  return (
    <div className='threat-analysis-container'>
      <h1>脅威分析によるCVSS自動算出</h1>
      <p className='description'>
        医療機器の脅威説明文を入力すると、自動的にCVSSメトリクスを抽出し、スコアを計算します。
      </p>

      <div className='mcp-status'>
        <h3>MCP接続状態</h3>
        <div className='status-indicators'>
          <div className={`status-item ${mcpAvailable ? 'available' : 'unavailable'}`}>
            <span className='status-label'>MCP利用可能:</span>
            <span className='status-value'>{mcpAvailable ? '✓' : '✗'}</span>
          </div>
          <div className={`status-item ${mcpConnected ? 'connected' : 'disconnected'}`}>
            <span className='status-label'>MCP接続済み:</span>
            <span className='status-value'>{mcpConnected ? '✓' : '✗'}</span>
          </div>
          <div className='status-item current-mode'>
            <span className='status-label'>実行モード:</span>
            <span className='status-value'>
              {mcpConnected && mcpAvailable ? 'MCP接続済み' : 'MCP未接続'}
            </span>
          </div>
          <button
            onClick={() => setShowDebug(!showDebug)}
            className='debug-toggle'
            style={{ marginLeft: '10px', fontSize: '12px', padding: '2px 8px' }}
          >
            {showDebug ? 'デバッグを隠す' : 'デバッグ情報'}
          </button>
        </div>
        {!mcpAvailable && (
          <p className='mcp-note'>
            <strong>注意:</strong> MCP環境が検出されませんでした。 Claude
            DesktopやMCP対応環境で実行すると、med-mcp-threatサーバーを利用した実際のAI脅威分析機能が利用できます。
          </p>
        )}
        {showDebug && <MCPDebug />}
      </div>

      <div className='mode-selector'>
        <button className={mode === 'single' ? 'active' : ''} onClick={() => setMode('single')}>
          単一分析
        </button>
        <button className={mode === 'batch' ? 'active' : ''} onClick={() => setMode('batch')}>
          バッチ分析
        </button>
      </div>

      {mode === 'single' ? (
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
                  <div className={`severity ${result.severity.toLowerCase()}`}>
                    {result.severity}
                  </div>
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

                <button
                  onClick={() => navigateToCalculator(result.cvss_metrics)}
                  className='navigate-button'
                >
                  CVSS計算機で詳細を確認
                </button>
              </div>
            </div>
          )}
        </div>
      ) : (
        <div className='batch-analysis'>
          <div className='input-section'>
            <h2>脅威の説明（複数）</h2>
            {batchDescriptions.map((desc, index) => (
              <div key={`batch-threat-${index}-${desc.slice(0, 10)}`} className='batch-input-row'>
                <textarea
                  value={desc}
                  onChange={(e) => updateBatchDescription(index, e.target.value)}
                  placeholder={`脅威 ${index + 1} の説明を入力...`}
                  rows={2}
                  className='threat-input'
                />
                {batchDescriptions.length > 1 && (
                  <button onClick={() => removeBatchDescription(index)} className='remove-button'>
                    削除
                  </button>
                )}
              </div>
            ))}

            <button onClick={addBatchDescription} className='add-button'>
              + 脅威を追加
            </button>

            <button
              onClick={extractBatchCVSS}
              disabled={
                isLoading ||
                batchDescriptions.every((d) => !d.trim()) ||
                !mcpConnected ||
                !mcpAvailable
              }
              className='analyze-button'
            >
              {isLoading ? '分析中...' : !mcpConnected ? 'MCP接続が必要' : 'バッチ分析を実行'}
            </button>
          </div>

          {error && <div className='error-message'>{error}</div>}

          {batchResults && (
            <div className='result-section'>
              <h2>バッチ分析結果</h2>

              <div className='statistics-card'>
                <h3>重要度別統計:</h3>
                <div className='statistics-grid'>
                  {Object.entries(batchResults.statistics).map(
                    ([severity, count]) =>
                      count > 0 && (
                        <div key={severity} className={`stat-item ${severity.toLowerCase()}`}>
                          <div className='stat-label'>{severity}</div>
                          <div className='stat-value'>{count}</div>
                        </div>
                      )
                  )}
                </div>
              </div>

              <div className='batch-results'>
                {batchResults.results.map((res, index) => (
                  <div
                    key={`result-${index}-${res.base_score}-${res.severity}`}
                    className='result-card compact'
                  >
                    <div className='result-header'>
                      <h4>脅威 {index + 1}</h4>
                      <div className='score-badge'>
                        <span className='score'>{res.base_score.toFixed(1)}</span>
                        <span className={`severity ${res.severity.toLowerCase()}`}>
                          {res.severity}
                        </span>
                      </div>
                    </div>
                    <p className='threat-desc'>{res.threat_description}</p>
                    <button
                      onClick={() => navigateToCalculator(res.cvss_metrics)}
                      className='navigate-button small'
                    >
                      詳細を確認
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      <div className='info-section'>
        <h3>注意事項</h3>
        <ul>
          <li>この機能は日本語の医療機器脅威説明文に最適化されています</li>
          <li>MCP接続が必要です。Claude Desktopでmed-mcp-threatサーバーを設定してください</li>
          <li>自動抽出された値は推定値であり、必要に応じて手動で調整してください</li>
          <li>より正確な評価のためには、CVSS計算機で詳細な設定を行ってください</li>
        </ul>
      </div>
    </div>
  );
});

ThreatAnalysis.displayName = 'ThreatAnalysis';

export default ThreatAnalysis;
