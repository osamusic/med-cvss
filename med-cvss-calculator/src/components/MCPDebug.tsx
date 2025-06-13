import React, { useEffect, useState } from 'react';
import { mcpThreatClient } from '../services/mcpClient';
import { auth } from '../services/firebase';
import './MCPDebug.css';

interface DebugInfo {
  mode: string;
  serverUrl: string;
  serverName: string;
  isAuthenticated: boolean;
  userEmail: string | null;
  hasToken: boolean;
  mcpAvailable: boolean;
  connectionStatus: string;
  error: string | null;
}

export const MCPDebug: React.FC = () => {
  const [debugInfo, setDebugInfo] = useState<DebugInfo | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const checkMCPStatus = async () => {
      try {
        const serverUrl = process.env.REACT_APP_MCP_SERVER_URL || '';
        const serverName = process.env.REACT_APP_MCP_THREAT_SERVER || 'threat-extraction';
        const mode = serverUrl ? 'HTTP API' : 'Claude Desktop';

        const currentUser = auth.currentUser;
        const isAuthenticated = Boolean(currentUser);
        const userEmail = currentUser?.email || null;
        let hasToken = false;

        if (currentUser) {
          try {
            const token = await currentUser.getIdToken();
            hasToken = Boolean(token);
          } catch (err) {
            console.error('Failed to get token:', err);
          }
        }

        // Check window.use_mcp_tool availability
        const mcpAvailable =
          mode === 'Claude Desktop' ? typeof (window as any).use_mcp_tool === 'function' : true; // For HTTP API, we check via connection

        // Try to connect
        let connectionStatus = 'Not connected';
        let error = null;

        try {
          const connected = await mcpThreatClient.connect();
          connectionStatus = connected ? 'Connected' : 'Failed to connect';
        } catch (err) {
          connectionStatus = 'Connection error';
          error = err instanceof Error ? err.message : String(err);
        }

        setDebugInfo({
          mode,
          serverUrl,
          serverName,
          isAuthenticated,
          userEmail,
          hasToken,
          mcpAvailable,
          connectionStatus,
          error,
        });
      } catch (err) {
        console.error('Debug check failed:', err);
      } finally {
        setIsLoading(false);
      }
    };

    checkMCPStatus();
  }, []);

  const testConnection = async () => {
    setIsLoading(true);
    try {
      // Disconnect and reconnect
      mcpThreatClient.disconnect();
      const connected = await mcpThreatClient.connect();

      setDebugInfo((prev) =>
        prev
          ? {
              ...prev,
              connectionStatus: connected ? 'Connected' : 'Failed to connect',
              error: connected ? null : 'Connection failed',
            }
          : null
      );

      if (connected && debugInfo?.mode === 'HTTP API') {
        // Test authentication with a simple request
        try {
          const result = await mcpThreatClient.extractCVSS('テスト脅威');
          console.log('Test extraction successful:', result);
          alert('MCP接続成功！テスト脅威の分析が完了しました。');
        } catch (err) {
          console.error('Test extraction failed:', err);
          alert(`MCP接続はできましたが、脅威分析に失敗しました: ${err}`);
        }
      }
    } catch (err) {
      console.error('Connection test failed:', err);
      alert(`接続テストに失敗しました: ${err}`);
    } finally {
      setIsLoading(false);
    }
  };

  if (isLoading) {
    return <div className='mcp-debug'>Loading debug info...</div>;
  }

  if (!debugInfo) {
    return <div className='mcp-debug'>Failed to load debug info</div>;
  }

  return (
    <div className='mcp-debug'>
      <h3>MCP Connection Debug Info</h3>
      <table>
        <tbody>
          <tr>
            <td>
              <strong>Mode:</strong>
            </td>
            <td>{debugInfo.mode}</td>
          </tr>
          {debugInfo.mode === 'HTTP API' && (
            <tr>
              <td>
                <strong>Server URL:</strong>
              </td>
              <td>{debugInfo.serverUrl || 'Not set'}</td>
            </tr>
          )}
          {debugInfo.mode === 'Claude Desktop' && (
            <tr>
              <td>
                <strong>Server Name:</strong>
              </td>
              <td>{debugInfo.serverName}</td>
            </tr>
          )}
          <tr>
            <td>
              <strong>Authentication:</strong>
            </td>
            <td>{debugInfo.isAuthenticated ? `Yes (${debugInfo.userEmail})` : 'No'}</td>
          </tr>
          {debugInfo.isAuthenticated && (
            <tr>
              <td>
                <strong>Has Token:</strong>
              </td>
              <td>{debugInfo.hasToken ? 'Yes' : 'No'}</td>
            </tr>
          )}
          {debugInfo.mode === 'Claude Desktop' && (
            <tr>
              <td>
                <strong>MCP Function:</strong>
              </td>
              <td>{debugInfo.mcpAvailable ? 'Available' : 'Not available'}</td>
            </tr>
          )}
          <tr>
            <td>
              <strong>Connection Status:</strong>
            </td>
            <td
              className={
                debugInfo.connectionStatus === 'Connected' ? 'status-connected' : 'status-error'
              }
            >
              {debugInfo.connectionStatus}
            </td>
          </tr>
          {debugInfo.error && (
            <tr>
              <td>
                <strong>Error:</strong>
              </td>
              <td className='error-message'>{debugInfo.error}</td>
            </tr>
          )}
        </tbody>
      </table>

      <button onClick={testConnection} disabled={isLoading} className='test-button'>
        {isLoading ? 'Testing...' : 'Test Connection'}
      </button>

      <div className='debug-tips'>
        <h4>Troubleshooting Tips:</h4>
        {debugInfo.mode === 'HTTP API' && !debugInfo.serverUrl && (
          <p>• Set REACT_APP_MCP_SERVER_URL in .env.local</p>
        )}
        {debugInfo.mode === 'Claude Desktop' && !debugInfo.mcpAvailable && (
          <p>• Ensure Claude Desktop is running with MCP support</p>
        )}
        {!debugInfo.isAuthenticated && <p>• Log in to use MCP features</p>}
        {debugInfo.error?.includes('CORS') && <p>• Check CORS settings on your MCP server</p>}
      </div>
    </div>
  );
};
