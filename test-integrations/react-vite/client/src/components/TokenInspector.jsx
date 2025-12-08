import { useState } from 'react';
import { useAuth } from '../context/AuthContext';

const TokenInspector = () => {
    const { tokens, userInfo, isRefreshing, lastRefresh, refreshTokens } = useAuth();
    const [activeTab, setActiveTab] = useState('id_token');
    const [showRaw, setShowRaw] = useState(false);

    if (!tokens) {
        return null;
    }

    const formatTimestamp = (timestamp) => {
        if (!timestamp) return 'N/A';
        const date = new Date(timestamp * 1000);
        return date.toLocaleString();
    };

    const getTimeRemaining = () => {
        if (!userInfo?.tokenExpiration) return null;
        const remaining = userInfo.tokenExpiration - Date.now();
        if (remaining <= 0) return 'Expired';

        const minutes = Math.floor(remaining / 60000);
        const seconds = Math.floor((remaining % 60000) / 1000);
        return `${minutes}m ${seconds}s`;
    };

    const renderClaimValue = (key, value) => {
        // Format timestamps (including ones with "lifetime" or "max" in the name)
        const isTimestamp = ['exp', 'iat', 'nbf', 'auth_time'].includes(key) ||
            (typeof value === 'number' && value > 1000000000 && value < 2000000000 &&
             (key.includes('lifetime') || key.includes('max') || key.includes('time')));

        if (isTimestamp && typeof value === 'number') {
            return (
                <span>
                    {value} <span className="claim-formatted">({formatTimestamp(value)})</span>
                </span>
            );
        }

        // Format arrays
        if (Array.isArray(value)) {
            return <span className="claim-array">[{value.join(', ')}]</span>;
        }

        // Format objects
        if (typeof value === 'object' && value !== null) {
            return <pre className="claim-object">{JSON.stringify(value, null, 2)}</pre>;
        }

        return String(value);
    };

    const renderClaims = (payload) => {
        if (!payload) return null;

        const claimGroups = {
            'Standard Claims': ['iss', 'sub', 'aud', 'exp', 'iat', 'nbf', 'jti'],
            'Authentication': ['acr', 'amr', 'auth_time', 'sid', 'nonce'],
            'User Info': ['name', 'given_name', 'family_name', 'email', 'email_verified', 'preferred_username'],
            'Groups & Permissions': ['groups', 'permissions', 'scope'],
            'Other': []
        };

        // Categorize claims
        const categorized = {};
        const usedKeys = new Set();

        Object.entries(claimGroups).forEach(([group, keys]) => {
            categorized[group] = {};
            keys.forEach(key => {
                if (payload[key] !== undefined) {
                    categorized[group][key] = payload[key];
                    usedKeys.add(key);
                }
            });
        });

        // Add uncategorized claims to "Other"
        Object.keys(payload).forEach(key => {
            if (!usedKeys.has(key)) {
                categorized['Other'][key] = payload[key];
            }
        });

        return (
            <div className="claims-container">
                {Object.entries(categorized).map(([group, claims]) => {
                    if (Object.keys(claims).length === 0) return null;
                    return (
                        <div key={group} className="claim-group">
                            <h4 className="claim-group-title">{group}</h4>
                            <div className="claims-list">
                                {Object.entries(claims).map(([key, value]) => (
                                    <div key={key} className="claim-row">
                                        <span className="claim-key">{key}</span>
                                        <span className="claim-value">{renderClaimValue(key, value)}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    );
                })}
            </div>
        );
    };

    const tabs = [
        { id: 'id_token', label: 'ID token' },
        { id: 'access_token', label: 'Access token' },
        { id: 'refresh_token', label: 'Refresh token' }
    ];

    const currentToken = tokens[activeTab];

    return (
        <div className="token-inspector">
            <div className="token-inspector-header">
                <h3>Token inspector</h3>
                <div className="token-status">
                    <span className={`status-indicator ${isRefreshing ? 'refreshing' : 'active'}`}>
                        {isRefreshing ? 'Refreshing...' : 'Active'}
                    </span>
                    {getTimeRemaining() && (
                        <span className="time-remaining">
                            Expires in: {getTimeRemaining()}
                        </span>
                    )}
                </div>
            </div>

            <div className="token-actions">
                <button
                    onClick={refreshTokens}
                    disabled={isRefreshing || !tokens.refresh_token}
                    className="btn btn-secondary btn-sm"
                >
                    {isRefreshing ? 'Refreshing...' : 'Refresh tokens'}
                </button>
                {lastRefresh && (
                    <span className="last-refresh">
                        Last refresh: {lastRefresh.toLocaleTimeString()}
                    </span>
                )}
            </div>

            <div className="token-tabs">
                {tabs.map(tab => (
                    <button
                        key={tab.id}
                        className={`tab-btn ${activeTab === tab.id ? 'active' : ''}`}
                        onClick={() => setActiveTab(tab.id)}
                        disabled={!tokens[tab.id]}
                    >
                        {tab.label}
                        {!tokens[tab.id] && ' (N/A)'}
                    </button>
                ))}
            </div>

            <div className="token-content">
                {currentToken ? (
                    <>
                        <div className="view-toggle">
                            <label className="toggle-label">
                                <input
                                    type="checkbox"
                                    checked={showRaw}
                                    onChange={(e) => setShowRaw(e.target.checked)}
                                />
                                Show raw JWT
                            </label>
                        </div>

                        {showRaw ? (
                            <div className="raw-token">
                                <pre>{currentToken.raw}</pre>
                            </div>
                        ) : (
                            currentToken.payload ? (
                                renderClaims(currentToken.payload)
                            ) : (
                                <p className="token-note">No payload available</p>
                            )
                        )}
                    </>
                ) : (
                    <p className="token-note">No {activeTab.replace('_', ' ')} available</p>
                )}
            </div>
        </div>
    );
};

export default TokenInspector;
