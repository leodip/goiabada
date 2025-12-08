import { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import {
    ACR_LEVELS,
    ACR_LEVEL_DESCRIPTIONS,
    AVAILABLE_SCOPES,
    DEFAULT_SCOPES,
    MAX_AGE_OPTIONS
} from '../config';

const LoginDialog = ({ isOpen, onClose }) => {
    const { login } = useAuth();
    const [selectedAcr, setSelectedAcr] = useState(ACR_LEVELS.LEVEL1);
    const [selectedScopes, setSelectedScopes] = useState(DEFAULT_SCOPES);
    const [selectedMaxAge, setSelectedMaxAge] = useState(null);

    if (!isOpen) return null;

    const handleLogin = () => {
        login({
            acrLevel: selectedAcr,
            scopes: selectedScopes,
            maxAge: selectedMaxAge
        });
    };

    const handleBackdropClick = (e) => {
        if (e.target === e.currentTarget) {
            onClose();
        }
    };

    const handleScopeChange = (scopeValue, checked) => {
        if (checked) {
            setSelectedScopes([...selectedScopes, scopeValue]);
        } else {
            setSelectedScopes(selectedScopes.filter(s => s !== scopeValue));
        }
    };

    return (
        <div className="dialog-backdrop" onClick={handleBackdropClick}>
            <div className="dialog dialog-wide">
                <div className="dialog-header">
                    <h2>Sign in options</h2>
                    <button className="dialog-close" onClick={onClose} aria-label="Close">
                        &times;
                    </button>
                </div>

                <div className="dialog-content">
                    {/* ACR Level Section */}
                    <div className="dialog-section">
                        <h3 className="dialog-section-title">Authentication level (ACR)</h3>
                        <p className="dialog-section-description">
                            Choose the required authentication strength.
                        </p>
                        <div className="acr-options">
                            {Object.entries(ACR_LEVELS).map(([key, value]) => (
                                <label
                                    key={key}
                                    className={`acr-option ${selectedAcr === value ? 'selected' : ''}`}
                                >
                                    <input
                                        type="radio"
                                        name="acr"
                                        value={value}
                                        checked={selectedAcr === value}
                                        onChange={(e) => setSelectedAcr(e.target.value)}
                                    />
                                    <div className="acr-option-content">
                                        <span className="acr-label">
                                            {ACR_LEVEL_DESCRIPTIONS[value].label}
                                        </span>
                                        <span className="acr-description">
                                            {ACR_LEVEL_DESCRIPTIONS[value].description}
                                        </span>
                                    </div>
                                </label>
                            ))}
                        </div>
                    </div>

                    {/* Scopes Section */}
                    <div className="dialog-section">
                        <h3 className="dialog-section-title">Scopes</h3>
                        <p className="dialog-section-description">
                            Select which information to request from the authorization server.
                        </p>
                        <div className="scope-options">
                            {AVAILABLE_SCOPES.map((scope) => (
                                <label
                                    key={scope.value}
                                    className={`scope-option ${selectedScopes.includes(scope.value) ? 'selected' : ''} ${scope.required ? 'required' : ''}`}
                                >
                                    <input
                                        type="checkbox"
                                        checked={selectedScopes.includes(scope.value)}
                                        disabled={scope.required}
                                        onChange={(e) => handleScopeChange(scope.value, e.target.checked)}
                                    />
                                    <div className="scope-option-content">
                                        <span className="scope-label">
                                            {scope.label}
                                            {scope.required && <span className="required-badge">Required</span>}
                                        </span>
                                        <span className="scope-description">{scope.description}</span>
                                    </div>
                                </label>
                            ))}
                        </div>
                    </div>

                    {/* Max Age Section */}
                    <div className="dialog-section">
                        <h3 className="dialog-section-title">Session max age</h3>
                        <p className="dialog-section-description">
                            Control when to require re-authentication.
                        </p>
                        <div className="max-age-options">
                            {MAX_AGE_OPTIONS.map((option) => (
                                <label
                                    key={option.label}
                                    className={`max-age-option ${selectedMaxAge === option.value ? 'selected' : ''}`}
                                >
                                    <input
                                        type="radio"
                                        name="maxAge"
                                        checked={selectedMaxAge === option.value}
                                        onChange={() => setSelectedMaxAge(option.value)}
                                    />
                                    <div className="max-age-option-content">
                                        <span className="max-age-label">{option.label}</span>
                                        <span className="max-age-description">{option.description}</span>
                                    </div>
                                </label>
                            ))}
                        </div>
                    </div>
                </div>

                <div className="dialog-actions">
                    <button className="btn btn-secondary" onClick={onClose}>
                        Cancel
                    </button>
                    <button className="btn btn-primary" onClick={handleLogin}>
                        Continue to Login
                    </button>
                </div>
            </div>
        </div>
    );
};

export default LoginDialog;
