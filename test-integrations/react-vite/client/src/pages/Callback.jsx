import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { authApi } from '../api';

const Callback = () => {
    const [searchParams] = useSearchParams();
    const navigate = useNavigate();
    const [error, setError] = useState(null);
    const [errorDetails, setErrorDetails] = useState(null);
    const [status, setStatus] = useState('Processing login...');

    useEffect(() => {
        const handleCallback = async () => {
            const code = searchParams.get('code');
            const state = searchParams.get('state');

            if (!code) {
                const errorParam = searchParams.get('error');
                const errorDescription = searchParams.get('error_description');
                console.error('Auth Error:', errorParam, errorDescription);
                setError(`Authentication error: ${errorParam}${errorDescription ? ` - ${errorDescription}` : ''}`);
                // Don't auto-redirect so user can see the error
                return;
            }

            try {
                setStatus('Exchanging code for tokens...');
                await authApi.callback(code, state);

                setStatus('Authentication successful! Redirecting...');

                // Dispatch event to trigger auth context refresh
                window.dispatchEvent(new Event('auth-success'));

                // Small delay to show success message
                setTimeout(() => navigate('/'), 500);
            } catch (err) {
                console.error('Authentication error:', err);
                console.error('Error response:', err.response);
                console.error('Error response data:', err.response?.data);

                // Capture full error details
                const errorMessage = err.response?.data?.error || err.message || 'Authentication failed';
                const details = {
                    message: err.message,
                    status: err.response?.status,
                    statusText: err.response?.statusText,
                    data: err.response?.data,
                    url: err.config?.url
                };

                setError(errorMessage);
                setErrorDetails(details);
                // Don't auto-redirect so user can see the error
            }
        };

        handleCallback();
    }, [searchParams, navigate]);

    const handleGoHome = () => {
        navigate('/');
    };

    return (
        <div className="callback-page">
            <div className="callback-card" style={{ maxWidth: error ? '600px' : '400px' }}>
                {error ? (
                    <>
                        <div className="callback-icon error">
                            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <circle cx="12" cy="12" r="10" />
                                <line x1="15" y1="9" x2="9" y2="15" />
                                <line x1="9" y1="9" x2="15" y2="15" />
                            </svg>
                        </div>
                        <h2>Authentication Failed</h2>
                        <p className="error-message" style={{ marginBottom: '1rem' }}>{error}</p>

                        {errorDetails && (
                            <div style={{ textAlign: 'left', marginBottom: '1.5rem' }}>
                                <h4 style={{ marginBottom: '0.5rem', fontSize: '0.875rem' }}>Error Details:</h4>
                                <pre style={{
                                    background: 'var(--color-bg-tertiary)',
                                    padding: '1rem',
                                    borderRadius: '8px',
                                    fontSize: '0.75rem',
                                    overflow: 'auto',
                                    maxHeight: '300px',
                                    textAlign: 'left'
                                }}>
                                    {JSON.stringify(errorDetails, null, 2)}
                                </pre>
                            </div>
                        )}

                        <button onClick={handleGoHome} className="btn btn-primary">
                            Go to Home
                        </button>
                    </>
                ) : (
                    <>
                        <div className="callback-icon loading">
                            <div className="spinner"></div>
                        </div>
                        <h2>{status}</h2>
                        <p className="redirect-notice">Please wait...</p>
                    </>
                )}
            </div>
        </div>
    );
};

export default Callback;
