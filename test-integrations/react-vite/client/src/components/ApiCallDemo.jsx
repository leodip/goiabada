import { useState } from 'react';

const ApiCallDemo = ({ title, description, apiCall, buttonText = 'Call API' }) => {
    const [response, setResponse] = useState(null);
    const [error, setError] = useState(null);
    const [isLoading, setIsLoading] = useState(false);

    const handleCall = async () => {
        try {
            setIsLoading(true);
            setError(null);
            const result = await apiCall();
            setResponse(result.data);
        } catch (err) {
            setError(err.response?.data?.error || err.message || 'Request failed');
            setResponse(null);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="api-demo-card">
            <div className="api-demo-header">
                <h3>{title}</h3>
                {description && <p className="api-demo-description">{description}</p>}
            </div>

            <button
                onClick={handleCall}
                disabled={isLoading}
                className="btn btn-primary"
            >
                {isLoading ? 'Loading...' : buttonText}
            </button>

            {response && (
                <div className="api-response success">
                    <h4>Response</h4>
                    <pre>{JSON.stringify(response, null, 2)}</pre>
                </div>
            )}

            {error && (
                <div className="api-response error">
                    <h4>Error</h4>
                    <p>{error}</p>
                </div>
            )}
        </div>
    );
};

export default ApiCallDemo;
