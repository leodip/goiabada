import { useAuth } from '../context/AuthContext';
import { useState } from 'react';
import axios from 'axios';

const Protected = () => {
  const { userInfo } = useAuth();
  const [apiResponse, setApiResponse] = useState(null);
  const [error, setError] = useState(null);

  const callProtectedApi = async () => {
    try {
      setError(null);
      const response = await axios.get('http://localhost:5000/api/protected/time', {
        withCredentials: true
      });
      setApiResponse(response.data);
    } catch (error) {
      setError(error.response?.data?.error || 'Failed to call protected API');
      console.error('API call failed:', error);
    }
  };

  return (
    <div>
      <h1>Protected Page</h1>
      <p>Welcome {userInfo.name || userInfo.email}!</p>
      
      <div className="api-section">
        <button onClick={callProtectedApi} className="button">
          Call Protected API
        </button>
        
        {apiResponse && (
          <div className="api-response">
            <h3>API Response:</h3>
            <p>Message: {apiResponse.message}</p>
            <p>Timestamp: {apiResponse.timestamp}</p>
          </div>
        )}
        
        {error && (
          <div className="error-message">
            {error}
          </div>
        )}
      </div>

      <div className="user-info">
        <h3>User Info:</h3>
        <pre>{JSON.stringify(userInfo, null, 2)}</pre>
      </div>
    </div>
  );
};

export default Protected;