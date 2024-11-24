import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import axios from 'axios';

const Callback = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [error, setError] = useState(null);

  useEffect(() => {
    const handleCallback = async () => {
      const code = searchParams.get('code');
      const state = searchParams.get('state');
      
      console.log('Received callback with:', { code, state });

      if (!code) {
        const error = searchParams.get('error');
        const errorDescription = searchParams.get('error_description');
        console.error('Auth Error:', error, errorDescription);
        setError(`Authentication error: ${error} - ${errorDescription}`);
        setTimeout(() => navigate('/'), 3000);
        return;
      }

      try {
        console.log('Sending callback request to server...');
        const response = await axios.post('http://localhost:5000/api/auth/callback', 
          { 
            code,
            state,
          },
          { 
            withCredentials: true,
            headers: {
              'Content-Type': 'application/json'
            }
          }
        );

        console.log('Callback response:', response.data);

        // Update authentication status in parent component
        // We'll add this next
        window.dispatchEvent(new Event('auth-success'));
        
        navigate('/');
      } catch (error) {
        console.error('Authentication error:', error.response?.data || error.message);
        setError(error.response?.data?.error || 'Authentication failed');
        setTimeout(() => navigate('/'), 3000);
      }
    };

    handleCallback();
  }, [searchParams, navigate]);

  if (error) {
    return <div className="error-message">{error}</div>;
  }

  return <div>Processing login... Please wait.</div>;
};

export default Callback;