import { createContext, useContext, useState, useEffect } from 'react';
import axios from 'axios';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [userInfo, setUserInfo] = useState(null);

  const fetchUserInfo = async () => {
    try {
      const response = await axios.get('http://localhost:5000/api/auth/user', { 
        withCredentials: true 
      });
      
      setIsAuthenticated(true);
      setUserInfo({
        ...response.data,        
      });
      return true;
    } catch (error) {
      console.error('Failed to fetch user info:', error);
      
      if (error.response?.status === 401) {
        setIsAuthenticated(false);
        setUserInfo(null);
      }
      
      return false;
    }
  };

  const checkAuthStatus = async () => {
    try {
      await fetchUserInfo();
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    checkAuthStatus();

    const handleAuthSuccess = () => {
      checkAuthStatus();
    };

    window.addEventListener('auth-success', handleAuthSuccess);
    
    return () => {
      window.removeEventListener('auth-success', handleAuthSuccess);
    };
  }, []);

  const login = async () => {
    try {
      const response = await axios.get('http://localhost:5000/api/auth/login-url', {
        withCredentials: true
      });
      window.location.href = response.data.url;
    } catch (error) {
      console.error('Failed to get login URL:', error);
    }
  };

  const logout = async () => {
    try {
      await axios.post('http://localhost:5000/api/auth/logout', {}, {
        withCredentials: true
      });
    } catch (error) {
      console.error('Logout failed:', error);
    } finally {
      setIsAuthenticated(false);
      setUserInfo(null);
    }
  };

  return (
    <AuthContext.Provider value={{ 
      isAuthenticated, 
      isLoading, 
      userInfo, 
      login, 
      logout,
      checkAuthStatus,
    }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};