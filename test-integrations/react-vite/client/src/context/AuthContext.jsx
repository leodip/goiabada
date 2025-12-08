import { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import { authApi } from '../api';
import { ACR_LEVELS, DEFAULT_SCOPES } from '../config';

const AuthContext = createContext(null);

// Token refresh threshold - refresh when less than 2 minutes remaining
const REFRESH_THRESHOLD_MS = 2 * 60 * 1000;

export const AuthProvider = ({ children }) => {
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [isLoading, setIsLoading] = useState(true);
    const [userInfo, setUserInfo] = useState(null);
    const [tokens, setTokens] = useState(null);
    const [isRefreshing, setIsRefreshing] = useState(false);
    const [lastRefresh, setLastRefresh] = useState(null);
    const refreshTimerRef = useRef(null);

    const clearAuthState = useCallback(() => {
        setIsAuthenticated(false);
        setUserInfo(null);
        setTokens(null);
        setLastRefresh(null);
        if (refreshTimerRef.current) {
            clearTimeout(refreshTimerRef.current);
            refreshTimerRef.current = null;
        }
    }, []);

    const scheduleTokenRefresh = useCallback((tokenExpiration) => {
        if (refreshTimerRef.current) {
            clearTimeout(refreshTimerRef.current);
        }

        const now = Date.now();
        const expiresAt = tokenExpiration;
        const timeUntilExpiry = expiresAt - now;
        const refreshTime = Math.max(timeUntilExpiry - REFRESH_THRESHOLD_MS, 0);

        if (refreshTime > 0) {
            console.log(`Scheduling token refresh in ${Math.round(refreshTime / 1000)}s`);
            refreshTimerRef.current = setTimeout(async () => {
                await refreshTokens();
            }, refreshTime);
        }
    }, []);

    const refreshTokens = useCallback(async () => {
        if (isRefreshing) return false;

        try {
            setIsRefreshing(true);
            const response = await authApi.refresh();

            if (response.data.success) {
                setTokens(response.data._tokens);
                setLastRefresh(new Date());

                // Update token expiration in userInfo
                setUserInfo(prev => ({
                    ...prev,
                    tokenExpiration: response.data.tokenExpiration
                }));

                // Schedule next refresh
                scheduleTokenRefresh(response.data.tokenExpiration);
                return true;
            }
            return false;
        } catch (error) {
            console.error('Token refresh failed:', error);
            if (error.response?.status === 401) {
                clearAuthState();
            }
            return false;
        } finally {
            setIsRefreshing(false);
        }
    }, [isRefreshing, scheduleTokenRefresh, clearAuthState]);

    const fetchUserInfo = useCallback(async () => {
        try {
            const response = await authApi.getUser();

            setIsAuthenticated(true);
            setUserInfo({
                ...response.data,
                _tokens: undefined // Don't store tokens in userInfo
            });
            setTokens(response.data._tokens);

            // Schedule token refresh
            if (response.data.tokenExpiration) {
                scheduleTokenRefresh(response.data.tokenExpiration);
            }

            return true;
        } catch (error) {
            console.error('Failed to fetch user info:', error);

            if (error.response?.status === 401) {
                clearAuthState();
            }

            return false;
        }
    }, [scheduleTokenRefresh, clearAuthState]);

    const checkAuthStatus = useCallback(async () => {
        try {
            await fetchUserInfo();
        } finally {
            setIsLoading(false);
        }
    }, [fetchUserInfo]);

    useEffect(() => {
        checkAuthStatus();

        const handleAuthSuccess = () => {
            checkAuthStatus();
        };

        window.addEventListener('auth-success', handleAuthSuccess);

        return () => {
            window.removeEventListener('auth-success', handleAuthSuccess);
            if (refreshTimerRef.current) {
                clearTimeout(refreshTimerRef.current);
            }
        };
    }, [checkAuthStatus]);

    const login = useCallback(async (options = {}) => {
        const {
            acrLevel = ACR_LEVELS.LEVEL1,
            scopes = DEFAULT_SCOPES,
            maxAge = null
        } = options;

        try {
            const response = await authApi.getLoginUrl({
                acrValues: acrLevel,
                scopes: scopes.join(' '),
                maxAge
            });
            window.location.href = response.data.url;
        } catch (error) {
            console.error('Failed to get login URL:', error);
        }
    }, []);

    const logout = useCallback(async (useRpInitiatedLogout = true) => {
        try {
            if (useRpInitiatedLogout) {
                // Get the RP-initiated logout URL
                const response = await authApi.getLogoutUrl();

                // Clear local session first
                await authApi.logout();
                clearAuthState();

                // Redirect to auth server logout if URL is available
                if (response.data.url) {
                    window.location.href = response.data.url;
                    return;
                }
            } else {
                // Just clear local session
                await authApi.logout();
                clearAuthState();
            }
        } catch (error) {
            console.error('Logout failed:', error);
            // Clear state anyway
            clearAuthState();
        }
    }, [clearAuthState]);

    return (
        <AuthContext.Provider value={{
            isAuthenticated,
            isLoading,
            userInfo,
            tokens,
            isRefreshing,
            lastRefresh,
            login,
            logout,
            checkAuthStatus,
            refreshTokens
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
