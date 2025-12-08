import axios from 'axios';
import { API_URL } from './config';

// Create axios instance with default config
const api = axios.create({
    baseURL: API_URL,
    withCredentials: true,
    headers: {
        'Content-Type': 'application/json'
    }
});

// Auth API
export const authApi = {
    getLoginUrl: ({ acrValues, scopes, maxAge }) =>
        api.get('/api/auth/login-url', {
            params: {
                acr_values: acrValues,
                scope: scopes,
                max_age: maxAge
            }
        }),

    callback: (code, state) =>
        api.post('/api/auth/callback', { code, state }),

    getUser: () =>
        api.get('/api/auth/user'),

    getLogoutUrl: () =>
        api.get('/api/auth/logout-url'),

    logout: () =>
        api.post('/api/auth/logout'),

    refresh: () =>
        api.post('/api/auth/refresh')
};

// Protected API
export const protectedApi = {
    getTime: () =>
        api.get('/api/protected/time'),

    getManagersTime: () =>
        api.get('/api/managers/time'),

    getAdminInfo: () =>
        api.get('/api/admin/info')
};

export default api;
