// API configuration from environment variables
export const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000';

// ACR levels supported by Goiabada
export const ACR_LEVELS = {
    LEVEL1: 'urn:goiabada:level1',
    LEVEL2_OPTIONAL: 'urn:goiabada:level2_optional',
    LEVEL2_MANDATORY: 'urn:goiabada:level2_mandatory'
};

export const ACR_LEVEL_DESCRIPTIONS = {
    [ACR_LEVELS.LEVEL1]: {
        label: 'Level 1 - Password only',
        description: 'Single factor authentication with password'
    },
    [ACR_LEVELS.LEVEL2_OPTIONAL]: {
        label: 'Level 2 - Optional MFA',
        description: 'Password + OTP if user has OTP enabled'
    },
    [ACR_LEVELS.LEVEL2_MANDATORY]: {
        label: 'Level 2 - Mandatory MFA',
        description: 'Password + OTP required (user must enroll if not already)'
    }
};

// Available scopes
export const AVAILABLE_SCOPES = [
    { value: 'openid', label: 'openid', description: 'Required for OIDC', required: true },
    { value: 'profile', label: 'profile', description: 'Name and profile info' },
    { value: 'email', label: 'email', description: 'Email address' },
    { value: 'groups', label: 'groups', description: 'Group memberships' },
    { value: 'offline_access', label: 'offline_access', description: 'Refresh token for long-lived sessions' },
    { value: 'backend:admin', label: 'backend:admin', description: 'Access to admin area' }
];

// Default scopes (excluding offline_access by default)
export const DEFAULT_SCOPES = ['openid', 'profile', 'email', 'groups'];

// Max age options (in seconds)
export const MAX_AGE_OPTIONS = [
    { value: null, label: 'No limit', description: 'Use existing session if valid' },
    { value: 0, label: 'Force re-auth', description: 'Always prompt for credentials' },
    { value: 300, label: '5 minutes', description: 'Re-auth if session older than 5 min' },
    { value: 3600, label: '1 hour', description: 'Re-auth if session older than 1 hour' }
];
