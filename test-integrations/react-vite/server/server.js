import express from 'express';
import cors from 'cors';
import session from 'express-session';
import * as client from 'openid-client';
import { initializeClient, getConfig, getExecuteOptions } from './authConfig.js';
import { isAuthenticated, hasRequiredRole, hasRequiredScope } from './middleware/auth.js';
import * as jose from 'jose';

// Note: dotenv.config() is called in authConfig.js to ensure env vars are loaded early

const app = express();
const port = process.env.PORT || 5000;
const clientUrl = process.env.CLIENT_URL || 'http://localhost:5173';

// Initialize auth client
(async () => {
    try {
        await initializeClient();
    } catch (error) {
        console.error('Failed to initialize auth client:', error);
    }
})();

// Middleware
app.use(cors({
    origin: clientUrl,
    credentials: true
}));
app.use(express.json());
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-session-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'lax'
    }
}));

// Auth endpoints
app.get('/api/auth/login-url', async (req, res) => {
    try {
        const config = getConfig();

        // Get parameters from query string
        const acrValues = req.query.acr_values || 'urn:goiabada:level1';
        const scope = req.query.scope || 'openid profile email groups';
        const maxAge = req.query.max_age;

        // Generate PKCE code verifier and challenge
        const code_verifier = client.randomPKCECodeVerifier();
        const code_challenge = await client.calculatePKCECodeChallenge(code_verifier);

        // Generate state
        const state = client.randomState();

        // Store in session
        req.session.code_verifier = code_verifier;
        req.session.state = state;

        // Build authorization URL with proper parameters
        const parameters = {
            redirect_uri: `${clientUrl}/callback`,
            scope,
            code_challenge,
            code_challenge_method: 'S256',
            state,
            acr_values: acrValues
        };

        // Add max_age if specified (including 0 which means force re-auth)
        if (maxAge !== undefined && maxAge !== null && maxAge !== '') {
            parameters.max_age = maxAge;
        }

        const redirectTo = client.buildAuthorizationUrl(config, parameters);

        // Save session explicitly
        await new Promise((resolve, reject) => {
            req.session.save((err) => {
                if (err) reject(err);
                else resolve();
            });
        });

        console.log('Redirecting to:', redirectTo.href);

        res.json({ url: redirectTo.href });
    } catch (error) {
        console.error('Error generating login URL:', error);
        res.status(500).json({ error: 'Failed to generate login URL' });
    }
});

app.post('/api/auth/callback', async (req, res) => {
    try {
        const { code, state } = req.body;

        // Verify state
        if (!state || state !== req.session.state) {
            console.error('State mismatch or missing');
            return res.status(400).json({ error: 'Invalid state' });
        }

        const config = getConfig();
        const currentUrl = new URL(`${clientUrl}/callback?code=${code}&state=${state}`);

        // Get the code verifier from session
        const code_verifier = req.session.code_verifier;
        if (!code_verifier) {
            console.error('No code verifier found in session');
            return res.status(400).json({ error: 'Missing code verifier' });
        }

        // Exchange code for tokens
        const grantOptions = {
            pkceCodeVerifier: code_verifier,
            expectedState: state
        };
        const execOpts = getExecuteOptions();
        if (execOpts) {
            grantOptions.execute = execOpts;
        }
        const tokens = await client.authorizationCodeGrant(config, currentUrl, grantOptions);

        // Store tokens in session
        req.session.tokens = tokens;

        // Save session explicitly
        await new Promise((resolve, reject) => {
            req.session.save((err) => {
                if (err) reject(err);
                else resolve();
            });
        });

        res.json({ success: true });
    } catch (error) {
        console.error('Callback error:', error);

        // Extract the most useful error message from openid-client's nested errors
        const errorCode = error.error || error.cause?.error || error.code;
        const errorDescription = error.error_description
            || error.cause?.error_description
            || error.message
            || 'Authentication failed';

        res.status(400).json({
            error: errorCode,
            error_description: errorDescription
        });
    }
});

app.get('/api/auth/user', isAuthenticated, async (req, res) => {
    if (!req.session.tokens?.id_token) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    try {
        const config = getConfig();
        const userInfoUrl = new URL(`${process.env.ISSUER_URL}/userinfo`);

        // Use fetchProtectedResource for the userinfo endpoint
        // The allowInsecureRequests setting from discovery applies automatically to the config
        const userInfoResponse = await client.fetchProtectedResource(
            config,
            req.session.tokens.access_token,
            userInfoUrl,
            'GET'
        );

        // Decode tokens for inspection
        const idTokenPayload = jose.decodeJwt(req.session.tokens.id_token);
        const accessTokenPayload = jose.decodeJwt(req.session.tokens.access_token);

        const userInfo = await userInfoResponse.json();
        res.json({
            ...userInfo,
            tokenExpiration: idTokenPayload.exp * 1000,
            // Include decoded tokens for the token inspector
            _tokens: {
                id_token: {
                    raw: req.session.tokens.id_token,
                    payload: idTokenPayload
                },
                access_token: {
                    raw: req.session.tokens.access_token,
                    payload: accessTokenPayload
                },
                refresh_token: req.session.tokens.refresh_token ? {
                    raw: req.session.tokens.refresh_token,
                    payload: jose.decodeJwt(req.session.tokens.refresh_token)
                } : null
            }
        });
    } catch (error) {
        console.error('Failed to get user info:', error);
        res.status(400).json({ error: 'Failed to get user info' });
    }
});

// Get logout URL for RP-initiated logout
app.get('/api/auth/logout-url', (req, res) => {
    try {
        if (!req.session.tokens?.id_token) {
            return res.json({ url: null });
        }

        const idToken = req.session.tokens.id_token;
        const postLogoutRedirectUri = `${clientUrl}/`;

        // Build the RP-initiated logout URL
        const logoutUrl = new URL(`${process.env.ISSUER_URL}/auth/logout`);
        logoutUrl.searchParams.set('id_token_hint', idToken);
        logoutUrl.searchParams.set('post_logout_redirect_uri', postLogoutRedirectUri);

        res.json({ url: logoutUrl.href });
    } catch (error) {
        console.error('Error generating logout URL:', error);
        res.status(500).json({ error: 'Failed to generate logout URL' });
    }
});

app.post('/api/auth/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).json({ error: 'Logout failed' });
        }
        res.json({ success: true });
    });
});

// Token refresh endpoint - can be called proactively
app.post('/api/auth/refresh', isAuthenticated, async (req, res) => {
    try {
        if (!req.session.tokens?.refresh_token) {
            return res.status(400).json({ error: 'No refresh token available' });
        }

        const config = getConfig();
        const execOpts3 = getExecuteOptions();
        const refreshOptions = execOpts3 ? { execute: execOpts3 } : undefined;
        const newTokens = await client.refreshTokenGrant(
            config,
            req.session.tokens.refresh_token,
            refreshOptions
        );

        req.session.tokens = newTokens;

        await new Promise((resolve, reject) => {
            req.session.save((err) => {
                if (err) reject(err);
                else resolve();
            });
        });

        const idTokenPayload = jose.decodeJwt(newTokens.id_token);
        const accessTokenPayload = jose.decodeJwt(newTokens.access_token);

        res.json({
            success: true,
            tokenExpiration: idTokenPayload.exp * 1000,
            _tokens: {
                id_token: {
                    raw: newTokens.id_token,
                    payload: idTokenPayload
                },
                access_token: {
                    raw: newTokens.access_token,
                    payload: accessTokenPayload
                },
                refresh_token: newTokens.refresh_token ? {
                    raw: newTokens.refresh_token,
                    payload: jose.decodeJwt(newTokens.refresh_token)
                } : null
            }
        });
    } catch (error) {
        console.error('Token refresh failed:', error);
        res.status(400).json({ error: 'Token refresh failed' });
    }
});

// Protected Routes

// Example of a route that just requires authentication
app.get('/api/protected/time', isAuthenticated, (req, res) => {
    res.json({
        timestamp: new Date().toISOString(),
        message: 'Hello from protected endpoint!',
        userGroups: req.userGroups
    });
});

// Example of a route that requires the 'managers' role
app.get('/api/managers/time', isAuthenticated, hasRequiredRole('managers'), (req, res) => {
    res.json({
        timestamp: new Date().toISOString(),
        message: 'Hello from managers endpoint!',
        userGroups: req.userGroups
    });
});

// Example of a route that requires the 'backend:admin' scope
app.get('/api/admin/info', isAuthenticated, hasRequiredScope('backend:admin'), (req, res) => {
    res.json({
        timestamp: new Date().toISOString(),
        message: 'Hello from admin endpoint!',
        tokenScopes: req.tokenScopes,
        serverInfo: {
            nodeVersion: process.version,
            platform: process.platform,
            uptime: process.uptime()
        }
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// Start server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
    console.log(`Client URL: ${clientUrl}`);
    console.log(`Issuer URL: ${process.env.ISSUER_URL}`);
});

// Handle uncaught exceptions and rejections
process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
    process.exit(1);
});

process.on('unhandledRejection', (err) => {
    console.error('Unhandled Rejection:', err);
    process.exit(1);
});
