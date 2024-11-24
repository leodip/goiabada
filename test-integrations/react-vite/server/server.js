import express from 'express';
import cors from 'cors';
import session from 'express-session';
import dotenv from 'dotenv';
import * as client from 'openid-client';
import { initializeClient, getConfig } from './authConfig.js';
import { isAuthenticated, hasRequiredRole } from './middleware/auth.js';
import * as jose from 'jose';

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

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
    origin: 'http://localhost:5173',
    credentials: true
}));
app.use(express.json());
app.use(session({
    secret: 'your-session-secret',
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
            redirect_uri: 'http://localhost:5173/callback',
            scope: 'openid profile email groups',
            code_challenge,
            code_challenge_method: 'S256',
            state
        };

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
        const currentUrl = new URL(`http://localhost:5173/callback?code=${code}&state=${state}`);

        // Get the code verifier from session
        const code_verifier = req.session.code_verifier;
        if (!code_verifier) {
            console.error('No code verifier found in session');
            return res.status(400).json({ error: 'Missing code verifier' });
        }

        // Exchange code for tokens
        const tokens = await client.authorizationCodeGrant(config, currentUrl, {
            pkceCodeVerifier: code_verifier,
            expectedState: state
        });

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
        res.status(400).json({ error: error.message || 'Authentication failed' });
    }
});

app.get('/api/auth/user', isAuthenticated, async (req, res) => {
    if (!req.session.tokens?.id_token) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    try {
        const config = getConfig();
        const userInfoUrl = new URL(`${process.env.ISSUER_URL}/userinfo`);

        const userInfoResponse = await client.fetchProtectedResource(
            config,
            req.session.tokens.access_token,
            userInfoUrl,
            'GET'
        );

        // Decode the ID token to get expiration time
        const idTokenPayload = jose.decodeJwt(req.session.tokens.id_token);
        
        const userInfo = await userInfoResponse.json();
        res.json({
            ...userInfo,
            tokenExpiration: idTokenPayload.exp * 1000 // Convert to milliseconds
        });
    } catch (error) {
        console.error('Failed to get user info:', error);
        res.status(400).json({ error: 'Failed to get user info' });
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

// Protected Routes

// Example of a route that just requires authentication
app.get('/api/protected/time', isAuthenticated, (req, res) => {
    res.json({
        timestamp: new Date().toISOString(),
        message: 'Hello from protected endpoint!',
        userGroups: req.userGroups
    });
});

// Example of a route that requires the 'manager' role
app.get('/api/managers/time', isAuthenticated, hasRequiredRole('manager'), (req, res) => {
    res.json({
        timestamp: new Date().toISOString(),
        message: 'Hello from managers endpoint!',
        userGroups: req.userGroups
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