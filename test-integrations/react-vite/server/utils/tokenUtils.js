import * as jose from 'jose';
import { getConfig } from '../authConfig.js';
import * as client from 'openid-client';

export async function validateTokensExpiration(tokens) {
  try {
    if (!tokens?.id_token || !tokens?.access_token) {
      return {
        isValid: false,
        error: 'Missing required tokens'
      };
    }

    const idTokenPayload = jose.decodeJwt(tokens.id_token);
    const accessTokenPayload = jose.decodeJwt(tokens.access_token);

    const now = Math.floor(Date.now() / 1000);

    // Check if access token is expired
    if (accessTokenPayload.exp <= now) {
      console.log('Access token expired:', {
        exp: new Date(accessTokenPayload.exp * 1000),
        now: new Date(now * 1000)
      });

      if (!tokens.refresh_token) {
        return {
          isValid: false,
          error: 'Access token expired and no refresh token available'
        };
      }

      return {
        isValid: false,
        canRefresh: true,
        error: 'Token expired'
      };
    }

    return {
      isValid: true,
      idToken: {
        payload: idTokenPayload,
        expiresAt: new Date(idTokenPayload.exp * 1000).toISOString()
      },
      accessToken: {
        payload: accessTokenPayload,
        expiresAt: new Date(accessTokenPayload.exp * 1000).toISOString()
      }
    };
  } catch (error) {
    console.error('Token validation error:', error);
    return {
      isValid: false,
      error: `Token validation failed: ${error.message}`
    };
  }
}

export async function refreshTokens(session) {
  try {
    if (!session?.tokens?.refresh_token) {
      throw new Error('No refresh token available');
    }

    const config = getConfig();
    console.log('Starting token refresh...');

    // Perform token refresh
    const newTokens = await client.refreshTokenGrant(
      config,
      session.tokens.refresh_token
    );

    console.log('Received new tokens:', {
      hasAccessToken: !!newTokens.access_token,
      hasIdToken: !!newTokens.id_token,
      hasRefreshToken: !!newTokens.refresh_token
    });

    // Update session with new tokens
    session.tokens = newTokens;

    // Save session explicitly
    await new Promise((resolve, reject) => {
      session.save((err) => {
        if (err) {
          console.error('Failed to save session with new tokens:', err);
          reject(err);
        } else {
          console.log('Session saved successfully with new tokens');
          resolve();
        }
      });
    });

    return {
      success: true,
      tokens: newTokens
    };
  } catch (error) {
    console.error('Token refresh failed:', error);
    return {
      success: false,
      error: error.message
    };
  }
}

export function checkGroupMembership(idToken, requiredGroup) {
  try {
    if (!idToken) {
      return {
        hasGroup: false,
        error: 'No ID token provided'
      };
    }

    const payload = jose.decodeJwt(idToken);

    if (!payload.groups) {
      return {
        hasGroup: false,
        error: 'No groups claim found in ID token'
      };
    }

    return {
      hasGroup: payload.groups.includes(requiredGroup),
      groups: payload.groups
    };
  } catch (error) {
    console.error('Group membership check failed:', error);
    return {
      hasGroup: false,
      error: `Failed to check group membership: ${error.message}`
    };
  }
}