import * as client from 'openid-client';
import dotenv from 'dotenv';

// Load env vars early so they're available
dotenv.config();

let config;

// Check if we should allow HTTP (for local development)
function shouldAllowInsecureRequests() {
    return process.env.NODE_ENV !== 'production' &&
        process.env.ISSUER_URL?.startsWith('http://');
}

export async function initializeClient() {
    try {
        const issuerUrl = new URL(process.env.ISSUER_URL);
        const allowInsecure = shouldAllowInsecureRequests();

        // For local development with HTTP, we need to pass execute options
        if (allowInsecure) {
            console.log('Warning: Using HTTP for OIDC discovery (development mode)');
            config = await client.discovery(
                issuerUrl,
                process.env.CLIENT_ID,
                process.env.CLIENT_SECRET,
                undefined, // clientAuth
                {
                    execute: [client.allowInsecureRequests]
                }
            );
        } else {
            config = await client.discovery(
                issuerUrl,
                process.env.CLIENT_ID,
                process.env.CLIENT_SECRET
            );
        }

        console.log('Auth client initialized successfully');
        console.log('Issuer:', config.serverMetadata().issuer);
    } catch (error) {
        console.error('Failed to initialize auth client:', error);
        throw error;
    }
}

export function getConfig() {
    if (!config) {
        throw new Error('Auth client not initialized');
    }
    return config;
}

// Export function for use in other modules
export function getExecuteOptions() {
    if (shouldAllowInsecureRequests()) {
        return [client.allowInsecureRequests];
    }
    return undefined;
}
