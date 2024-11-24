import * as client from 'openid-client';

let config;

export async function initializeClient() {
  try {
    config = await client.discovery(
      new URL(process.env.ISSUER_URL),
      process.env.CLIENT_ID,
      process.env.CLIENT_SECRET
    );
    console.log('Auth client initialized successfully');
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