# Goiabada Test Client Application

This application is a client-side (browser-only) test application for Goiabada, an OAuth2 and OIDC auth server. It demonstrates an integration with the auth server using the Authorization Code Flow with PKCE and also serves as a testing and debugging tool.

## Prerequisites

- Python 3.x (to serve the static files)
- A web browser

## Setup Instructions

### 1. Configure the client in Goiabada

Before using this test client, you must configure a client in your Goiabada auth server with the following settings:

| Setting | Value |
|---------|-------|
| **Client type** | Public (no client secret) |
| **Redirect URI** | `http://localhost:8090/callback.html` |
| **Web origin** | `http://localhost:8090` |

The **Web origin** is required for CORS - without it, the browser will block requests to the token endpoint.

### 2. Start the test client

Navigate to this directory and serve the static files using Python's built-in HTTP server:

```bash
python3 -m http.server 8090
```

### 3. Open the test client

Open your browser and navigate to http://localhost:8090

### 4. Configure and test

1. Enter your Goiabada server URL (issuer)
2. Enter the client ID you configured in step 1
3. Click "Prepare request" to build the authorization URL
4. Click "Authorize" to redirect to Goiabada for authentication
5. After authentication, click "Exchange code" to get tokens
6. Optionally test "Refresh token" and "Get userinfo"
