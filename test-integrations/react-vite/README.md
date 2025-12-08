# React + Vite OAuth2/OIDC Demo

A sample React application demonstrating OAuth2/OIDC authentication with Goiabada using the Backend-for-Frontend (BFF) pattern.

## Overview

This demo shows how to integrate a React SPA with Goiabada for authentication. It uses a Node.js backend (Express) to handle OAuth flows securely, keeping tokens in server-side sessions rather than exposing them to the browser.

### Features demonstrated

- **Authorization Code flow with PKCE** - Secure authentication flow
- **Protected routes** - Routes that require authentication
- **Group-based access control** - Routes restricted to users in specific groups
- **Scope-based access control** - Routes restricted by access token scopes
- **Token inspection** - View decoded ID, access, and refresh tokens
- **Silent token refresh** - Automatic token refresh before expiration
- **ACR levels** - Step-up authentication with different security levels

## Goiabada server configuration

Before running this demo, configure your Goiabada server with the following:

### 1. Create a client

In the Goiabada admin console, create a new client with these settings:

| Setting | Value |
|---------|-------|
| Client identifier | `react-vite-demo` (or your choice) |
| Description | React Vite demo application |
| Enabled | Yes |
| Consent required | No (or Yes if you want to show consent screen) |
| Authentication method | Confidential client |
| Redirect URIs | `http://localhost:5173/callback` and `http://localhost:5173/` |

After creating the client, note down the **Client ID** and **Client Secret**.

### 2. Create a resource and permission (for scope-based access)

To demonstrate scope-based access control, create a resource with a permission:

1. Go to **Resources** in the admin console
2. Create a new resource:
   - Resource identifier: `backend`
   - Description: Backend API
3. Add a permission to this resource:
   - Permission identifier: `admin`
   - Description: Admin access

This creates the scope `backend:admin` which is used by the `/admin` route.

Now go to **Users with permission** and assign the permission to your test user.

### 3. Create a group (for group-based access)

To demonstrate group-based access control:

1. Go to **Groups** in the admin console
2. Create a new group:
   - Group identifier: `managers`
   - Description: Managers group

### 4. Assign users to the group

1. Go to **Users** → select a user → **Groups**
2. Add the user to the `managers` group

## Application configuration

### Server configuration

Create a `.env` file in the `server/` directory:

```env
# Goiabada server URL
ISSUER_URL=http://localhost:8080

# Client credentials (from Goiabada)
CLIENT_ID=react-vite-demo
CLIENT_SECRET=your-client-secret-here

# Session secret (generate a random string)
SESSION_SECRET=your-random-session-secret

# Server port
PORT=5000

# Client URL (frontend)
CLIENT_URL=http://localhost:5173
```

### Client configuration

Create a `.env` file in the `client/` directory (optional):

```env
# Backend API URL
VITE_API_URL=http://localhost:5000
```

## Running the application

### Install dependencies

```bash
# Install server dependencies
cd server
npm install

# Install client dependencies
cd ../client
npm install
```

### Start the application

In two separate terminals:

```bash
# Terminal 1: Start the backend server
cd server
npm run dev

# Terminal 2: Start the frontend
cd client
npm run dev
```

The application will be available at `http://localhost:5173`.

