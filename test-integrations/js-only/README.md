# Goiabada Test Client Application

This application is a client-side (browser-only) test application for Goiabada, an OAuth2 and OIDC auth server. It demonstrates an integration with the auth server using the Authorization Code Flow with PKCE and also serves as a testing and debugging tool.

## Prerequisites

- Python 3.12.4 or later
- A web browser

## Setup Instructions

1. Ensure your Goiabada auth server is configured to accept this application as a public client. Please remember to configure the redirect URI and Web origin, in the auth server.

2. Navigate to the directory containing the static files (index.html, etc.)

3. Serve the static files using Python's built-in HTTP server:

`python3 -m http.server 8090`

This will start a web server on port 8090. You can access the application by navigating to http://localhost:8090 in your web browser.
