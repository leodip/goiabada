# Goiabada Test Client Application

This application serves as a test client for the Goiabada authorization server. It demonstrates the integration of OAuth 2.0 and OpenID Connect (OIDC) protocols with Goiabada, providing a practical example of a client application using these authentication and authorization mechanisms.

## Overview

This test client application showcases:
- OAuth 2.0 authorization code flow
- OpenID Connect authentication
- Token handling (ID tokens, access tokens, and refresh tokens)
- Protected routes with different authentication and scope requirements

## Prerequisites

- Go version 1.22.5 or later

## Configuration

Before running the application, you may want to review and adjust the settings in `config/config.go`. This file contains important configuration parameters such as:

- Client ID and Secret
- OIDC Provider URL
- Redirect URLs
- Default scopes
- Session keys

Feel free to modify these settings to match your Goiabada server configuration or to experiment with different setups.

## Running the Application

To run the application, follow these steps:

1. Ensure you have Go 1.22.5 or later installed on your system.
2. Navigate to the root directory of the project in your terminal.
3. Run the following command:

`go run .`

4. The application will start and listen on the port specified in the configuration (default is 8100).
5. Open a web browser and navigate to `http://localhost:8100` to access the application.

## Usage

- The home page displays the current configuration and any active tokens.
- Use the navigation menu to access different protected routes and test various authentication scenarios.
- The login page allows you to initiate the OAuth 2.0/OIDC authentication process with Goiabada.
- After successful authentication, you can view token information and access protected resources based on your permissions.

## Note

This application is designed for testing and demonstration purposes. Ensure that you're using it in a secure environment, especially when dealing with sensitive information like client secrets.

Feel free to explore the code, modify the configuration, and experiment with different OAuth 2.0 and OIDC features supported by Goiabada.
