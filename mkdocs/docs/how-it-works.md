# How it works

## Use cases

Goiabada comes in handy in two main situations:

1. When you have users who need to access a resource (an area of your application, or an API)
2. When you have a server that wants to access another server securely

Let's view those in more details.

### Users accessing resources

When you have users accessing resources, you basically need to know: who is the user (*authentication*), and if they're allowed to access that resource (*authorization*).

Goiabada works with two familiar web protocols to fulfil that: OpenID Connect handles the who's who (*authentication*), and OAuth2 takes care of who can do what (*authorization*).

When users are accessing resources, no matter what type of app you may have (like a web app on the server side, a web app using JavaScript, or a mobile native app), the recommended way to go is the **Authorization code flow with PKCE**.

The Authorization code flow with PKCE is a secure method for user authentication in web applications. It involves a two-step process: first, the application requests an authorization code in the `/authorize` endpoint, and then it exchanges this code for an access token, a refresh token, and optionally an id token, using the `/token` endpoint.

PKCE adds an extra layer of security by preventing interception of the authorization code, particularly in public clients like mobile or single-page applications.

### Server to server communications

When you have a set of servers working together, and you want to ensure that only the right clients can access resources on a specific server, go for the **Client credentials flow**, with a confidential client.

### Learn more about OAuth2

OAuth2 covers a lot of ground. To delve deeper into it, check out this link - [https://www.oauth.com/](https://www.oauth.com/)

## Clients

A clients represents an application that requests access to protected resources.

This access can be on behalf of a user (in authorization code flow with PKCE), or for the client itself (in client credentials flow).

### Public or confidential clients

Clients can be public or confidential.

A **public client** is recommended for applications that cannot ensure the confidentiality of their client credentials. This is relevant for JavaScript-only web applications, where keeping a password confidential in JavaScript is not feasible due to its visibility. The same consideration applies to mobile apps, as an APK package can be downloaded and decompiled, exposing any secrets stored within.

A **confidential client** is recommended for applications that can securely maintain the confidentiality of their client credentials. This applies to server-side applications, where the ability to protect and keep secrets confidential is feasible. In contrast to public clients, confidential clients, such as server-side web applications, can safely store sensitive information like passwords without exposing them to potential risks.

### Consent required

In OAuth2, the consent process is vital to ensuring users explicitly authorize third-party applications to access their resources.

Typically, when the client is affiliated with the same organization that owns the authorization server and a high level of trust exists, explicit consent may not be necessary.

However, in the case of a client from a third-party organization, it's crucial to configure the client to request user consent. This ensures users are informed about who is utilizing their tokens, promoting transparency and user awareness.

### Default ACR level

ACR stands for "Authentication Context Class Reference." It's a way to specify the level of authentication assurance or the strength of the authentication method used to authenticate the end-user.

Goiabada has 3 levels:

| ACR level | Description |
| --------- | ----------- |
| `urn:goiabada:pwd` | Password only |
| `urn:goiabada:pwd:otp_ifpossible` | Password with 2fa OTP (if enabled) |
| `urn:goiabada:pwd:otp_mandatory` | Password with mandatory 2fa OTP |

By default, a client comes configured with `urn:goiabada:pwd:otp_ifpossible`.

You have the flexibility to override the client's default ACR level on a per-authorization basis. For instance, if you have a specific resource that requires users to authenticate using a two-factor authentication (2FA) one-time password (OTP), you can specify `urn:goiabada:pwd:otp_mandatory` in the `acr_values` parameter of the authorization request.

### Redirect URIs

In the Authorization code flow with PKCE, the client application specifies a redirect URI in its authorization request.

After the user grants or denies permission, the authorization server redirects the user back to this specified URI.

It's necessary to pre-configure this URI in the client, and only exact matches are accepted (no wildcards are allowed). This helps ensure the security of the authorization process.

### Web origins

If your client application plans to make calls to the `/token` or `/userinfo` endpoints from Javascript, you must register the URL (origin) of the web application here, to enable Cross-Origin Resource Sharing (CORS) access. Failure to do so will result in CORS blocking the HTTP requests.

### Client permissions

Client permissions become relevant in server-to-server exchanges, specifically within the client credentials flow. This is about the permissions granted to the client itself, allowing it to access other resources.

## Resources and permissions

In Goiabada, you have the ability to define both resources and permissions. Each resource can have multiple permissions associated with it. Subsequently, you can assign these permissions to users, groups, or clients as needed.

### Scope

When you pair a resource with a permission, it forms a **scope**, both in the authorization request and within the tokens. For example, if you have a resource identified as `product-api` and a permission identified as `delete-product` the corresponding scope will be represented as `product-api:delete-product`.

## OpenID Connect scopes

Besides the normal authorization scope explained earlier, Goiabada supports typical OpenID Connect scopes. They are:

| OIDC scope | Description |
| --------- | ----------- |
| openid | Will include an **id token** in the token response, with the subject identifier (sub claim) |
| profile | Access to claims: name, family_name, given_name, middle_name, nickname, preferred_username, profile, website, gender, birthdate, zoneinfo, locale, and updated_at |
| email | Access to claims: email, email_verified |
| address | Access to the address claim |
| phone | Access to claims: phone_number and phone_number_verified |
| groups | Access to the list of groups the user belongs to |
| attributes | Access to the attributes assigned to the user by an admin, stored as key-value pairs |
| offline_access | Access to a refresh token of the type 'Offline', allowing the client to obtain a new access token without requiring an immediate interaction |

## User sessions

User sessions facilitate the single sign-on (SSO) functionality of Goiabada. Once a user logs in, a new session starts. If they try to log in again and their session is still good, they don't need to go through the authentication process again.

There are two configurations that are related to the user session:

| Property | Description |
| --------- | ----------- |
| User session idle timeout in seconds | If there is no activity from the user within this timeframe, the session will be terminated. This will look into the `last_accessed` timestamp of the session. |
| User session max lifetime in seconds | The maximum duration a user session can last, irrespective of user activity. This will be checked against the `started` timestamp of the session. |

A user session is bumped (which means, gets a new `last_accessed` timestamp) in two situations:

1. When a new authorization request completes
2. When a refresh token associated with the session is used to request a new access token

In your authorization request, you have the option to include the `max_age` parameter. This parameter allows you to define the maximum acceptable time (in seconds) since the user's last authentication. For instance, if you add `max_age=120` to the authentication request, it implies that the user needs to re-authenticate if their last authentication was over 120 seconds (2 minutes) ago, regardless of having a valid session. This parameter is useful when the client needs to ensure that the user authenticated within a specific timeframe.

## Refresh tokens

Refresh tokens are relevant to the authorization code flow with PKCE (in the client credentials flow we don't have refresh tokens). 

Goiabada supports two types of refresh tokens: normal and offline.

Normal tokens are linked to the user session. They can be used to get a new access token, as long as there's an active user session. When a normal refresh token is used, the user session `last_accessed` timestamp is bumped. The expiration time of a normal refresh token is the same as the user session idle timeout (default is 2 hours). If the user session is terminated,  it will automatically invalidate the refresh tokens linked to that session.

Offline refresh tokens are not linked to a user session. They can be used to obtain a new access token even when the user is not actively using the application. Their expiration time is long (defaults to 30 days).

In your authorization request, when you ask for the `offline_access` scope, your refresh token will be classified as `offline`. Otherwise, if you don't include the `offline_access` scope, your refresh token will be considered normal.

Upon each usage of a refresh token, the refresh token passed in to the `/auth/token` endpoint becomes inactive, and a new refresh token is provided in the token response. In other words, a refresh token is a one-time-use token; once used, it must be substituted with the new refresh token obtained from the response.

## Users and groups

As an administrator of Goiabada you can create users and configure their properties (profile information, address, phone, email...). Also, you have the capability to modify their credentials, terminate active user sessions, and revoke consents.

You can also assign permissions and attributes to individual users. Attributes are key-value pairs or arbitraty information, and can be included in the access token or id token.

To facilitate user management, you can create groups of users. When you give a permission to a group, you give it to all group members. The same applies to attributes - group attributes will be included for all group members.

For better user management, the option to create user groups is available. When a permission is granted to a group, it automatically extends to all members of that group. This principle also holds true for attributes – any attributes configured for a group will be applicable to every member of that group.

## Self registration

When the 'Self registration' setting is activated, users gain the ability to independently register their accounts using a link incorporated into the login form. Conversely, if this setting is disabled, only administrators have the privilege of creating new user accounts.

Within the realm of self-registrations, there is an additional configuration option regarding the verification of the new user's email. Enabling this option ensures that the account becomes active only after the user clicks a link sent via email. To use this feature, it is imperative to configure your SMTP settings.

## Endpoints

### Well-known discovery URL

You can find a link to the well-known discovery URL by going to the root of Goiabada ("/"). 

`https://localhost:8100/.well-known/openid-configuration`

This endpoint will show the capabilities that are supported by Goiabada.

### /auth/authorize (GET)

The authorize endpoint is used to request authorization codes via the browser. This process normally involves authentication of the end-user and giving consent, when required.

Parameters (* are mandatory):

| Parameter | Description |
| --------- | ----------- |
| client_id | The client identifier. |
| redirect_uri | The redirect URI is the callback entry point of the app. In other words, it's the location where the authorization server sends the user once the `/auth/authorize` process completes. This must exactly match one of the allowed redirect URIs for the client. |
| response_type | `code` is the only value supported - for the authorization code flow with PKCE. | 
| code_challenge_method | `S256` is the only value supported - for a SHA256 hash of the code verifier. |
| code_challenge | A random string between 43 and 128 characters long. |
| response_mode | Supported values: `query`, `fragment` or `form_post`. With `query` the authorization response parameters are encoded in the query string of the `redirect_uri`. With `fragment` they are encoded in the fragment (#). And `form_post` will make the parameters be encoded as HTML form values that are auto-submitted in the browser, via HTTP POST. |
| max_age | If the user's authentication timestamp exceeds the max age (in seconds), they will have to re-authenticate |
| acr_values | Supported values are: `urn:goiabada:pwd`, `urn:goiabada:pwd:otp_ifpossible` or `urn:goiabada:pwd:otp_mandatory`. This will override the default ACR level configured in the client for this authorization request. See [Default ACR level](#default-acr-level). |
| state | Any string. Goiabada will echo back the state value on the token response, for CSRF/replay protection. |
| nonce | Any string. Goiabada will echo back the nonce value in the identity token, as a claim, for replay protection. |
| scope | One or more registered scopes, separated by a space character. A registered scope can be either a `resource:permission` or an OIDC scope. See [Scope](#scope) and [OpenID Connect scopes](#openid-connect-scopes).

### /auth/token (POST)

The token endpoint serves the purpose of requesting tokens. This can happen either through the authorization code flow, involving the exchange of an authorization code for tokens, or through the client credentials flow, where a client directly requests tokens.

Parameters:

| Parameter | Description |
| --------- | ----------- |
| grant_type | Supported grant types are `authorization_code` (to exchange an authorization code for tokens), `client_credentials` (for the client credentials flow) or `refresh_token` (to use a refresh token). |
| client_id | The client identifier. |
| client_secret | The client secret, if it's a confidential client. |
| redirect_uri | Required for the `authorization_code` grant type. |
| code | The authorization code. Required for the `authorization_code` grant type. |
| code_verifier | This is the code verifier associated with the PKCE request, initially generated by the app before the authorization request. It represents the original string from which the `code_challenge` was derived. |
| scope | This parameter is used in the `client_credentials` and `refresh_token` grant types. In `client_credentials` grant type, it's a mandatory parameter, and it should encompass one or more registered scopes, separated by a space character. These scopes represent the requested permissions in the format of `resource:permission`. <br /><br />For the `refresh_token` grant type, the scope parameter is optional and serves to restrict the original scope to a more specific and narrower subset. |
| refresh_token | The refresh token, required for the `refresh_token` grant type. |
 
### /userinfo (GET or POST)

The UserInfo endpoint, a component of OpenID Connect, serves the purpose of retrieving identity information about a user.

The caller needs to send a valid access token to be able to access this endpoint. This is done by adding the `Authorization: Bearer token-value-here` header to the HTTP request.

The endpoint validates the presence of the `authserver:userinfo` scope within the access token. If this scope is present, the endpoint responds by providing claims about the user. 

Please note that you don't need to manually request the `authserver:userinfo` scope in the authorization request. Instead, it will be automatically included in the access token whenever any OpenID Connect scope is included in the request.

The specific claims returned by the UserInfo endpoint depend on the OpenID Connect scopes included in the access token. For instance, if the `openid` and `email` scopes are present, the endpoint will return the `sub` (subject) claim from the `openid` scope, as well as the `email` and `email_verified` claims from the email scope.