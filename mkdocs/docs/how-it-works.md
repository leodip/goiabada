# How it works

## Use cases

Goiabada is useful in two main scenarios:

1. When users need access to specific resources (such as a section of your application or an API) and you want to manage that access.
2. When servers need to access other servers, and you want to set defined permission levels for them.

Let's view those in more detail.

### Users accessing resources

When you have users accessing resources, you basically need to know: who the user is (*authentication*), and whether they're authorized to access that resource (*authorization*).

Goiabada works with two familiar web protocols to fulfill that: OpenID Connect handles the who's who (*authentication*), and OAuth2 takes care of who can do what (*authorization*).

Regardless of your app type (a web app on the server side, a web app using JavaScript, or a mobile native app), the recommended approach is the **Authorization code flow with PKCE**.

The Authorization code flow with PKCE is a secure method for handling user authentication in web applications. It works in two steps: first, the application requests an authorization code from the `/authorize` endpoint. Then, it exchanges this code for an access token, a refresh token, and optionally an ID token at the `/token` endpoint.

PKCE adds an extra layer of security by preventing interception of the authorization code, especially in public clients like mobile or single-page applications.

### Server to server communications

When you have a set of servers working together, and you want to ensure that only the right clients can access resources on a specific server, go for the **Client credentials flow**, with a confidential client.

### Learn more about OAuth2

OAuth2 covers a lot of ground. To delve deeper into it, check out [https://www.oauth.com/](https://www.oauth.com/)

## Clients

A client represents an application that requests access to protected resources.

This access can either be on behalf of a user (using the authorization code flow with PKCE) or for the client itself (using the client credentials flow).

Clients can be created through the admin console or dynamically via the [Dynamic Client Registration](#dynamic-client-registration-rfc-7591) endpoint (RFC 7591).

### Public or confidential clients

Clients can be either public or confidential, depending on whether they can securely store credentials.

**Public clients** are for applications that **cannot** keep secrets confidential:

- **Single-page applications (SPAs)** - JavaScript code runs in the browser where all secrets are visible to users
- **Mobile apps** - APK/IPA files can be decompiled, exposing any embedded secrets
- **Desktop applications** - Binaries can be reverse-engineered to extract credentials

Public clients must use the authorization code flow with PKCE and cannot use client credentials flow.

**Confidential clients** are for applications that **can** securely protect credentials:

- **Server-side web applications** - Backend code runs on servers not accessible to end-users
- **Backend services** - APIs and microservices with secure credential storage
- **Server-to-server integrations** - Services running in controlled environments

Confidential clients can safely store client secrets and use both authorization code flow and client credentials flow.

**Which should you choose?** If your application code runs entirely in the browser or on user devices, you must use a public client. If you have a backend server that handles OAuth flows, use a confidential client for better security.

### Consent required

In OAuth2, the consent process is important for ensuring that users explicitly authorize third-party applications to access their resources.

When the client is affiliated with the same organization as the authorization server and a high level of trust exists, explicit consent is not usually required.

However, for clients from third-party organizations, it's important to configure the client to request user consent. This ensures that users are aware of who is accessing their tokens.

### Default ACR level

ACR stands for "Authentication Context Class Reference." It's a way to specify the level of authentication assurance or the strength of the authentication method used to authenticate the end-user.

Goiabada has 3 levels:

| ACR level | Description | When to use |
| --------- | ----------- | ----------- |
| `urn:goiabada:level1` | Level 1 authentication only (password) | Low-security resources, read-only access |
| `urn:goiabada:level2_optional` | Level 1 with optional 2FA (if enabled by user) | Balanced security, respects user preferences |
| `urn:goiabada:level2_mandatory` | Level 1 with mandatory 2FA | High-security resources, admin operations, financial transactions |

By default, a client comes configured with `urn:goiabada:level2_optional`, which provides a good balance between security and user experience.

You have the flexibility to override the client's default ACR level on a per-authorization basis. For example, if your client has the default `urn:goiabada:level2_optional` but you have a specific resource that requires users to authenticate using two-factor authentication (2FA), you can specify `urn:goiabada:level2_mandatory` in the `acr_values` parameter of the authorization request.

### Redirect URIs

In the Authorization code flow with PKCE, the client application specifies a redirect URI in its authorization request.

After the user grants or denies permission, the authorization server redirects the user back to this specified URI.

It's necessary to pre-configure this URI in the client, and only exact matches are accepted (no wildcards).

### Web origins

If your client application plans to make calls to the `/token`, `/logout` or `/userinfo` endpoints from JavaScript, you must register the URL (origin) of the web application here, to enable Cross-Origin Resource Sharing (CORS) access. Failure to do so will result in CORS blocking the HTTP requests.

### Client permissions

Client permissions are used in server-to-server checks, specifically within the client credentials flow. This is about the permissions granted to the client itself, allowing it to access other resources.

## Resources and permissions

In Goiabada, you have the ability to define both resources and permissions. Each resource can have multiple permissions associated with it. 

You can assign these permissions to users, groups, or clients as needed.

### Scope

When you pair a resource with a permission, it forms a **scope**, both in the authorization request and within the tokens.

**Format:** `resource-identifier:permission-identifier`

**Example:**

If you have:

- A resource with identifier: `product-api`
- A permission with identifier: `delete-product`

The resulting scope will be: `product-api:delete-product`

This scope can then be requested in authorization requests and will appear in access tokens, allowing fine-grained access control to your APIs and resources.

## OpenID Connect scopes

Besides the authorization scopes that are formed by resources and permissions (as explained in the previous section), Goiabada supports typical OpenID Connect scopes. They are:

| OIDC scope | Description |
| --------- | ----------- |
| openid | Will include an `id_token` in the token response, with the subject identifier (`sub` claim) |
| profile | Access to claims: `name`, `family_name`, `given_name`, `middle_name`, `nickname`, `preferred_username`, `profile`, `website`, `gender`, `birthdate`, `zoneinfo`, `locale`, and `updated_at` |
| email | Access to claims: `email`, `email_verified` |
| address | Access to the `address` claim |
| phone | Access to claims: `phone_number` and `phone_number_verified` |
| groups | Access to the list of groups the user belongs to |
| attributes | Access to the attributes assigned to the user by an admin, stored as key-value pairs |
| offline_access | Access to a refresh token of the type `Offline`, allowing the client to obtain a new access token without requiring immediate user interaction |

## User sessions

User sessions facilitate the single sign-on (SSO) functionality of Goiabada. Once a user logs in, a new session starts. If they try to log in again and their session is still good, they don't need to go through the authentication process again.

There are two configurations that are related to the user session:

| Property | Description |
| --------- | ----------- |
| User session idle timeout in seconds | If there is no activity from the user within this timeframe, the session will be terminated. This will look into the `last_accessed` timestamp of the session. |
| User session max lifetime in seconds | The maximum duration a user session can last, irrespective of user activity. This will be checked against the `started` timestamp of the session. |

A user session is bumped (meaning it receives a new `last_accessed` timestamp) in two situations:

1. When a new authorization request completes
2. When a refresh token associated with the session is used to request a new access token

In your authorization request, you have the option to include the `max_age` parameter. This parameter allows you to define the maximum acceptable time (in seconds) since the user's last authentication. For instance, if you add `max_age=120` to the authentication request, it implies that the user needs to re-authenticate if their last authentication was over 120 seconds (2 minutes) ago, regardless of having a valid session. This is useful when the client needs to ensure that the user authenticated within a specific timeframe.

## Token expiration

You can customize the expiration (in seconds) for access tokens and ID tokens on the Settings → Tokens page. These configurations apply globally to all clients. However, if needed, individual clients have the flexibility to override the global settings in their specific client configurations.

The default token expiration is set to 5 minutes. Access tokens are intentionally kept short-lived, for security reasons.

## Refresh tokens

Refresh tokens are used in the authorization code flow with PKCE (in the client credentials flow we don't have refresh tokens). 

Goiabada supports two types of refresh tokens: normal and offline.

Normal tokens are linked to the user session. They can be used to get a new access token, as long as there's an active user session. When a normal refresh token is used, the user session `last_accessed` timestamp is bumped. The expiration time of a normal refresh token is the same as the user session idle timeout (default is 2 hours). If the user session is terminated,  it will automatically invalidate the refresh tokens linked to that session.

Offline refresh tokens are not linked to a user session. They can be used to obtain a new access token even when the user is not actively using the application. Their expiration time is long (defaults to 30 days).

In your authorization request, when you ask for the `offline_access` scope, your refresh token will be classified as `offline`. Otherwise, if you don't include the `offline_access` scope, your refresh token will be considered normal.

### Refresh Token Rotation

Upon each usage of a refresh token, the refresh token passed in to the `/auth/token` endpoint becomes inactive, and a new refresh token is provided in the token response. In other words, a refresh token is a one-time-use token; once used, it must be substituted with the new refresh token obtained from the response.

**Important:** Your client application must store the new refresh token from each response and use it for the next request. Attempting to reuse an old refresh token will fail and may invalidate the entire token chain for security reasons.

## Users and groups

As an administrator of Goiabada, you can create users and configure their properties (profile information, address, phone, email...). You also have the capability to modify their credentials, terminate active user sessions, and revoke consents.

You can assign permissions and attributes to individual users. Attributes are key-value pairs of arbitrary information that can be included in the access token or ID token.

To facilitate user management, you can create groups of users. When you give a permission to a group, it's given to all group members. The same applies to attributes - group attributes will be included for all group members.

When creating an attribute, you can choose to include it either in the access token or the ID token.

## User Self-Registration

When the 'User self-registration' setting is activated, end-users gain the ability to independently register their user accounts using a link on the login form. If this setting is disabled, only administrators can create new user accounts through the admin console.

For user self-registrations, there's an option to require email verification for new accounts. Enabling this ensures that a user account only becomes active after the user clicks a verification link sent to their email. To use this feature, be sure to configure your SMTP settings.

**Note:** This is different from [Dynamic Client Registration](#dynamic-client-registration-rfc-7591), which allows applications (not users) to self-register as OAuth clients.

## Dynamic Client Registration (RFC 7591)

Goiabada supports Dynamic Client Registration according to [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591), allowing applications to self-register as OAuth clients without manual administrator intervention.

**Note:** This is OAuth client registration (for applications), not to be confused with [User Self-Registration](#user-self-registration), which is for end-users creating accounts.

This feature is particularly useful for:

- **MCP (Model Context Protocol) servers** - AI tools and IDE extensions that need OAuth credentials
- **Native desktop applications** - Apps that need unique client credentials per installation
- **Development tools** - CLI tools, testing frameworks, and developer utilities
- **Automated deployments** - CI/CD pipelines that provision OAuth clients automatically

### Enabling Dynamic Client Registration

By default, this feature is disabled for security reasons. To enable it:

1. Navigate to **Settings → Dynamic Client Registration** in the admin console
2. Enable the feature
3. The registration endpoint becomes available at `/connect/register`

### Security Considerations

When enabled, any application can register as a client. Consider these security measures:

- **Limit to trusted networks** - Use firewall rules or reverse proxy to restrict access
- **Monitor registrations** - Regularly audit newly registered clients in the admin console
- **Review client metadata** - Check redirect URIs and other metadata of self-registered clients
- **Disable untrusted clients** - Clients can be disabled through the admin console if needed

### Registration Endpoint

**POST** `/connect/register`

The endpoint accepts client metadata as defined in RFC 7591 and returns client credentials.

For detailed API documentation and examples, see the [RFC 7591 specification](https://datatracker.ietf.org/doc/html/rfc7591).

---

## Endpoints

### Well-known discovery URL

You can find a link to the well-known discovery URL by going to the root of the admin console. The URL will look like this:

`https://demo-authserver.goiabada.dev/.well-known/openid-configuration`

This endpoint will show the capabilities that are supported by Goiabada.

### /auth/authorize (GET)

The authorize endpoint is used to request authorization codes via the browser. This process normally involves authentication of the end-user and giving consent, when required.

| Parameter | Required | Description |
| --------- | -------- | ----------- |
| client_id | ✓ | The client identifier. |
| redirect_uri | ✓ | The redirect URI is the callback entry point of the app. In other words, it's the location where the authorization server sends the user once the `/auth/authorize` process completes. This must exactly match one of the allowed redirect URIs for the client. |
| response_type | ✓ | `code` is the only value supported - for the authorization code flow with PKCE. |
| code_challenge_method | ✓ | `S256` is the only value supported - for a SHA256 hash of the code verifier. |
| code_challenge | ✓ | A random string between 43 and 128 characters long used for PKCE. |
| scope | ✓ | One or more registered scopes, separated by a space character. A registered scope can be either a `resource:permission` or an OIDC scope. Must include `openid` for OpenID Connect flows. See [Scope](#scope) and [OpenID Connect scopes](#openid-connect-scopes). |
| response_mode |  | Optional. Supported values: `query` (default), `fragment` or `form_post`. With `query` the authorization response parameters are encoded in the query string of the `redirect_uri`. With `fragment` they are encoded in the fragment (#). And `form_post` will make the parameters be encoded as HTML form values that are auto-submitted in the browser, via HTTP POST. |
| state |  | Recommended. Any string. Goiabada will echo back the state value on the token response, for CSRF/replay protection. |
| nonce |  | Recommended for OpenID Connect. Any string. Goiabada will echo back the nonce value in the ID token, as a claim, for replay protection. |
| max_age |  | Optional. If the user's authentication timestamp exceeds the max age (in seconds), they will have to re-authenticate. |
| acr_values |  | Optional. Supported values: `urn:goiabada:level1`, `urn:goiabada:level2_optional` or `urn:goiabada:level2_mandatory`. This will override the default ACR level configured in the client for this authorization request. See [Default ACR level](#default-acr-level). |

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

### /auth/logout (GET or POST)

This endpoint enables the client application to initiate a logout. This implementation aligns with the [OpenID Connect RP-Initiated Logout 1.0 protocol](https://openid.net/specs/openid-connect-rpinitiated-1_0.html).

#### Basic logout (no parameters)

**GET /auth/logout** - Displays a logout consent screen, prompting the user to confirm their intention to log out. No redirection occurs.

**POST /auth/logout** - Immediately logs out the user and redirects to the auth server base URL. No redirection to the client application.

#### RP-Initiated Logout (with parameters)

For proper logout with redirection back to your application, use either GET or POST with the following parameters:

| Parameter | Required | Description |
| --------- | -------- | ----------- |
| id_token_hint | ✓ | The previously issued ID token (can be encrypted or unencrypted). |
| post_logout_redirect_uri | ✓ | A redirect URI that must be pre-registered with the client. The user will be redirected here after logout. |
| client_id | Conditional | Required only if `id_token_hint` is encrypted with the client secret. |
| state | Optional | Any arbitrary string that will be echoed back in the redirect. |

#### Response

After successful logout, the user is redirected to the `post_logout_redirect_uri` with the following query parameters:

- `sid` - The session identifier from the ID token
- `state` - The state parameter if provided in the request

Example redirect: `https://your-app.com/logged-out?sid=abc123&state=xyz`

#### Two authentication routes

**Route 1: Unencrypted ID token**
```
id_token_hint (unencrypted JWT) + post_logout_redirect_uri + state (optional)
```

**Route 2: Encrypted ID token (recommended for security)**
```
id_token_hint (encrypted with AES-GCM) + post_logout_redirect_uri + client_id + state (optional)
```

Encrypting the `id_token_hint` (route 2) enhances security by preventing exposure of the ID token in browser history and logs. Without encryption, the unencrypted `id_token_hint` could expose personally identifiable information (PII) and other claims contained in the ID token.

Below are some examples on how to encrypt the id token for the `id_token_hint` parameter. You must URL-encode the resulting base64 string, when sending it as a querystring parameter to `/auth/logout`.

#### .NET C\#

```csharp
private static string AesGcmEncryption(string idTokenUnencrypted, 
    string clientSecret)
{
    var key = new byte[32];
    
    // use the first 32 bytes of the client secret as key
    var keyBytes = Encoding.UTF8.GetBytes(clientSecret);
    Array.Copy(keyBytes, key, Math.Min(keyBytes.Length, key.Length));

    // random nonce
    var nonce = new byte[AesGcm.NonceByteSizes.MaxSize]; // MaxSize = 12
    RandomNumberGenerator.Fill(nonce);

    using var aes = new AesGcm(key);
    var cipherText = new byte[idTokenUnencrypted.Length];
    var tag = new byte[AesGcm.TagByteSizes.MaxSize]; // MaxSize = 16
    aes.Encrypt(nonce, Encoding.UTF8.GetBytes(idTokenUnencrypted), 
        cipherText, tag);

    // concatenate nonce (12 bytes) + ciphertext (? bytes) + tag (16 bytes)
    var encrypted = new byte[nonce.Length + cipherText.Length + tag.Length];
    Array.Copy(nonce, encrypted, nonce.Length);
    Array.Copy(cipherText, 0, encrypted, nonce.Length, cipherText.Length);
    Array.Copy(tag, 0, encrypted, nonce.Length + cipherText.Length, tag.Length);
    
    return Convert.ToBase64String(encrypted);
}
```

#### Go

```go
import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"math"
)

func AesGcmEncryption(idTokenUnencrypted string, clientSecret string) (string, error) {
	key := make([]byte, 32)

	// Use the first 32 bytes of the client secret as key
	keyBytes := []byte(clientSecret)
	copy(key, keyBytes[:int(math.Min(float64(len(keyBytes)), float64(len(key))))])

	// Random nonce
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	cipherText := aesGcm.Seal(nil, nonce, []byte(idTokenUnencrypted), nil)

	// Concatenate nonce (12 bytes) + ciphertext (? bytes) + tag (16 bytes)
	encrypted := make([]byte, len(nonce)+len(cipherText))
	copy(encrypted, nonce)
	copy(encrypted[len(nonce):], cipherText)

	return base64.StdEncoding.EncodeToString(encrypted), nil
}
```

#### NodeJS

```javascript
const crypto = require('crypto');

function aesGcmEncryption(idTokenUnencrypted, clientSecret) {
    const key = Buffer.alloc(32);

    // Use the first 32 bytes of the client secret as the key
    const keyBytes = Buffer.from(clientSecret, 'utf-8');
    keyBytes.copy(key, 0, 0, Math.min(keyBytes.length, key.length));

    // Random nonce
    const nonce = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
    let cipherText = cipher.update(idTokenUnencrypted, 'utf-8', 'base64');
    cipherText += cipher.final('base64');

    const tag = cipher.getAuthTag();

    // Concatenate nonce (12 bytes) + ciphertext (? bytes) + tag (16 bytes)
    const encrypted = Buffer.concat([nonce, Buffer.from(cipherText, 'base64'), tag]);

    return encrypted.toString('base64');
}
```

You can explore the libraries available on your platform and use the same approach as shown here.

### /userinfo (GET or POST)

The UserInfo endpoint is an OpenID Connect standard endpoint used to retrieve identity information about an authenticated user.

#### Authentication

Send a valid access token using the `Authorization` header:

```
Authorization: Bearer <access-token>
```

The endpoint requires the `authserver:userinfo` scope to be present in the access token.

**Automatic scope addition:** When you request any OpenID Connect scope in your authorization request (`openid`, `profile`, `email`, `address`, `phone`, `groups`, or `attributes`), the auth server automatically adds the `authserver:userinfo` scope to the generated access token. This gives your application permission to call the UserInfo endpoint.

You don't need to explicitly include `authserver:userinfo` in your authorization request's `scope` parameter - it's added automatically behind the scenes when OIDC scopes are present.

#### Response

The response is a JSON object containing user claims. The `sub` (subject) claim is always included. Additional claims depend on the scopes in the access token:

| Scope in access token | Claims returned |
| --------------------- | --------------- |
| `profile` | `name`, `given_name`, `middle_name`, `family_name`, `nickname`, `preferred_username`, `profile`, `website`, `gender`, `birthdate`, `zoneinfo`, `locale`, `updated_at` |
| `email` | `email`, `email_verified` |
| `address` | `address` (structured claim) |
| `phone` | `phone_number`, `phone_number_verified` |
| `groups` | `groups` (array of group identifiers configured to be included in ID tokens) |
| `attributes` | `attributes` (map of user and group attributes configured to be included in ID tokens) |

#### Example Response

Request with scopes `profile` and `email`:

```json
{
  "sub": "248289761001",
  "name": "Jane Doe",
  "given_name": "Jane",
  "family_name": "Doe",
  "preferred_username": "j.doe",
  "email": "janedoe@example.com",
  "email_verified": true,
  "profile": "https://auth.example.com/account/profile",
  "updated_at": 1311280970
}
```

#### Error Responses

- **401 Unauthorized** - Missing or invalid access token
- **403 Forbidden** - Access token lacks `authserver:userinfo` scope
- **500 Internal Server Error** - User account is disabled or not found
