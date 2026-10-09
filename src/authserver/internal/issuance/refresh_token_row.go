package issuance

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/uuid"
	"github.com/leodip/goiabada/core/errs"
)

// grantIsOffline reports whether an authorization-code grant is offline, from the
// AUTHORIZED scope rather than whatever a later request asked for. Mirrors the branch
// generateRefreshToken uses to choose the token type, so the two cannot disagree.
func grantIsOffline(authorizedScope string, sessionIdentifier string) bool {
	return oidc.HasOfflineAccessScope(authorizedScope) ||
		sessionIdentifier == ""
}

// generateRefreshToken signs a refresh token for a code-descended grant and inserts its row.
//
// tx is the transaction the row is inserted in and the session read behind the max lifetime runs
// in, nil for a grant that runs in none. A rotation hands over its own, so the child commits with
// the claim on its parent and the check of the family's revocation record (#132, #437).
func (t *TokenIssuer) generateRefreshToken(ctx context.Context, tx *sql.Tx, settings *record.Settings, code *record.Code, scope string,
	now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string, refreshToken *record.RefreshToken) (string, int64, error) {

	claims := make(jwt.MapClaims)

	jti := uuid.New()
	claims["iss"] = settings.Issuer
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()
	claims["jti"] = jti
	claims["aud"] = settings.Issuer
	claims["sub"] = code.User.Subject

	// Use Offline type if the offline_access scope was granted, or if no session identifier
	// exists (e.g. ROPC, which creates no browser session). In both cases the refresh token
	// cannot be bound to a user session. Shared with the access token's sid decision through
	// grantIsOffline, so the two cannot disagree about what "offline" means.
	if grantIsOffline(scope, code.SessionIdentifier) {
		// offline refresh token (not related to user session)
		claims["typ"] = TokenTypeOffline.String()

		exp, err := t.getRefreshTokenExpiration(TokenTypeOffline, now, settings, &code.Client)
		if err != nil {
			return "", 0, err
		}

		maxLifetime, err := t.getRefreshTokenMaxLifetime(ctx, tx, TokenTypeOffline, now, settings,
			&code.Client, code.SessionIdentifier)
		if err != nil {
			return "", 0, err
		}
		if refreshToken != nil {
			// if we are refreshing a refresh token, we need to use the max lifetime of the original refresh token
			maxLifetime = refreshToken.MaxLifetime.Time.Unix()
		}
		claims["offline_access_max_lifetime"] = maxLifetime

		if exp < maxLifetime {
			claims["exp"] = exp
		} else {
			claims["exp"] = maxLifetime
		}

	} else {
		// normal refresh token (associated with user session)
		claims["typ"] = TokenTypeRefresh.String()
		claims["sid"] = code.SessionIdentifier

		exp, err := t.getRefreshTokenExpiration(TokenTypeRefresh, now, settings, &code.Client)
		if err != nil {
			return "", 0, err
		}

		maxLifetime, err := t.getRefreshTokenMaxLifetime(ctx, tx, TokenTypeRefresh, now, settings, &code.Client, code.SessionIdentifier)
		if err != nil {
			return "", 0, err
		}

		if exp < maxLifetime {
			claims["exp"] = exp
		} else {
			claims["exp"] = maxLifetime
		}
	}
	claims["scope"] = scope

	// save 1st refresh token
	refreshTokenEntity := &record.RefreshToken{
		RefreshTokenJti:  jti,
		IssuedAt:         sql.NullTime{Time: now, Valid: true},
		ExpiresAt:        sql.NullTime{Time: time.Unix(claims["exp"].(int64), 0), Valid: true},
		CodeId:           sql.NullInt64{Int64: code.Id, Valid: true},
		RefreshTokenType: claims["typ"].(string),
		Scope:            claims["scope"].(string),
		Revoked:          false,
	}

	if refreshToken != nil {
		refreshTokenEntity.PreviousRefreshTokenJti = refreshToken.RefreshTokenJti
		refreshTokenEntity.FirstRefreshTokenJti = refreshToken.FirstRefreshTokenJti
		// Copied from the PARENT, never re-read from the code or the user. The parent may
		// have been promoted while the code was not, and reading the user's current value
		// would let an old grant launder itself into a new generation (#106 rule 5).
		refreshTokenEntity.AuthStateGeneration = refreshToken.AuthStateGeneration
	} else {
		// first refresh token issued
		refreshTokenEntity.FirstRefreshTokenJti = jti
		refreshTokenEntity.AuthStateGeneration = code.AuthStateGeneration
	}

	// Store either max lifetime (for Offline type) or session identifier (for Refresh type)
	if claims["typ"].(string) == TokenTypeOffline.String() {
		t := time.Unix(claims["offline_access_max_lifetime"].(int64), 0)
		refreshTokenEntity.MaxLifetime = sql.NullTime{Time: t, Valid: true}
	} else {
		refreshTokenEntity.SessionIdentifier = claims["sid"].(string)
	}
	err := t.database.CreateRefreshToken(ctx, tx, refreshTokenEntity)
	if err != nil {
		return "", 0, err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyIdentifier
	rt, err := token.SignedString(signingKey)
	if err != nil {
		return "", 0, errs.Wrap(err, "unable to sign refresh_token")
	}
	refreshExpiresIn := claims["exp"].(int64) - now.Unix()

	return rt, refreshExpiresIn, nil
}

func (t *TokenIssuer) getRefreshTokenExpiration(refreshTokenType TokenType, now time.Time, settings *record.Settings,
	client *record.Client) (int64, error) {
	switch refreshTokenType {
	case TokenTypeOffline:
		refreshTokenExpirationInSeconds := settings.RefreshTokenOfflineIdleTimeoutInSeconds
		if client.RefreshTokenOfflineIdleTimeoutInSeconds > 0 {
			refreshTokenExpirationInSeconds = client.RefreshTokenOfflineIdleTimeoutInSeconds
		}
		exp := now.Add(time.Second * time.Duration(refreshTokenExpirationInSeconds)).Unix()
		return exp, nil
	case TokenTypeRefresh:
		refreshTokenExpirationInSeconds := settings.UserSessionIdleTimeoutInSeconds
		exp := now.Add(time.Second * time.Duration(refreshTokenExpirationInSeconds)).Unix()
		return exp, nil
	}
	return 0, errs.Errorf("invalid refresh token type: %v", refreshTokenType)
}

// getRefreshTokenMaxLifetime is the instant a grant's refresh tokens stop being redeemable. A
// session-bound token reads the session it is bound to, on tx when the caller holds one: sqlitedb
// has one connection, so a read on nil waits on the connection the caller's transaction holds
// until the context expires (#139, #437).
func (t *TokenIssuer) getRefreshTokenMaxLifetime(ctx context.Context, tx *sql.Tx, refreshTokenType TokenType, now time.Time, settings *record.Settings,
	client *record.Client, sessionIdentifier string) (int64, error) {
	switch refreshTokenType {
	case TokenTypeOffline:
		maxLifetimeInSeconds := settings.RefreshTokenOfflineMaxLifetimeInSeconds
		if client.RefreshTokenOfflineMaxLifetimeInSeconds > 0 {
			maxLifetimeInSeconds = client.RefreshTokenOfflineMaxLifetimeInSeconds
		}
		maxLifetime := now.Add(time.Second * time.Duration(maxLifetimeInSeconds)).Unix()
		return maxLifetime, nil
	case TokenTypeRefresh:
		userSession, err := t.database.GetUserSessionBySessionIdentifier(ctx, tx, sessionIdentifier)
		if err != nil {
			return 0, err
		}
		if userSession == nil {
			// The session backing this Refresh token no longer exists (e.g. it was
			// concurrently torn down). Fail cleanly instead of dereferencing nil.
			return 0, errs.Errorf("user session %q not found while computing refresh token max lifetime", sessionIdentifier)
		}
		maxLifetime := userSession.Started.Add(
			time.Second * time.Duration(settings.UserSessionMaxLifetimeInSeconds)).Unix()
		return maxLifetime, nil
	}
	return 0, errs.Errorf("invalid refresh token type: %v", refreshTokenType)
}

// generateRefreshTokenForROPC creates a refresh token specifically for ROPC flow.
// Unlike auth code flow, ROPC tokens store UserId and ClientId directly on the RefreshToken
// instead of referencing a Code entity.
func (t *TokenIssuer) generateRefreshTokenForROPC(ctx context.Context, tx *sql.Tx, settings *record.Settings, input *ROPCGrantInput, scope string,
	now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string, previousRefreshToken *record.RefreshToken) (string, int64, error) {

	claims := make(jwt.MapClaims)

	jti := uuid.New()
	claims["iss"] = settings.Issuer
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()
	claims["jti"] = jti
	claims["aud"] = settings.Issuer
	claims["sub"] = input.User.Subject

	// ROPC tokens are always Offline type since there's no browser session
	// (The user authenticates directly with username/password via API)
	claims["typ"] = TokenTypeOffline.String()

	exp, err := t.getRefreshTokenExpiration(TokenTypeOffline, now, settings, input.Client)
	if err != nil {
		return "", 0, err
	}

	maxLifetime := t.getRefreshTokenMaxLifetimeForROPC(now, settings, input.Client)
	if previousRefreshToken != nil {
		// if we are refreshing a refresh token, we need to use the max lifetime of the original refresh token
		maxLifetime = previousRefreshToken.MaxLifetime.Time.Unix()
	}
	claims["offline_access_max_lifetime"] = maxLifetime

	if exp < maxLifetime {
		claims["exp"] = exp
	} else {
		claims["exp"] = maxLifetime
	}

	claims["scope"] = scope

	// Create refresh token entity with direct UserId and ClientId (no Code reference)
	refreshTokenEntity := &record.RefreshToken{
		RefreshTokenJti:  jti,
		IssuedAt:         sql.NullTime{Time: now, Valid: true},
		ExpiresAt:        sql.NullTime{Time: time.Unix(claims["exp"].(int64), 0), Valid: true},
		UserId:           sql.NullInt64{Int64: input.User.Id, Valid: true},
		ClientId:         sql.NullInt64{Int64: input.Client.Id, Valid: true},
		RefreshTokenType: claims["typ"].(string),
		Scope:            claims["scope"].(string),
		Revoked:          false,
		MaxLifetime:      sql.NullTime{Time: time.Unix(maxLifetime, 0), Valid: true},
	}

	if previousRefreshToken != nil {
		refreshTokenEntity.PreviousRefreshTokenJti = previousRefreshToken.RefreshTokenJti
		refreshTokenEntity.FirstRefreshTokenJti = previousRefreshToken.FirstRefreshTokenJti
		// From the PARENT. The refresh path reloads the user, so reading input.User here
		// would stamp the current generation onto a grant authenticated under an older one
		// (#106 rule 5 and decision 13).
		refreshTokenEntity.AuthStateGeneration = previousRefreshToken.AuthStateGeneration
		// From the PARENT too: the password was checked once, when the family began (#125).
		refreshTokenEntity.AuthenticatedAt = previousRefreshToken.AuthenticatedAt
	} else {
		// first refresh token issued
		refreshTokenEntity.FirstRefreshTokenJti = jti
		// The User snapshot the password validation returned, not a reload.
		refreshTokenEntity.AuthStateGeneration = input.User.AuthStateGeneration
		// The password grant's own instant, which its access and ID tokens carry too.
		refreshTokenEntity.AuthenticatedAt = sql.NullTime{Time: input.AuthenticatedAt, Valid: true}
	}

	err = t.database.CreateRefreshToken(ctx, tx, refreshTokenEntity)
	if err != nil {
		return "", 0, err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyIdentifier
	rt, err := token.SignedString(signingKey)
	if err != nil {
		return "", 0, errs.Wrap(err, "unable to sign refresh_token")
	}
	refreshExpiresIn := claims["exp"].(int64) - now.Unix()

	return rt, refreshExpiresIn, nil
}

// getRefreshTokenMaxLifetimeForROPC calculates max lifetime for ROPC refresh tokens.
// ROPC tokens don't have user sessions, so we use the offline access max lifetime settings.
func (t *TokenIssuer) getRefreshTokenMaxLifetimeForROPC(now time.Time, settings *record.Settings, client *record.Client) int64 {
	// ROPC always uses offline access settings since there's no browser session
	maxLifetimeInSeconds := settings.RefreshTokenOfflineMaxLifetimeInSeconds
	if client.RefreshTokenOfflineMaxLifetimeInSeconds > 0 {
		maxLifetimeInSeconds = client.RefreshTokenOfflineMaxLifetimeInSeconds
	}
	return now.Add(time.Second * time.Duration(maxLifetimeInSeconds)).Unix()
}
