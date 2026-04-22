// Package authfirebase implements sdk.IdentityProvider using Firebase Auth.
//
// Usage:
//
//	provider, err := authfirebase.New(ctx, authfirebase.Config{
//	    ProjectID: "my-project",
//	    Redis:     redisClient,
//	})
//	k.SetIdentityProvider(provider)
package authfirebase

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	fb "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"github.com/redis/go-redis/v9"
	"go.edgescale.dev/kernel/sdk"
	"google.golang.org/api/option"
)

// Config holds the configuration for the Firebase identity provider.
type Config struct {
	// ProjectID is the Firebase project ID (required).
	ProjectID string

	// CredentialsFile is an optional path to a service account JSON file.
	// If empty, the SDK uses the GOOGLE_APPLICATION_CREDENTIALS env var
	// or Application Default Credentials (ADC).
	CredentialsFile string

	// CredentialsJSON is optional raw service account JSON bytes.
	// Takes precedence over CredentialsFile if both are set.
	CredentialsJSON []byte

	// Redis is the Redis client used for token revocation tracking.
	// Required for single-device logout support.
	Redis *redis.Client
}

// Provider implements sdk.IdentityProvider using Firebase Auth.
// It validates Firebase ID tokens and supports per-token revocation
// via Redis and full-session revocation via the Firebase Admin SDK.
type Provider struct {
	auth  *auth.Client
	redis *redis.Client
}

// Compile-time interface checks.
var _ sdk.IdentityProvider = (*Provider)(nil)
var _ sdk.TokenRevoker = (*Provider)(nil)

// New creates a new Firebase identity provider.
// It initialises the Firebase Admin SDK and returns a Provider ready for use
// with kernel.SetIdentityProvider().
func New(ctx context.Context, cfg Config) (*Provider, error) {
	if cfg.ProjectID == "" {
		return nil, fmt.Errorf("authfirebase: project ID is required")
	}
	if cfg.Redis == nil {
		return nil, fmt.Errorf("authfirebase: redis client is required for token revocation")
	}

	var opts []option.ClientOption
	if len(cfg.CredentialsJSON) > 0 {
		opts = append(opts, option.WithCredentialsJSON(cfg.CredentialsJSON))
	} else if cfg.CredentialsFile != "" {
		opts = append(opts, option.WithCredentialsFile(cfg.CredentialsFile))
	}

	app, err := fb.NewApp(ctx, &fb.Config{
		ProjectID: cfg.ProjectID,
	}, opts...)
	if err != nil {
		return nil, fmt.Errorf("authfirebase: init firebase app: %w", err)
	}

	authClient, err := app.Auth(ctx)
	if err != nil {
		return nil, fmt.Errorf("authfirebase: init auth client: %w", err)
	}

	return &Provider{
		auth:  authClient,
		redis: cfg.Redis,
	}, nil
}

// Authenticate extracts a Bearer token from the Authorization header,
// checks the local Redis revocation list, and verifies the token
// via the Firebase Admin SDK.
//
// When used inside an IdentityProviderChain with issuer-based routing,
// the chain only calls this provider when the JWT's iss claim matches.
// ErrNoCredentials is mostly a safeguard for standalone usage.
func (p *Provider) Authenticate(ctx context.Context, headers http.Header) (*sdk.Identity, error) {
	header := headers.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return nil, sdk.ErrNoCredentials
	}

	token := strings.TrimPrefix(header, "Bearer ")

	if p.isRevoked(ctx, token) {
		return nil, fmt.Errorf("authfirebase: token has been revoked")
	}

	decoded, err := p.auth.VerifyIDToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("authfirebase: verify token: %w", err)
	}

	identity := mapToken(decoded)
	identity.Kind = sdk.IdentityKindUser
	identity.RawCredential = token
	return identity, nil
}

// mapToken converts a Firebase decoded token into the canonical sdk.Identity.
func mapToken(t *auth.Token) *sdk.Identity {
	identity := &sdk.Identity{
		Subject:      t.UID,
		Provider:     "firebase",
		SignInMethod: t.Firebase.SignInProvider,
		Claims:       t.Claims,
		ExpiresAt:    time.Unix(t.Expires, 0),
	}

	switch t.Firebase.SignInProvider {
	case "phone":
		if phone, ok := t.Claims["phone_number"].(string); ok {
			identity.Identifier = phone
			identity.Verified = true // Phone OTP is inherently verified.
		}

	case "password":
		if email, ok := t.Claims["email"].(string); ok {
			identity.Identifier = email
			if v, ok := t.Claims["email_verified"].(bool); ok {
				identity.Verified = v
			}
		}

	case "google.com", "apple.com", "facebook.com", "github.com", "microsoft.com":
		// OAuth providers verify identity during the OAuth flow.
		if email, ok := t.Claims["email"].(string); ok {
			identity.Identifier = email
			identity.Verified = true
		}

	default:
		// SAML, OIDC, or unknown providers - try email, fall back to UID.
		if email, ok := t.Claims["email"].(string); ok {
			identity.Identifier = email
			if v, ok := t.Claims["email_verified"].(bool); ok {
				identity.Verified = v
			}
		} else {
			identity.Identifier = t.UID
		}
	}

	return identity
}

// tokenHash returns the SHA-256 hex digest of a token string.
// Used as the Redis key for revocation tracking. We never store raw tokens.
func tokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
