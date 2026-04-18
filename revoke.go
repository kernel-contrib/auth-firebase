package authfirebase

import (
	"context"
	"fmt"
	"time"
)

const (
	// revokePrefix is the Redis key prefix for revoked token hashes.
	revokePrefix = "authfirebase:revoked:"

	// maxTokenTTL is the maximum lifetime of a Firebase ID token (1 hour).
	// Revocation entries use this as their TTL to ensure they outlive any
	// valid token without needing to parse the token's actual expiry.
	maxTokenTTL = 1 * time.Hour
)

// RevokeToken revokes a single token by storing its hash in Redis.
// This satisfies the sdk.IdentityProvider interface.
//
// Only this specific token is revoked - other devices and sessions for
// the same user are unaffected. For revoking all sessions, use
// RevokeAllSessions instead.
func (p *Provider) RevokeToken(ctx context.Context, token string) error {
	key := revokePrefix + tokenHash(token)
	if err := p.redis.Set(ctx, key, "1", maxTokenTTL).Err(); err != nil {
		return fmt.Errorf("authfirebase: revoke token: %w", err)
	}
	return nil
}

// RevokeTokens revokes one or more tokens by storing their hashes in Redis
// using a pipeline for efficiency.
//
// Only the specified tokens are revoked - other devices and sessions for
// the same user are unaffected.
func (p *Provider) RevokeTokens(ctx context.Context, tokens ...string) error {
	if len(tokens) == 0 {
		return nil
	}

	pipe := p.redis.Pipeline()
	for _, token := range tokens {
		key := revokePrefix + tokenHash(token)
		pipe.Set(ctx, key, "1", maxTokenTTL)
	}

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("authfirebase: revoke tokens: %w", err)
	}
	return nil
}

// RevokeAllSessions revokes ALL sessions for a user across all devices.
// This calls Firebase's RevokeRefreshTokens which prevents the user from
// obtaining new ID tokens. Existing ID tokens remain valid until they
// expire (up to 1 hour).
//
// Use this for security events such as password changes or account
// compromise. For normal single-device logout, use RevokeToken instead.
func (p *Provider) RevokeAllSessions(ctx context.Context, uid string) error {
	if err := p.auth.RevokeRefreshTokens(ctx, uid); err != nil {
		return fmt.Errorf("authfirebase: revoke all sessions for %s: %w", uid, err)
	}
	return nil
}

// isRevoked checks whether a token has been locally revoked via Redis.
// Returns false on Redis errors (fail-open) to avoid blocking
// authentication when Redis is temporarily unavailable.
func (p *Provider) isRevoked(ctx context.Context, token string) bool {
	key := revokePrefix + tokenHash(token)
	val, err := p.redis.Exists(ctx, key).Result()
	if err != nil {
		return false
	}
	return val > 0
}
