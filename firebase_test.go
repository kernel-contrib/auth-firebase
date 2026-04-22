package authfirebase

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"firebase.google.com/go/v4/auth"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.edgescale.dev/kernel/sdk"
)

func TestMapToken_Phone(t *testing.T) {
	token := &auth.Token{
		UID:     "firebase-uid-123",
		Expires: time.Now().Add(time.Hour).Unix(),
		Claims: map[string]any{
			"phone_number": "+9647901234567",
		},
		Firebase: auth.FirebaseInfo{
			SignInProvider: "phone",
		},
	}

	identity := mapToken(token)

	assert.Equal(t, "firebase-uid-123", identity.Subject)
	assert.Equal(t, "firebase", identity.Provider)
	assert.Equal(t, "phone", identity.SignInMethod)
	assert.Equal(t, "+9647901234567", identity.Identifier)
	assert.True(t, identity.Verified)
	assert.NotZero(t, identity.ExpiresAt)
}

func TestMapToken_Password(t *testing.T) {
	token := &auth.Token{
		UID:     "firebase-uid-456",
		Expires: time.Now().Add(time.Hour).Unix(),
		Claims: map[string]any{
			"email":          "user@example.com",
			"email_verified": true,
		},
		Firebase: auth.FirebaseInfo{
			SignInProvider: "password",
		},
	}

	identity := mapToken(token)

	assert.Equal(t, "firebase-uid-456", identity.Subject)
	assert.Equal(t, "password", identity.SignInMethod)
	assert.Equal(t, "user@example.com", identity.Identifier)
	assert.True(t, identity.Verified)
}

func TestMapToken_PasswordUnverified(t *testing.T) {
	token := &auth.Token{
		UID:     "firebase-uid-789",
		Expires: time.Now().Add(time.Hour).Unix(),
		Claims: map[string]any{
			"email":          "unverified@example.com",
			"email_verified": false,
		},
		Firebase: auth.FirebaseInfo{
			SignInProvider: "password",
		},
	}

	identity := mapToken(token)

	assert.Equal(t, "unverified@example.com", identity.Identifier)
	assert.False(t, identity.Verified)
}

func TestMapToken_Google(t *testing.T) {
	token := &auth.Token{
		UID:     "firebase-uid-google",
		Expires: time.Now().Add(time.Hour).Unix(),
		Claims: map[string]any{
			"email":          "user@gmail.com",
			"email_verified": true,
		},
		Firebase: auth.FirebaseInfo{
			SignInProvider: "google.com",
		},
	}

	identity := mapToken(token)

	assert.Equal(t, "google.com", identity.SignInMethod)
	assert.Equal(t, "user@gmail.com", identity.Identifier)
	assert.True(t, identity.Verified)
}

func TestMapToken_Apple(t *testing.T) {
	token := &auth.Token{
		UID:     "firebase-uid-apple",
		Expires: time.Now().Add(time.Hour).Unix(),
		Claims: map[string]any{
			"email": "relay@privaterelay.appleid.com",
		},
		Firebase: auth.FirebaseInfo{
			SignInProvider: "apple.com",
		},
	}

	identity := mapToken(token)

	assert.Equal(t, "apple.com", identity.SignInMethod)
	assert.Equal(t, "relay@privaterelay.appleid.com", identity.Identifier)
	assert.True(t, identity.Verified)
}

func TestMapToken_UnknownProvider(t *testing.T) {
	token := &auth.Token{
		UID:     "firebase-uid-saml",
		Expires: time.Now().Add(time.Hour).Unix(),
		Claims: map[string]any{
			"email":          "user@corp.com",
			"email_verified": true,
		},
		Firebase: auth.FirebaseInfo{
			SignInProvider: "saml.my-provider",
		},
	}

	identity := mapToken(token)

	assert.Equal(t, "saml.my-provider", identity.SignInMethod)
	assert.Equal(t, "user@corp.com", identity.Identifier)
	assert.True(t, identity.Verified)
}

func TestMapToken_UnknownProviderNoEmail(t *testing.T) {
	token := &auth.Token{
		UID:     "firebase-uid-custom",
		Expires: time.Now().Add(time.Hour).Unix(),
		Claims:  map[string]any{},
		Firebase: auth.FirebaseInfo{
			SignInProvider: "custom",
		},
	}

	identity := mapToken(token)

	assert.Equal(t, "firebase-uid-custom", identity.Identifier, "should fall back to UID")
	assert.False(t, identity.Verified)
}

func TestMapToken_ClaimsPreserved(t *testing.T) {
	claims := map[string]any{
		"phone_number": "+9647901234567",
		"custom_claim": "custom_value",
	}
	token := &auth.Token{
		UID:     "uid",
		Expires: time.Now().Add(time.Hour).Unix(),
		Claims:  claims,
		Firebase: auth.FirebaseInfo{
			SignInProvider: "phone",
		},
	}

	identity := mapToken(token)

	require.NotNil(t, identity.Claims)
	assert.Equal(t, "custom_value", identity.Claims["custom_claim"])
}

func TestTokenHash_Deterministic(t *testing.T) {
	hash1 := tokenHash("test-token-abc")
	hash2 := tokenHash("test-token-abc")
	assert.Equal(t, hash1, hash2)
}

func TestTokenHash_Different(t *testing.T) {
	hash1 := tokenHash("token-a")
	hash2 := tokenHash("token-b")
	assert.NotEqual(t, hash1, hash2)
}

func TestTokenHash_Length(t *testing.T) {
	hash := tokenHash("any-token")
	assert.Len(t, hash, 64, "SHA-256 hex digest should be 64 chars")
}

func TestNewConfig_MissingProjectID(t *testing.T) {
	_, err := New(t.Context(), Config{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project ID is required")
}

func TestNewConfig_MissingRedis(t *testing.T) {
	_, err := New(t.Context(), Config{ProjectID: "test-project"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "redis client is required")
}

// ── Authenticate tests ───────────────────────────────────────────────────────

// mockAuthClient implements authClient for unit testing.
type mockAuthClient struct {
	verifyFunc func(ctx context.Context, idToken string) (*auth.Token, error)
}

func (m *mockAuthClient) VerifyIDToken(ctx context.Context, idToken string) (*auth.Token, error) {
	return m.verifyFunc(ctx, idToken)
}

func (m *mockAuthClient) RevokeRefreshTokens(_ context.Context, _ string) error {
	return nil
}

// newTestProvider creates a Provider backed by miniredis and a mock auth client.
func newTestProvider(t *testing.T, mock *mockAuthClient) (*Provider, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return &Provider{auth: mock, redis: rc}, mr
}

func TestAuthenticate_MissingHeader(t *testing.T) {
	p, _ := newTestProvider(t, &mockAuthClient{})

	_, err := p.Authenticate(t.Context(), http.Header{})
	assert.ErrorIs(t, err, sdk.ErrNoCredentials)
}

func TestAuthenticate_WrongScheme(t *testing.T) {
	p, _ := newTestProvider(t, &mockAuthClient{})

	h := http.Header{}
	h.Set("Authorization", "Basic dXNlcjpwYXNz")

	_, err := p.Authenticate(t.Context(), h)
	assert.ErrorIs(t, err, sdk.ErrNoCredentials)
}

func TestAuthenticate_EmptyBearerToken(t *testing.T) {
	p, _ := newTestProvider(t, &mockAuthClient{})

	h := http.Header{}
	h.Set("Authorization", "Bearer ")

	_, err := p.Authenticate(t.Context(), h)
	assert.ErrorIs(t, err, sdk.ErrNoCredentials)
}

func TestAuthenticate_RevokedToken(t *testing.T) {
	p, mr := newTestProvider(t, &mockAuthClient{})

	revokedToken := "revoked-token-123"
	mr.Set(revokePrefix+tokenHash(revokedToken), "1")

	h := http.Header{}
	h.Set("Authorization", "Bearer "+revokedToken)

	_, err := p.Authenticate(t.Context(), h)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revoked")
}

func TestAuthenticate_VerifyError(t *testing.T) {
	mock := &mockAuthClient{
		verifyFunc: func(_ context.Context, _ string) (*auth.Token, error) {
			return nil, errors.New("token expired")
		},
	}
	p, _ := newTestProvider(t, mock)

	h := http.Header{}
	h.Set("Authorization", "Bearer expired-token")

	_, err := p.Authenticate(t.Context(), h)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verify token")
}

func TestAuthenticate_Success(t *testing.T) {
	rawToken := "valid-firebase-token"
	mock := &mockAuthClient{
		verifyFunc: func(_ context.Context, idToken string) (*auth.Token, error) {
			assert.Equal(t, rawToken, idToken, "should pass the extracted token")
			return &auth.Token{
				UID:     "uid-abc",
				Expires: time.Now().Add(time.Hour).Unix(),
				Claims: map[string]any{
					"email":          "user@example.com",
					"email_verified": true,
				},
				Firebase: auth.FirebaseInfo{SignInProvider: "password"},
			}, nil
		},
	}
	p, _ := newTestProvider(t, mock)

	h := http.Header{}
	h.Set("Authorization", "Bearer "+rawToken)

	identity, err := p.Authenticate(t.Context(), h)
	require.NoError(t, err)

	// Core identity fields (delegated to mapToken, already tested).
	assert.Equal(t, "uid-abc", identity.Subject)
	assert.Equal(t, "firebase", identity.Provider)
	assert.Equal(t, "user@example.com", identity.Identifier)

	// New fields set by Authenticate — the reason for this test.
	assert.Equal(t, sdk.IdentityKindUser, identity.Kind)
	assert.Equal(t, rawToken, identity.RawCredential)
}
