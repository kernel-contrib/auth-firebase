package authfirebase

import (
	"testing"
	"time"

	"firebase.google.com/go/v4/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
