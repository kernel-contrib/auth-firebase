# auth-firebase

Firebase identity provider for the [EdgeScale Kernel](https://go.edgescale.dev/kernel) framework.

Implements `sdk.IdentityProvider` using the [Firebase Admin Go SDK](https://firebase.google.com/go/v4), providing:

- **Token validation** - verifies Firebase ID tokens and maps claims to `sdk.Identity`
- **Single-token revocation** - revokes individual tokens via Redis (other devices unaffected)
- **Batch revocation** - revoke multiple tokens in a single pipeline call
- **Full-session revocation** - revokes all sessions for a user via Firebase (security events)
- **Profile sync** - opt-in module that syncs IAM profile changes (email, phone, name) back to Firebase Auth

## Installation

```bash
go get github.com/kernel-contrib/auth-firebase@latest
```

## Usage

```go
package main

import (
    "context"

    "github.com/redis/go-redis/v9"
    "github.com/edgescaleDev/kernel"
    "github.com/edgescaleDev/kernel/sdk"
    authfirebase "github.com/kernel-contrib/auth-firebase"
)

func main() {
    ctx := context.Background()

    redisClient := redis.NewClient(&redis.Options{Addr: "localhost:6379"})

    fb, err := authfirebase.New(ctx, authfirebase.Config{
        ProjectID: "my-firebase-project",
        Redis:     redisClient,
        // Optional: explicit credentials (defaults to ADC / GOOGLE_APPLICATION_CREDENTIALS)
        // CredentialsFile: "/path/to/service-account.json",
        // CredentialsJSON: []byte(`{...}`),
    })
    if err != nil {
        panic(err)
    }

    // Build the provider chain (for multi-provider setups).
    chain := sdk.NewIdentityProviderChain()
    chain.AddJWTIssuer("firebase",
        "https://securetoken.google.com/my-firebase-project", fb)
    chain.SetFallback("firebase", fb)

    k := kernel.New(kernel.LoadConfig())
    k.SetIdentityProvider(chain) // or k.SetIdentityProvider(fb) for single-provider

    // Optional: enable profile sync (IAM profile changes synced back to Firebase)
    k.Register(authfirebase.NewSyncModule(fb))

    // ... register other modules, k.Execute()
}
```

## Credentials

The provider supports three credential modes (in priority order):

1. **`CredentialsJSON`** - raw service account JSON bytes (highest priority)
2. **`CredentialsFile`** - path to a service account JSON file
3. **Application Default Credentials** - auto-discovered from `GOOGLE_APPLICATION_CREDENTIALS` env var or GCP metadata server (default)

## Token Revocation

### Single device logout

```go
// Revokes only this specific token - other devices are unaffected.
provider.RevokeToken(ctx, idToken)
```

### Batch revocation

```go
// Revokes multiple tokens in a single Redis pipeline call.
provider.RevokeTokens(ctx, token1, token2, token3)
```

### Security events (all devices)

```go
// Revokes ALL refresh tokens for the user across all devices.
// Existing ID tokens remain valid until they expire (up to 1 hour).
// Use for password changes, account compromise, etc.
provider.RevokeAllSessions(ctx, firebaseUID)
```

## Profile Sync

The `SyncModule` is an opt-in headless kernel module that keeps Firebase Auth in sync when users update their profile through IAM. It subscribes to `iam.user.updated` events and pushes changes back to Firebase.

### What it syncs

| IAM field | Firebase field |
| --- | --- |
| `email` | Email |
| `phone` | Phone number |
| `name` | Display name |

### How it works

1. A user updates their profile via the IAM module (`PATCH /v1/me`)
2. IAM publishes an enriched `iam.user.updated` event containing the changed fields, the user's `provider`, and `provider_id`
3. `SyncModule` receives the event, checks if `provider == "firebase"`, and calls `auth.UpdateUser()` with the changed fields
4. Sync is best-effort: failures are logged but don't block the event pipeline

### Event payload

The `iam.user.updated` event includes only the fields that actually changed:

```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "provider": "firebase",
  "provider_id": "firebase-uid-123",
  "email": "new@example.com",
  "phone": "+1234567890",
  "name": "Jane Doe"
}
```

### Enabling

Register the sync module after creating the provider:

```go
fb, _ := authfirebase.New(ctx, cfg)
k.SetIdentityProvider(fb)
k.Register(authfirebase.NewSyncModule(fb)) // opt-in
```

If you don't register the `SyncModule`, the provider works exactly as before with no profile sync behavior.

## How it works

| Layer | What happens |
| --- | --- |
| **Authenticate** | Extracts Bearer token from headers, checks Redis for revoked token hash, verifies with Firebase Admin SDK, maps claims to `sdk.Identity` |
| **RevokeToken / RevokeTokens** | Stores `SHA-256(token)` in Redis with 1h TTL (max Firebase token lifetime) |
| **RevokeAllSessions** | Calls Firebase `RevokeRefreshTokens(uid)` to prevent new token issuance |
| **SyncModule** | Subscribes to `iam.user.updated`, pushes email/phone/name changes to Firebase Auth |

### Identity mapping

| `sdk.Identity` field | Firebase source |
| --- | --- |
| `Subject` | `token.UID` |
| `Provider` | `"firebase"` |
| `Identifier` | Phone number, email, or UID (depends on sign-in method) |
| `Verified` | `true` for phone/OAuth; `email_verified` claim for password |
| `SignInMethod` | `token.Firebase.SignInProvider` |
| `Kind` | `IdentityKindUser` |
| `RawCredential` | Raw Bearer token (never logged) |
| `Claims` | Full decoded token claims |
| `ExpiresAt` | `token.Expires` |

## Requirements

- Go 1.26+
- Redis (required for token revocation)
- Firebase project with Authentication enabled
