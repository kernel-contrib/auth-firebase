package authfirebase

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"

	"firebase.google.com/go/v4/auth"
	"github.com/kernel-contrib/sdk"
)

// SyncModule is a headless kernel module that subscribes to IAM profile
// update events and syncs email, phone, and display name changes back
// to Firebase Auth.
//
// Usage in the consumer's main.go:
//
//	provider, _ := authfirebase.New(ctx, cfg)
//	k.SetIdentityProvider(provider)
//	k.Register(authfirebase.NewSyncModule(provider)) // opt-in profile sync
type SyncModule struct {
	auth authClient
	ctx  sdk.Context
}

// Compile-time interface checks.
var _ sdk.Module = (*SyncModule)(nil)
var _ sdk.EventModule = (*SyncModule)(nil)

// NewSyncModule creates a new profile sync module backed by the given
// Firebase provider's auth client.
func NewSyncModule(p *Provider) *SyncModule {
	return &SyncModule{auth: p.auth}
}

// ── Module interface ──────────────────────────────────────────────────────────

// Manifest returns immutable metadata for the sync module.
func (m *SyncModule) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:          "auth_firebase",
		Type:        sdk.TypeCore,
		Name:        "Firebase Auth Profile Sync",
		Description: "Syncs IAM profile changes back to Firebase Auth",
		Version:     "1.0.0",
		DependsOn:   []string{"iam"},
	}
}

// Migrations returns nil because this module has no database tables.
func (m *SyncModule) Migrations() fs.FS { return nil }

// Init stores the SDK context for use in event handlers.
func (m *SyncModule) Init(ctx sdk.Context) error {
	m.ctx = ctx
	ctx.Logger.Info("auth-firebase sync module initialized")
	return nil
}

// Shutdown performs graceful cleanup.
func (m *SyncModule) Shutdown() error { return nil }

// ── Event subscriptions ───────────────────────────────────────────────────────

// RegisterEvents subscribes to IAM user profile updates so that changes
// to email, phone, or display name are synced back to Firebase Auth.
func (m *SyncModule) RegisterEvents(bus sdk.EventBus) {
	bus.Subscribe("auth_firebase", "iam.user.updated", m.handleUserUpdated)
}

// handleUserUpdated syncs profile field changes back to Firebase Auth.
// Only processes events from users whose provider is "firebase".
// Profile sync is best-effort: errors are logged but not propagated.
func (m *SyncModule) handleUserUpdated(ctx context.Context, env sdk.EventEnvelope) error {
	var payload struct {
		UserID     string  `json:"user_id"`
		ProviderID string  `json:"provider_id"`
		Provider   string  `json:"provider"`
		Email      *string `json:"email"`
		Phone      *string `json:"phone"`
		Name       *string `json:"name"`
	}
	if err := json.Unmarshal(env.Payload, &payload); err != nil {
		return fmt.Errorf("unmarshal user updated event: %w", err)
	}

	// Only sync users that belong to this provider.
	if payload.Provider != "firebase" {
		return nil
	}

	update := (&auth.UserToUpdate{})
	hasChanges := false

	if payload.Email != nil {
		update = update.Email(*payload.Email)
		hasChanges = true
	}
	if payload.Phone != nil {
		if *payload.Phone == "" {
			update = update.PhoneNumber("")
		} else {
			update = update.PhoneNumber(*payload.Phone)
		}
		hasChanges = true
	}
	if payload.Name != nil {
		update = update.DisplayName(*payload.Name)
		hasChanges = true
	}

	if !hasChanges {
		return nil
	}

	if _, err := m.auth.UpdateUser(ctx, payload.ProviderID, update); err != nil {
		m.ctx.Logger.Warn("failed to sync profile to Firebase",
			"provider_id", payload.ProviderID,
			"user_id", payload.UserID,
			"error", err,
		)
		// Best-effort: don't propagate the error.
		return nil
	}

	m.ctx.Logger.Info("synced profile update to Firebase",
		"provider_id", payload.ProviderID,
		"user_id", payload.UserID,
	)
	return nil
}
