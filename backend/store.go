package backend

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"cloud.google.com/go/storage"
	"log/slog"
	"go.skymeyer.dev/pkg/crypto"
)

const (
	METADATA_OWNER      = "owner"
	METADATA_CREATED_AT = "created_at"
	METADATA_EXPIRES_AT = "expires_at"
	METADATA_KEK        = "kek"
	METADATA_DEK        = "dek"
)

// SecretEntry represents a stored secret and its metadata
type SecretEntry struct {
	ID        string    `json:"id"`
	Value     string    `json:"value,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Owner     string    `json:"-"`
}

func InitSecretStore(ctx context.Context, kek, dek, secretBucket, userBucket string) error {
	if err := crypto.Initialize(ctx, kek, dek); err != nil {
		return err
	}

	gcs, err := storage.NewClient(ctx)
	if err != nil {
		return err
	}

	GlobalStore = &SecretStore{
		gcs:          gcs,
		secretBucket: secretBucket,
		userBucket:   userBucket,
	}
	return nil
}

// SecretStore is our mocked backend store for one-time secrets
type SecretStore struct {
	gcs          *storage.Client
	secretBucket string
	userBucket   string
}

var GlobalStore *SecretStore

// GenerateID produces a secure, non-correlated id using 32 cryptographically secure bytes
func GenerateID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *SecretStore) Shutdown() error {
	return s.gcs.Close()
}

func (s *SecretStore) StoreUser(ctx context.Context, ui UserInfo) error {
	if s.userBucket == "" {
		return nil
	}
	obj := s.gcs.Bucket(s.userBucket).Object(ui.ID)
	w := obj.NewWriter(ctx)
	defer w.Close()

	data, err := json.Marshal(ui)
	if err != nil {
		slog.Error("failed to marshal user info", "error", err, "user", ui.ID)
		return fmt.Errorf("failed to marshal user info: %w", err)
	}

	w.ContentType = "application/json"
	if _, err := io.Copy(w, bytes.NewBuffer(data)); err != nil {
		slog.Error("failed to write user info", "error", err, "user", ui.ID)
		return fmt.Errorf("failed to write user info: %w", err)
	}
	slog.Debug("user info stored successfully", "user", ui.ID, "user_info", ui)
	return nil
}

// StoreSecret saves a secret with a securely generated id and a TTL
// secret obj --> secret bytes (json) --> sealed bytes --> gcs object
func (s *SecretStore) StoreSecret(ctx context.Context, value string, ttlHours int) (string, error) {
	id, err := GenerateID()
	if err != nil {
		slog.Error("failed to generate id", "error", err)
		return "", fmt.Errorf("failed to generate id: %w", err)
	}

	if ttlHours <= 0 {
		slog.Debug("ttlHours is zero or negative, using default", "ttlHours", ttlHours)
		ttlHours = AppConfig.DefaultTTLHours
	}
	if ttlHours > AppConfig.MaxTTLHours {
		slog.Debug("ttlHours is greater than maxTTLHours, using maxTTLHours", "ttlHours", ttlHours, "maxTTLHours", AppConfig.MaxTTLHours)
		ttlHours = AppConfig.MaxTTLHours
	}

	// Create secret object and JSON encode it
	var (
		createdAt = time.Now().UTC()
		expiresAt = createdAt.Add(time.Duration(ttlHours) * time.Hour)
		user      = ctx.Value("session").(*Session).UserID
	)
	secret := SecretEntry{
		ID:        id,
		Value:     value,
		CreatedAt: createdAt,
		ExpiresAt: expiresAt,
		Owner:     user,
	}

	// Convert to JSON
	jsonBytes, err := json.Marshal(secret)
	if err != nil {
		slog.Error("failed to marshal secret", "error", err, "user", user)
		return "", fmt.Errorf("failed to marshal secret: %w", err)
	}

	// Encrypt secret with user subject as AAD
	ctx = crypto.ContextWithAAD(ctx, crypto.AAD{
		Content: user,
	})
	sealed, err := crypto.Seal(ctx, jsonBytes)
	if err != nil {
		slog.Error("failed to seal secret", "error", err, "user", user)
		return "", fmt.Errorf("failed to seal secret: %w", err)
	}

	// Create an object handle with the desired attributes, including metadata.
	// Althought the KEK and DEK information is embedded in the sealed secert,
	// we store them on metadata too to easily query key usage.
	obj := s.gcs.Bucket(s.secretBucket).Object(id)
	objectAttrs := storage.ObjectAttrs{
		ContentType: "application/octet-stream",
		Metadata: map[string]string{
			METADATA_OWNER:      user,
			METADATA_KEK:        sealed.KEKVersion,
			METADATA_DEK:        sealed.DEKVersion,
			METADATA_CREATED_AT: createdAt.Format(time.RFC3339),
			METADATA_EXPIRES_AT: expiresAt.Format(time.RFC3339),
		},
	}

	// Create a writer with the specified attributes
	w := obj.If(storage.Conditions{DoesNotExist: true}).NewWriter(ctx)
	w.ContentType = objectAttrs.ContentType
	w.Metadata = objectAttrs.Metadata

	// Write the file content
	sealedBytes, err := sealed.Bytes()
	if err != nil {
		slog.Error("failed to marshal sealed", "error", err, "user", user)
		return "", fmt.Errorf("failed to marshal sealed: %w", err)
	}
	if _, err := io.Copy(w, bytes.NewReader(sealedBytes)); err != nil {
		slog.Error("io.Copy failed", "error", err, "user", user)
		return "", fmt.Errorf("io.Copy: %w", err)
	}

	// Close the writer to finalize the upload
	if err := w.Close(); err != nil {
		slog.Error("w.Close failed", "error", err, "user", user)
		return "", fmt.Errorf("w.Close: %w", err)
	}

	slog.Info("secret stored successfully", "id", id, "user", user, "ttlHours", ttlHours)
	return id, nil
}

// GetMetadata checks if a secret exists without returning its value or burning it.
func (s *SecretStore) GetMetadata(ctx context.Context, id string) (*SecretEntry, bool) {

	// Use the Attrs method to get object metadata
	attrs, err := s.gcs.Bucket(s.secretBucket).Object(id).Attrs(ctx)
	if err != nil {
		// Check if the error is a "Not Found" error
		if err == storage.ErrObjectNotExist {
			return nil, false
		}
		slog.Info("gcs object no longer exists", "error", err, "id", id)
		return nil, false
	}

	// Object exists, return its custom metadata
	createdAt, err := time.Parse(time.RFC3339, attrs.Metadata[METADATA_CREATED_AT])
	if err != nil {
		slog.Error("time.Parse created_at failed", "error", err, "id", id)
		return nil, false
	}
	expiresAt, err := time.Parse(time.RFC3339, attrs.Metadata[METADATA_EXPIRES_AT])
	if err != nil {
		slog.Error("time.Parse expires_at failed", "error", err, "id", id)
		return nil, false
	}

	// If expired, we pretend it doesn't exist. GCS Bucket Lifecycle will delete it later.
	if time.Now().After(expiresAt) {
		slog.Debug("secret exists but is expired", "id", id)
		if err := s.destroySecret(ctx, &SecretEntry{ID: id}); err != nil {
			slog.Error("destroy expired secret failed", "error", err, "id", id)
		}
		return nil, false
	}

	secret := &SecretEntry{
		ID:        id,
		CreatedAt: createdAt,
		ExpiresAt: expiresAt,
	}
	if owner, ok := attrs.Metadata[METADATA_OWNER]; ok {
		secret.Owner = owner
	}

	slog.Info("secret metadata retrieved", "id", id, "owner", secret.Owner)
	return secret, true
}

// RevealSecret securely burns the secret and returns its value.
func (s *SecretStore) RevealSecret(ctx context.Context, id string) (string, bool) {

	// Get secret metadata
	secret, ok := s.GetMetadata(ctx, id)
	if !ok {
		slog.Error("secret does not exist or is expired", "id", id)
		return "", false
	}

	// Create a reader for the object
	reader, err := s.gcs.Bucket(s.secretBucket).Object(id).NewReader(ctx)
	if err != nil {
		slog.Error("reader creation failed", "error", err, "id", id)
		return "", false
	}
	defer reader.Close()

	// Read the bytes from the file
	bytes, err := io.ReadAll(reader)
	if err != nil {
		slog.Error("io.ReadAll failed", "error", err, "id", id)
		return "", false
	}

	// Decrypt the secret
	sealed, err := crypto.UnmarshalSealed(bytes)
	if err != nil {
		slog.Error("crypto.UnmarshalSealed failed", "error", err, "id", id)
		return "", false
	}

	// Decrypt the secret with username as AAD
	ctx = crypto.ContextWithAAD(ctx, crypto.AAD{
		Content: secret.Owner,
	})
	decrypted, err := crypto.Unseal(ctx, sealed)
	if err != nil {
		slog.Error("crypto.Unseal failed", "error", err, "id", id, "owner", secret.Owner)
		return "", false
	}

	if err := json.Unmarshal(decrypted, &secret); err != nil {
		slog.Error("json.Unmarshal failed", "error", err, "id", id, "owner", secret.Owner)
		return "", false
	}

	// Burn the secret
	if err := s.destroySecret(ctx, secret); err != nil {
		slog.Error("destroy revealed secret failed", "error", err, "id", secret.ID, "owner", secret.Owner)
		return "", false
	}

	return secret.Value, true
}

func (s *SecretStore) destroySecret(ctx context.Context, secret *SecretEntry) error {
	if err := s.gcs.Bucket(s.secretBucket).Object(secret.ID).Delete(ctx); err != nil {
		return err
	}
	slog.Info("secret destroyed", "id", secret.ID, "owner", secret.Owner)
	return nil
}
