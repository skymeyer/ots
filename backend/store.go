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

	"github.com/rs/zerolog/log"

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
		log.Error().Err(err).Str("user", ui.ID).Msg("failed to marshal user info")
		return fmt.Errorf("failed to marshal user info: %w", err)
	}

	w.ContentType = "application/json"
	if _, err := io.Copy(w, bytes.NewBuffer(data)); err != nil {
		log.Error().Err(err).Str("user", ui.ID).Msg("failed to write user info")
		return fmt.Errorf("failed to write user info: %w", err)
	}
	log.Debug().Str("user", ui.ID).Interface("user_info", ui).Msg("user info stored successfully")
	return nil
}

// StoreSecret saves a secret with a securely generated id and a TTL
// secret obj --> secret bytes (json) --> sealed bytes --> gcs object
func (s *SecretStore) StoreSecret(ctx context.Context, value string, ttlHours int) (string, error) {
	id, err := GenerateID()
	if err != nil {
		log.Error().Err(err).Msg("failed to generate id")
		return "", fmt.Errorf("failed to generate id: %w", err)
	}

	if ttlHours <= 0 {
		log.Debug().Int("ttlHours", ttlHours).Msg("ttlHours is zero or negative, using default")
		ttlHours = AppConfig.DefaultTTLHours
	}
	if ttlHours > AppConfig.MaxTTLHours {
		log.Debug().Int("ttlHours", ttlHours).Int("maxTTLHours", AppConfig.MaxTTLHours).
			Msg("ttlHours is greater than maxTTLHours, using maxTTLHours")
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
		log.Error().Err(err).Str("user", user).Msg("failed to marshal secret")
		return "", fmt.Errorf("failed to marshal secret: %w", err)
	}

	// Encrypt secret with user subject as AAD
	ctx = crypto.ContextWithAAD(ctx, crypto.AAD{
		Content: user,
	})
	sealed, err := crypto.Seal(ctx, jsonBytes)
	if err != nil {
		log.Error().Err(err).Str("user", user).Msg("failed to seal secret")
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
		log.Error().Err(err).Str("user", user).Msg("failed to marshal sealed")
		return "", fmt.Errorf("failed to marshal sealed: %w", err)
	}
	if _, err := io.Copy(w, bytes.NewReader(sealedBytes)); err != nil {
		log.Error().Err(err).Str("user", user).Msg("io.Copy failed")
		return "", fmt.Errorf("io.Copy: %w", err)
	}

	// Close the writer to finalize the upload
	if err := w.Close(); err != nil {
		log.Error().Err(err).Str("user", user).Msg("w.Close failed")
		return "", fmt.Errorf("w.Close: %w", err)
	}

	log.Info().Str("id", id).Str("user", user).Int("ttlHours", ttlHours).Msg("secret stored successfully")
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
		log.Info().Err(err).Str("id", id).Msg("gcs object no longer exists")
		return nil, false
	}

	// Object exists, return its custom metadata
	createdAt, err := time.Parse(time.RFC3339, attrs.Metadata[METADATA_CREATED_AT])
	if err != nil {
		log.Error().Err(err).Str("id", id).Msg("time.Parse created_at failed")
		return nil, false
	}
	expiresAt, err := time.Parse(time.RFC3339, attrs.Metadata[METADATA_EXPIRES_AT])
	if err != nil {
		log.Error().Err(err).Str("id", id).Msg("time.Parse expires_at failed")
		return nil, false
	}

	// If expired, we pretend it doesn't exist. GCS Bucket Lifecycle will delete it later.
	if time.Now().After(expiresAt) {
		log.Debug().Str("id", id).Msg("secret exists but is expired")
		if err := s.destroySecret(ctx, &SecretEntry{ID: id}); err != nil {
			log.Error().Err(err).Str("id", id).Msg("destroy expired secret failed")
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

	log.Info().Str("id", id).Str("owner", secret.Owner).Msg("secret metadata retrieved")
	return secret, true
}

// RevealSecret securely burns the secret and returns its value.
func (s *SecretStore) RevealSecret(ctx context.Context, id string) (string, bool) {

	// Get secret metadata
	secret, ok := s.GetMetadata(ctx, id)
	if !ok {
		log.Error().Str("id", id).Msg("secret does not exist or is expired")
		return "", false
	}

	// Create a reader for the object
	reader, err := s.gcs.Bucket(s.secretBucket).Object(id).NewReader(ctx)
	if err != nil {
		log.Error().Err(err).Str("id", id).Msg("reader creation failed")
		return "", false
	}
	defer reader.Close()

	// Read the bytes from the file
	bytes, err := io.ReadAll(reader)
	if err != nil {
		log.Error().Err(err).Str("id", id).Msg("io.ReadAll failed")
		return "", false
	}

	// Decrypt the secret
	sealed, err := crypto.UnmarshalSealed(bytes)
	if err != nil {
		log.Error().Err(err).Str("id", id).Msg("crypto.UnmarshalSealed failed")
		return "", false
	}

	// Decrypt the secret with username as AAD
	ctx = crypto.ContextWithAAD(ctx, crypto.AAD{
		Content: secret.Owner,
	})
	decrypted, err := crypto.Unseal(ctx, sealed)
	if err != nil {
		log.Error().Err(err).Str("id", id).Str("owner", secret.Owner).Msg("crypto.Unseal failed")
		return "", false
	}

	if err := json.Unmarshal(decrypted, &secret); err != nil {
		log.Error().Err(err).Str("id", id).Str("owner", secret.Owner).Msg("json.Unmarshal failed")
		return "", false
	}

	// Burn the secret
	if err := s.destroySecret(ctx, secret); err != nil {
		log.Error().Err(err).Str("id", secret.ID).Str("owner", secret.Owner).Msg("destroy revealed secret failed")
		return "", false
	}

	return secret.Value, true
}

func (s *SecretStore) destroySecret(ctx context.Context, secret *SecretEntry) error {
	if err := s.gcs.Bucket(s.secretBucket).Object(secret.ID).Delete(ctx); err != nil {
		return err
	}
	log.Info().Str("id", secret.ID).Str("owner", secret.Owner).Msg("secret destroyed")
	return nil
}
