package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"
)

type SecretRequest struct {
	Secret   string `json:"secret"`
	TTLHours int    `json:"ttl_hours"`
}

type SecretResponse struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

type SecretReveal struct {
	Value string `json:"value"`
}

// AuthMiddleware ensures the request has a valid session
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := GetSession(r)
		if err != nil {
			log.Warn().Err(err).Msg("Unauthorized access attempt")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Store session in context
		ctx := context.WithValue(r.Context(), "session", session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// CreateSecretHandler handles authenticated users posting new secrets
func CreateSecretHandler(w http.ResponseWriter, r *http.Request) {
	var req SecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if len(req.Secret) == 0 {
		http.Error(w, "secret cannot be empty", http.StatusBadRequest)
		return
	}

	if len(req.Secret) > AppConfig.MaxSecretLength {
		log.Warn().Int("length", len(req.Secret)).Msg("Secret maximum length exceeded")
		http.Error(w, fmt.Sprintf("secret exceeded maximum length of %d", AppConfig.MaxSecretLength), http.StatusBadRequest)
		return
	}

	id, err := GlobalStore.StoreSecret(r.Context(), req.Secret, req.TTLHours)
	if err != nil {
		log.Error().Err(err).Msg("Failed storing secret")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	url := fmt.Sprintf("%s/s/%s", AppConfig.PublicURL, id)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(SecretResponse{
		ID:  id,
		URL: url,
	})
}

// GetSecretMetadataHandler checks if a secret exists
func GetSecretMetadataHandler(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.Error(w, "missing id param", http.StatusBadRequest)
		return
	}

	entry, ok := GlobalStore.GetMetadata(r.Context(), id)
	if !ok {
		// Do not leak if it never existed or was revealed; just say non-existent
		http.Error(w, "previously retrieved or no longer available", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entry)
}

// RevealSecretHandler burns the secret and returns it
func RevealSecretHandler(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.Error(w, "missing id param", http.StatusBadRequest)
		return
	}

	val, ok := GlobalStore.RevealSecret(r.Context(), id)
	if !ok {
		// Could be already revealed or never existed
		http.Error(w, "previously retrieved or no longer available", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SecretReveal{
		Value: val,
	})
}
