package backend

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"context"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Session represents an authenticated user's session
type Session struct {
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
	Picture   string    `json:"picture"`
	ExpiresAt time.Time `json:"expires_at"`
}

type UserInfo struct {
	ID         string `json:"sub"`
	Email      string `json:"email"`
	Name       string `json:"name,omitempty"`
	GivenName  string `json:"given_name,omitempty"`
	FamilyName string `json:"family_name,omitempty"`
	Picture    string `json:"picture,omitempty"`
}

func (u *UserInfo) Domain() string {
	parts := strings.Split(u.Email, "@")
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

const CookieName = "ots_session"

var (
	oidcProvider *oidc.Provider
	providerOnce sync.Once
)

func getOIDCProvider(ctx context.Context) (*oidc.Provider, error) {
	var err error
	providerOnce.Do(func() {
		oidcProvider, err = oidc.NewProvider(context.Background(), "https://accounts.google.com")
	})
	return oidcProvider, err
}

func getOAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     AppConfig.GoogleClientID,
		ClientSecret: AppConfig.GoogleSecret,
		RedirectURL:  strings.TrimRight(AppConfig.PublicURL, "/") + "/api/auth/google/callback",
		Scopes:       AppConfig.GoogleScopes,
		Endpoint:     google.Endpoint,
	}
}

// AuthLoginHandler initiates the Google OAuth flow
func AuthLoginHandler(w http.ResponseWriter, r *http.Request) {
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{
		Name:     "ots_oauth_state",
		Value:    state,
		Path:     "/",
		Expires:  time.Now().Add(10 * time.Minute),
		HttpOnly: true,
		Secure:   AppConfig.IsSecureCookie(),
		SameSite: http.SameSiteLaxMode,
	})

	verifier, challenge := generatePKCE()
	http.SetCookie(w, &http.Cookie{
		Name:     "ots_oauth_verifier",
		Value:    verifier,
		Path:     "/",
		Expires:  time.Now().Add(10 * time.Minute),
		HttpOnly: true,
		Secure:   AppConfig.IsSecureCookie(),
		SameSite: http.SameSiteLaxMode,
	})

	n := make([]byte, 16)
	rand.Read(n)
	nonce := base64.URLEncoding.EncodeToString(n)
	http.SetCookie(w, &http.Cookie{
		Name:     "ots_oauth_nonce",
		Value:    nonce,
		Path:     "/",
		Expires:  time.Now().Add(10 * time.Minute),
		HttpOnly: true,
		Secure:   AppConfig.IsSecureCookie(),
		SameSite: http.SameSiteLaxMode,
	})

	url := getOAuthConfig().AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("nonce", nonce),
	)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// AuthCallbackHandler handles the return from Google OAuth
func AuthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	oauthState, err := r.Cookie("ots_oauth_state")
	if err != nil {
		log.Warn().Err(err).Msg("OAuth state cookie missing")
		http.Redirect(w, r, "/?error=oauth_state_missing", http.StatusTemporaryRedirect)
		return
	}

	oauthVerifier, err := r.Cookie("ots_oauth_verifier")
	if err != nil {
		log.Warn().Err(err).Msg("OAuth verifier cookie missing")
		http.Redirect(w, r, "/?error=oauth_verifier_missing", http.StatusTemporaryRedirect)
		return
	}

	oauthNonce, err := r.Cookie("ots_oauth_nonce")
	if err != nil {
		log.Warn().Err(err).Msg("OAuth nonce cookie missing")
		http.Redirect(w, r, "/?error=oauth_nonce_missing", http.StatusTemporaryRedirect)
		return
	}

	if r.FormValue("state") != oauthState.Value {
		log.Warn().Msg("Invalid OAuth state")
		http.Redirect(w, r, "/?error=invalid_oauth_state", http.StatusTemporaryRedirect)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "ots_oauth_state",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		Secure:   AppConfig.IsSecureCookie(),
		HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "ots_oauth_verifier",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		Secure:   AppConfig.IsSecureCookie(),
		HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "ots_oauth_nonce",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		Secure:   AppConfig.IsSecureCookie(),
		HttpOnly: true,
	})

	code := r.FormValue("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	token, err := getOAuthConfig().Exchange(r.Context(), code, oauth2.SetAuthURLParam("code_verifier", oauthVerifier.Value))
	if err != nil {
		log.Error().Err(err).Msg("OAuth exchange failed")
		http.Error(w, "auth failed", http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		log.Error().Msg("No id_token found in token response")
		http.Error(w, "auth failed", http.StatusInternalServerError)
		return
	}
	log.Debug().Str("id_token", rawIDToken).Msg("id token received")

	provider, err := getOIDCProvider(r.Context())
	if err != nil {
		log.Error().Err(err).Msg("Failed initializing OIDC provider")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: AppConfig.GoogleClientID})
	idToken, err := verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		log.Error().Err(err).Msg("Failed to verify ID token")
		http.Error(w, "auth failed", http.StatusInternalServerError)
		return
	}

	if idToken.Nonce != oauthNonce.Value {
		log.Warn().Msg("Invalid nonce in ID token")
		http.Error(w, "auth failed", http.StatusForbidden)
		return
	}

	if err := idToken.VerifyAccessToken(token.AccessToken); err != nil {
		log.Error().Err(err).Msg("Failed to verify access token hash")
		http.Error(w, "auth failed", http.StatusInternalServerError)
		return
	}

	var ui UserInfo
	if err := idToken.Claims(&ui); err != nil {
		log.Error().Err(err).Msg("Failed parsing id_token claims")
		http.Error(w, "auth failed", http.StatusInternalServerError)
		return
	}

	// Store user: errors are logged but are not critical in the process
	GlobalStore.StoreUser(r.Context(), ui)

	handleUserLogin(w, r, &ui)
}

func handleUserLogin(w http.ResponseWriter, r *http.Request, u *UserInfo) {
	if !AppConfig.IsAllowed(u) {
		http.Redirect(w, r, "/?error=unauthorized", http.StatusSeeOther)
		return
	}

	// Create Session
	sess := Session{
		UserID:    u.ID,
		Email:     u.Email,
		Picture:   u.Picture,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	val, err := signSession(sess)
	if err != nil {
		log.Error().Err(err).Msg("Failed signing session")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    val,
		Path:     "/",
		Expires:  sess.ExpiresAt,
		HttpOnly: true,
		Secure:   AppConfig.IsSecureCookie(),
		SameSite: http.SameSiteLaxMode,
	})

	log.Info().Str("user", u.ID).Msg("User logged in")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// AuthLogoutHandler clears the session cookie
func AuthLogoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		Secure:   AppConfig.IsSecureCookie(),
		HttpOnly: true,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// AuthMeHandler returns current logged in user (if any)
func AuthMeHandler(w http.ResponseWriter, r *http.Request) {
	sess, err := GetSession(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"authenticated": false}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"authenticated": true,
		"email":         sess.Email,
		"picture":       sess.Picture,
	})
}

func signSession(s Session) (string, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return "", err
	}

	mac := hmac.New(sha256.New, []byte(AppConfig.SessionSecret))
	mac.Write(b)
	signature := mac.Sum(nil)

	// Format: base64(payload).base64(signature)
	return fmt.Sprintf("%s.%s", base64.RawURLEncoding.EncodeToString(b), base64.RawURLEncoding.EncodeToString(signature)), nil
}

func GetSession(r *http.Request) (*Session, error) {
	cookie, err := r.Cookie(CookieName)
	if err != nil {
		return nil, err
	}

	parts := strings.SplitN(cookie.Value, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid cookie format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	mac := hmac.New(sha256.New, []byte(AppConfig.SessionSecret))
	mac.Write(payload)
	expectedMAC := mac.Sum(nil)

	if !hmac.Equal(signature, expectedMAC) {
		return nil, fmt.Errorf("invalid signature")
	}

	var s Session
	if err := json.Unmarshal(payload, &s); err != nil {
		return nil, err
	}

	if time.Now().After(s.ExpiresAt) {
		return nil, fmt.Errorf("session expired")
	}

	return &s, nil
}

func generatePKCE() (verifier string, challenge string) {
	b := make([]byte, 32)
	rand.Read(b)
	verifier = base64.RawURLEncoding.EncodeToString(b)

	h := sha256.New()
	h.Write([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return verifier, challenge
}
