// main.go
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/hanxi/gamepass-local/handler"
	"github.com/hanxi/gamepass-local/storage"

	"github.com/joho/godotenv"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"golang.org/x/crypto/bcrypt"
)

var (
	fositeStore *storage.FositeStore
)

func main() {
	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: .env file not found: %v", err)
	}

	// Get configuration from environment variables
	port := getEnv("PORT", "3000")
	host := getEnv("HOST", "localhost")
	systemSecret := []byte(getEnv("SYSTEM_SECRET", "some-super-secret-key-that-is-32-bytes-long-for-security"))
	clientID := getEnv("CLIENT_ID", "my-client")
	clientSecret := getEnv("CLIENT_SECRET", "my-secret")
	issuer := getEnv("ISSUER", "http://localhost:3000")
	redirectURI := getEnv("REDIRECT_URI", "http://home.hanxi.cc:3180/auth/local-oidc/callback")

	// Parse token lifespans
	accessTokenLifetime := parseDuration(getEnv("ACCESS_TOKEN_LIFETIME", "3600"))
	authorizeCodeLifetime := parseDuration(getEnv("AUTHORIZE_CODE_LIFETIME", "600"))
	idTokenLifetime := parseDuration(getEnv("ID_TOKEN_LIFETIME", "3600"))
	refreshTokenLifetime := parseDuration(getEnv("REFRESH_TOKEN_LIFETIME", "604800"))

	// Initialize stores
	fositeStore = storage.NewFositeStore()
	userStore := storage.NewUserStore()

	// Register a dummy user for testing
	if _, err := userStore.RegisterUser("testuser", "password123"); err != nil {
		log.Fatalf("Failed to register initial user: %v", err)
	}

	// Register a client application
	client := &fosite.DefaultClient{
		ID:            clientID,
		Secret:        mustHash(clientSecret),
		RedirectURIs:  []string{redirectURI},
		ResponseTypes: []string{"code"},
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		Scopes:        []string{"openid", "profile", "offline_access"},
		Audience:      []string{issuer + "/api"},
	}
	fositeStore.AddClient(client)

	// Fosite configuration
	config := &fosite.Config{
		AccessTokenLifespan:   accessTokenLifetime,
		AuthorizeCodeLifespan: authorizeCodeLifetime,
		IDTokenLifespan:       idTokenLifetime,
		RefreshTokenLifespan:  refreshTokenLifetime,
		ScopeStrategy:         fosite.ExactScopeStrategy,
	}

	// Create the Fosite provider
	oauth2Provider := compose.ComposeAllEnabled(config, fositeStore, systemSecret)

	// Initialize handlers
	handler.InitUserHandlers(userStore, oauth2Provider, fositeStore)

	// Setup routes
	http.HandleFunc("/register", handler.RegisterHandler)
	http.HandleFunc("/login", handler.LoginHandler)
	http.HandleFunc("/consent", handler.ConsentHandler)
	http.HandleFunc("/authorize", handler.AuthorizeHandler)
	http.HandleFunc("/token", handler.TokenHandler)
	http.HandleFunc("/userinfo", handler.UserInfoHandler)

	// OIDC Discovery endpoint
	http.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		config := map[string]interface{}{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"userinfo_endpoint":                     issuer + "/userinfo",
			"jwks_uri":                              issuer + "/.well-known/jwks.json",
			"scopes_supported":                      []string{"openid", "profile", "offline_access"},
			"response_types_supported":              []string{"code"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"HS256"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config)
	})

	// Static file server for assets (if needed)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	serverAddr := host + ":" + port
	log.Printf("Starting OIDC IdP server on http://%s", serverAddr)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

// getEnv gets environment variable with fallback
func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

// parseDuration parses duration from string (seconds)
func parseDuration(s string) time.Duration {
	seconds, err := strconv.Atoi(s)
	if err != nil {
		log.Printf("Warning: invalid duration %s, using default", s)
		return time.Hour
	}
	return time.Duration(seconds) * time.Second
}

// mustHash hashes a password using bcrypt. Panics on error.
func mustHash(password string) []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	return hash
}
