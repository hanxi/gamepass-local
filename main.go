// main.go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/hanxi/gamepass-local/handler"
	"github.com/hanxi/gamepass-local/storage"
	"github.com/hanxi/gamepass-local/utils"

	"github.com/joho/godotenv"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: .env file not found: %v", err)
	}

	// Get configuration from environment variables
	port := utils.GetEnv("PORT", "3000")
	host := utils.GetEnv("HOST", "localhost")
	systemSecret := []byte(utils.GetEnv("SYSTEM_SECRET", "some-cool-secret-that-is-32bytes"))
	clientID := utils.GetEnv("CLIENT_ID", "my-client")
	clientSecret := utils.GetEnv("CLIENT_SECRET", "foobar")
	issuer := utils.GetEnv("ISSUER", "http://localhost:3000")
	redirectURI := utils.GetEnv("REDIRECT_URI", "http://localhost:4000/auth/local-oidc/callback")

	// Parse token lifespans
	accessTokenLifetime := parseDuration(utils.GetEnv("ACCESS_TOKEN_LIFETIME", "3600"))
	authorizeCodeLifetime := parseDuration(utils.GetEnv("AUTHORIZE_CODE_LIFETIME", "600"))
	idTokenLifetime := parseDuration(utils.GetEnv("ID_TOKEN_LIFETIME", "3600"))
	refreshTokenLifetime := parseDuration(utils.GetEnv("REFRESH_TOKEN_LIFETIME", "604800"))

	// Initialize stores
	userStore := storage.NewUserStore()
	fositeStore := storage.NewMemoryStore(userStore)

	// Register a dummy user for testing
	if _, err := userStore.RegisterUser("testuser", "password123"); err != nil {
		log.Fatalf("Failed to register initial user: %v", err)
	}

	client := &fosite.DefaultClient{
		ID:            clientID,
		Secret:        mustHash(clientSecret),
		RedirectURIs:  []string{redirectURI},
		ResponseTypes: []string{"code"},
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		Scopes:        []string{"openid", "profile", "offline_access"},
	}
	fositeStore.Clients[clientID] = client
	log.Printf("Created new client configuration for %s", clientID)
	// }

	// Fosite configuration
	config := &fosite.Config{
		AccessTokenLifespan:   accessTokenLifetime,
		AuthorizeCodeLifespan: authorizeCodeLifetime,
		IDTokenLifespan:       idTokenLifetime,
		RefreshTokenLifespan:  refreshTokenLifetime,
		ScopeStrategy:         fosite.ExactScopeStrategy,
		GlobalSecret:          systemSecret,
	}

	// Create the Fosite provider
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	oauth2Provider := compose.ComposeAllEnabled(config, fositeStore, privateKey)

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
