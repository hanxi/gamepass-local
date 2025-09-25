package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/hanxi/gamepass-local/storage"
	"github.com/ory/fosite"
)

var (
	userStore      *storage.UserStore
	oauth2Provider fosite.OAuth2Provider
	templates      *template.Template
)

// InitUserHandlers initializes the handlers with dependencies
func InitUserHandlers(us *storage.UserStore, provider fosite.OAuth2Provider) {
	userStore = us
	oauth2Provider = provider

	// Load templates
	var err error
	templates, err = template.ParseGlob("templates/*.html")
	if err != nil {
		panic(fmt.Sprintf("Failed to load templates: %v", err))
	}
}

// RegisterHandler handles user registration
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// Show registration form
		templates.ExecuteTemplate(w, "register.html", nil)
		return
	}

	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")
		confirmPassword := r.FormValue("confirm_password")

		log.Printf("[RegisterHandler] Registration attempt for username: %s", username)

		// Validate input
		if username == "" || password == "" {
			log.Printf("[RegisterHandler] Validation failed: empty username or password")
			templates.ExecuteTemplate(w, "register.html", map[string]string{
				"Error": "Username and password are required",
			})
			return
		}

		if password != confirmPassword {
			log.Printf("[RegisterHandler] Validation failed: passwords do not match")
			templates.ExecuteTemplate(w, "register.html", map[string]string{
				"Error": "Passwords do not match",
			})
			return
		}

		// Register user
		user, err := userStore.RegisterUser(username, password)
		if err != nil {
			log.Printf("[RegisterHandler] Registration failed for username %s: %v", username, err)
			templates.ExecuteTemplate(w, "register.html", map[string]string{
				"Error": err.Error(),
			})
			return
		}

		log.Printf("[RegisterHandler] Registration successful for username: %s, userID: %s", username, user.ID)
		// Redirect to login
		http.Redirect(w, r, "/login?message=Registration successful", http.StatusSeeOther)
	}
}

// LoginHandler handles user login
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		message := r.URL.Query().Get("message")
		redirectURL := r.URL.Query().Get("redirect_url")
		log.Printf("[LoginHandler] GET request, message: %s, redirect_url: %s", message, redirectURL)
		templates.ExecuteTemplate(w, "login.html", map[string]string{
			"Message":     message,
			"RedirectURL": redirectURL,
		})
		return
	}

	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")
		redirectURL := r.FormValue("redirect_url")

		log.Printf("[LoginHandler] Login attempt for username: %s, redirect_url: %s", username, redirectURL)

		// Authenticate user
		user, err := userStore.AuthenticateUser(username, password)
		if err != nil {
			log.Printf("[LoginHandler] Authentication failed for username %s: %v", username, err)
			templates.ExecuteTemplate(w, "login.html", map[string]string{
				"Error": "Invalid username or password",
			})
			return
		}

		log.Printf("[LoginHandler] Authentication successful for username: %s, userID: %s", username, user.ID)

		// Create session (simple cookie-based session)
		http.SetCookie(w, &http.Cookie{
			Name:     "user_session",
			Value:    user.ID,
			Path:     "/",
			HttpOnly: true,
			Secure:   false, // Set to true in production with HTTPS
			MaxAge:   3600,  // 1 hour
		})

		log.Printf("[LoginHandler] Session cookie set for userID: %s", user.ID)

		// Check if there's a redirect URL from OAuth flow
		if redirectURL != "" {
			log.Printf("[LoginHandler] Redirecting to OAuth flow: %s", redirectURL)
			http.Redirect(w, r, redirectURL, http.StatusSeeOther)
			return
		}

		// Default redirect to user info
		log.Printf("[LoginHandler] Redirecting to /userinfo for userID: %s", user.ID)
		http.Redirect(w, r, "/userinfo", http.StatusSeeOther)
	}
}

// ConsentHandler handles OAuth2 consent
func ConsentHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[ConsentHandler] %s request to %s", r.Method, r.URL.String())

	// Get user from session
	user := getUserFromSession(r)
	if user == nil {
		log.Printf("[ConsentHandler] No user session found, redirecting to login")
		// Redirect to login with return URL
		loginURL := fmt.Sprintf("/login?redirect_url=%s", url.QueryEscape(r.URL.String()))
		http.Redirect(w, r, loginURL, http.StatusSeeOther)
		return
	}

	log.Printf("[ConsentHandler] User found in session: %s (ID: %s)", user.Username, user.ID)

	if r.Method == "GET" {
		// Parse OAuth2 parameters
		clientID := r.URL.Query().Get("client_id")
		scopes := strings.Split(r.URL.Query().Get("scope"), " ")

		log.Printf("[ConsentHandler] Showing consent page for client: %s, scopes: %v", clientID, scopes)

		templates.ExecuteTemplate(w, "consent.html", map[string]interface{}{
			"User":     user,
			"ClientID": clientID,
			"Scopes":   scopes,
			"Query":    r.URL.RawQuery,
		})
		return
	}

	if r.Method == "POST" {
		// Handle consent decision
		if r.FormValue("consent") == "allow" {
			log.Printf("[ConsentHandler] User %s granted consent", user.Username)
			// Redirect back to authorize endpoint with consent
			query := r.FormValue("query")
			var authorizeURL string
			if query != "" {
				authorizeURL = "/authorize?" + query + "&consent=granted"
			} else {
				authorizeURL = "/authorize?consent=granted"
			}
			log.Printf("[ConsentHandler] Redirecting to: %s", authorizeURL)
			http.Redirect(w, r, authorizeURL, http.StatusSeeOther)
		} else {
			log.Printf("[ConsentHandler] User %s denied consent", user.Username)
			// Deny consent
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Access denied"))
		}
	}
}

// AuthorizeHandler handles OAuth2 authorization
func AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[AuthorizeHandler] %s request to %s", r.Method, r.URL.String())
	ctx := context.Background()

	// Get user from session
	user := getUserFromSession(r)
	if user == nil {
		log.Printf("[AuthorizeHandler] No user session found, redirecting to login")
		// Redirect to login with return URL
		loginURL := fmt.Sprintf("/login?redirect_url=%s", url.QueryEscape(r.URL.String()))
		http.Redirect(w, r, loginURL, http.StatusSeeOther)
		return
	}

	log.Printf("[AuthorizeHandler] User found in session: %s (ID: %s)", user.Username, user.ID)

	// Create OAuth2 session with OpenID Connect support
	session := &fosite.DefaultSession{
		Username: user.Username,
		Subject:  user.ID,
		Extra: map[string]interface{}{
			"name":  user.Name,
			"email": user.Email,
		},
	}

	// Handle authorization request
	ar, err := oauth2Provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		log.Printf("[AuthorizeHandler] Failed to create authorize request: %v", err)
		oauth2Provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	log.Printf("[AuthorizeHandler] Authorize request created for client: %s, scopes: %v", ar.GetClient().GetID(), ar.GetRequestedScopes())

	// Check if user has already consented (simple check)
	if !hasUserConsented(r) {
		log.Printf("[AuthorizeHandler] User has not consented, redirecting to consent page")
		// Redirect to consent page
		consentURL := fmt.Sprintf("/consent?%s", r.URL.RawQuery)
		http.Redirect(w, r, consentURL, http.StatusSeeOther)
		return
	}

	log.Printf("[AuthorizeHandler] User has consented, completing authorization")

	// User has consented, complete authorization
	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}

	// Create the response
	log.Printf("[AuthorizeHandler] Creating authorize response with session: Username=%s, Subject=%s", session.Username, session.Subject)
	response, err := oauth2Provider.NewAuthorizeResponse(ctx, ar, session)
	if err != nil {
		log.Printf("[AuthorizeHandler] Failed to create authorize response: %v", err)
		log.Printf("[AuthorizeHandler] Error type: %T", err)

		// Try to get more specific error information
		if fositeErr, ok := err.(*fosite.RFC6749Error); ok {
			log.Printf("[AuthorizeHandler] Fosite error code: %s", fositeErr.ErrorField)
			log.Printf("[AuthorizeHandler] Fosite error description: %s", fositeErr.DescriptionField)
			log.Printf("[AuthorizeHandler] Fosite error hint: %s", fositeErr.HintField)
		}

		// Log request details for debugging
		log.Printf("[AuthorizeHandler] Request details - Client: %s, Scopes: %v, ResponseTypes: %v",
			ar.GetClient().GetID(), ar.GetRequestedScopes(), ar.GetResponseTypes())
		log.Printf("[AuthorizeHandler] Session details - Username: %s, Subject: %s",
			session.Username, session.Subject)

		oauth2Provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	log.Printf("[AuthorizeHandler] Authorization successful, writing response")
	oauth2Provider.WriteAuthorizeResponse(ctx, w, ar, response)
}

// TokenHandler handles OAuth2 token exchange
func TokenHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[TokenHandler] %s request to %s", r.Method, r.URL.String())
	log.Printf("[TokenHandler] Headers: %v", r.Header)

	ctx := context.Background()

	// Parse form to get parameters
	if err := r.ParseForm(); err != nil {
		log.Printf("[TokenHandler] Failed to parse form: %v", err)
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	log.Printf("[TokenHandler] Form values: %v", r.Form)

	grantType := r.FormValue("grant_type")
	code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")

	log.Printf("[TokenHandler] Grant type: %s", grantType)
	log.Printf("[TokenHandler] Authorization code: %s", code)
	log.Printf("[TokenHandler] Client ID: %s", clientID)
	log.Printf("[TokenHandler] Redirect URI: %s", redirectURI)

	// Debug: Print all form values
	for key, values := range r.Form {
		log.Printf("[TokenHandler] Form field %s: %v", key, values)
	}

	// Create session
	session := &fosite.DefaultSession{}

	// Handle token request
	ar, err := oauth2Provider.NewAccessRequest(ctx, r, session)
	if err != nil {
		log.Printf("[TokenHandler] Failed to create access request: %v", err)
		log.Printf("[TokenHandler] Error type: %T", err)

		// Try to get more specific error information
		if fositeErr, ok := err.(*fosite.RFC6749Error); ok {
			log.Printf("[TokenHandler] Fosite error code: %s", fositeErr.ErrorField)
			log.Printf("[TokenHandler] Fosite error description: %s", fositeErr.DescriptionField)
			log.Printf("[TokenHandler] Fosite error hint: %s", fositeErr.HintField)
		}

		oauth2Provider.WriteAccessError(ctx, w, ar, err)
		return
	}

	log.Printf("[TokenHandler] Access request created for client: %s", ar.GetClient().GetID())

	// Create token response
	response, err := oauth2Provider.NewAccessResponse(ctx, ar)
	if err != nil {
		log.Printf("[TokenHandler] Failed to create access response: %v", err)
		log.Printf("[TokenHandler] Error type: %T", err)

		if fositeErr, ok := err.(*fosite.RFC6749Error); ok {
			log.Printf("[TokenHandler] Fosite error code: %s", fositeErr.ErrorField)
			log.Printf("[TokenHandler] Fosite error description: %s", fositeErr.DescriptionField)
			log.Printf("[TokenHandler] Fosite error hint: %s", fositeErr.HintField)
		}

		oauth2Provider.WriteAccessError(ctx, w, ar, err)
		return
	}

	log.Printf("[TokenHandler] Token exchange successful")
	oauth2Provider.WriteAccessResponse(ctx, w, ar, response)
}

// UserInfoHandler handles OIDC userinfo endpoint
func UserInfoHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[UserInfoHandler] %s request to %s", r.Method, r.URL.String())
	log.Printf("[UserInfoHandler] Headers: %v", r.Header)

	ctx := context.Background()
	var user *storage.User
	var authMethod string

	// Try OAuth2 access token first
	token := fosite.AccessTokenFromRequest(r)
	log.Printf("[UserInfoHandler] Extracted token from request: '%s' (length: %d)", token, len(token))

	if token != "" {
		log.Printf("[UserInfoHandler] Attempting OAuth2 token validation")
		// Validate access token
		session := &fosite.DefaultSession{}
		_, ar, err := oauth2Provider.IntrospectToken(ctx, token, fosite.AccessToken, session)
		if err != nil {
			log.Printf("[UserInfoHandler] OAuth2 token introspection failed: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_token", "error_description": "Token validation failed"})
			return
		}

		log.Printf("[UserInfoHandler] OAuth2 token validation successful")
		authMethod = "oauth2_token"

		// Get user info from OAuth2 session
		userID := ar.GetSession().GetSubject()
		log.Printf("[UserInfoHandler] Getting user info for userID: %s", userID)

		user, err = userStore.GetUserByID(userID)
		if err != nil {
			log.Printf("[UserInfoHandler] Failed to get user by ID %s: %v", userID, err)
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "user_not_found"})
			return
		}
	} else {
		log.Printf("[UserInfoHandler] No OAuth2 access token found, trying session cookie")
		// Try session cookie authentication
		user = getUserFromSession(r)
		if user == nil {
			log.Printf("[UserInfoHandler] No valid session cookie found")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error":             "invalid_token",
				"error_description": "No valid access token or session found",
			})
			return
		}

		log.Printf("[UserInfoHandler] Session cookie authentication successful for user: %s", user.Username)
		authMethod = "session_cookie"
	}

	// Return user info
	userInfo := map[string]interface{}{
		"sub":   user.ID,
		"name":  user.Name,
		"email": user.Email,
	}

	log.Printf("[UserInfoHandler] Returning user info for user: %s (auth method: %s)", user.Username, authMethod)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
}

// Helper functions

func getUserFromSession(r *http.Request) *storage.User {
	cookie, err := r.Cookie("user_session")
	if err != nil {
		log.Printf("[getUserFromSession] No user_session cookie found: %v", err)
		return nil
	}

	log.Printf("[getUserFromSession] Found session cookie with userID: %s", cookie.Value)

	user, err := userStore.GetUserByID(cookie.Value)
	if err != nil {
		log.Printf("[getUserFromSession] Failed to get user by ID %s: %v", cookie.Value, err)
		return nil
	}

	log.Printf("[getUserFromSession] Successfully retrieved user: %s (ID: %s)", user.Username, user.ID)
	return user
}

func hasUserConsented(r *http.Request) bool {
	// Simple consent check - in a real app, you'd store consent decisions
	// For this demo, we'll check if the request came from the consent page
	consented := r.URL.Query().Get("consent") == "granted" || r.Referer() == "http://localhost:3000/consent"
	log.Printf("[hasUserConsented] Consent check result: %v (consent param: %s, referer: %s)",
		consented, r.URL.Query().Get("consent"), r.Referer())
	return consented
}
