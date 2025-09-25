package storage

import (
	"context"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/ory/fosite"
	"golang.org/x/crypto/bcrypt"
)

// FositeStore implements all the storage interfaces required by fosite
type FositeStore struct {
	clients        map[string]fosite.Client
	authorizeCodes map[string]fosite.Requester
	accessTokens   map[string]fosite.Requester
	refreshTokens  map[string]fosite.Requester
	idTokens       map[string]fosite.Requester
	pkces          map[string]fosite.Requester
	mutex          sync.RWMutex
}

// NewFositeStore creates a new in-memory fosite store
func NewFositeStore() *FositeStore {
	return &FositeStore{
		clients:        make(map[string]fosite.Client),
		authorizeCodes: make(map[string]fosite.Requester),
		accessTokens:   make(map[string]fosite.Requester),
		refreshTokens:  make(map[string]fosite.Requester),
		idTokens:       make(map[string]fosite.Requester),
		pkces:          make(map[string]fosite.Requester),
	}
}

// Client storage interface
func (s *FositeStore) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// First try instance clients
	client, ok := s.clients[id]
	if ok {
		return client, nil
	}
	return nil, fosite.ErrNotFound
}

// Authorization code storage interface
func (s *FositeStore) CreateAuthorizeCodeSession(ctx context.Context, code string, req fosite.Requester) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.authorizeCodes[code] = req
	return nil
}

func (s *FositeStore) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	req, ok := s.authorizeCodes[code]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return req, nil
}

func (s *FositeStore) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.authorizeCodes, code)
	return nil
}

// Access token storage interface
func (s *FositeStore) CreateAccessTokenSession(ctx context.Context, signature string, req fosite.Requester) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.accessTokens[signature] = req
	return nil
}

func (s *FositeStore) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	req, ok := s.accessTokens[signature]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return req, nil
}

func (s *FositeStore) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.accessTokens, signature)
	return nil
}

// Refresh token storage interface
func (s *FositeStore) CreateRefreshTokenSession(ctx context.Context, signature string, requestID string, request fosite.Requester) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.refreshTokens[signature] = request
	return nil
}

func (s *FositeStore) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	req, ok := s.refreshTokens[signature]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return req, nil
}

func (s *FositeStore) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.refreshTokens, signature)
	return nil
}

// RotateRefreshToken rotates a refresh token
func (s *FositeStore) RotateRefreshToken(ctx context.Context, requestID string, newSignature string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Find and remove the old refresh token by request ID
	for signature, req := range s.refreshTokens {
		if req.GetID() == requestID {
			delete(s.refreshTokens, signature)
			break
		}
	}
	return nil
}

// ID token storage interface
func (s *FositeStore) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, req fosite.Requester) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.idTokens[authorizeCode] = req
	return nil
}

func (s *FositeStore) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, req fosite.Requester) (fosite.Requester, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	session, ok := s.idTokens[authorizeCode]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return session, nil
}

func (s *FositeStore) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.idTokens, authorizeCode)
	return nil
}

// PKCE storage interface
func (s *FositeStore) CreatePKCERequestSession(ctx context.Context, signature string, req fosite.Requester) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.pkces[signature] = req
	return nil
}

func (s *FositeStore) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	req, ok := s.pkces[signature]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return req, nil
}

func (s *FositeStore) DeletePKCERequestSession(ctx context.Context, signature string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.pkces, signature)
	return nil
}

// RevokeRefreshToken revokes a refresh token
func (s *FositeStore) RevokeRefreshToken(ctx context.Context, requestID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for signature, req := range s.refreshTokens {
		if req.GetID() == requestID {
			delete(s.refreshTokens, signature)
		}
	}
	return nil
}

// RevokeAccessToken revokes an access token
func (s *FositeStore) RevokeAccessToken(ctx context.Context, requestID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for signature, req := range s.accessTokens {
		if req.GetID() == requestID {
			delete(s.accessTokens, signature)
		}
	}
	return nil
}

// Authenticate is used for client authentication
func (s *FositeStore) Authenticate(ctx context.Context, name string, secret string) (string, error) {
	client, err := s.GetClient(ctx, name)
	if err != nil {
		return "", err
	}

	if client.IsPublic() {
		return name, nil
	}

	err = bcrypt.CompareHashAndPassword(client.(*fosite.DefaultClient).GetHashedSecret(), []byte(secret))
	if err != nil {
		return "", err
	}

	return name, nil
}

// ClientAssertionJWTValid validates client JWT assertions
func (s *FositeStore) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	// For this simple implementation, we'll just return nil (allow all)
	// In a production environment, you would want to:
	// 1. Store used JTIs to prevent replay attacks
	// 2. Check if the JTI has been used before
	// 3. Implement proper JWT validation logic
	return nil
}

// SetClientAssertionJWT stores client JWT assertions
func (s *FositeStore) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	// For this simple implementation, we'll just return nil (accept all)
	// In a production environment, you would want to:
	// 1. Store the JTI with its expiration time
	// 2. Implement cleanup for expired JTIs
	// 3. Prevent replay attacks by tracking used JTIs
	return nil
}

// GetClientCredentials returns client credentials
func (s *FositeStore) GetClientCredentials(ctx context.Context, id string) (fosite.Client, error) {
	return s.GetClient(ctx, id)
}

// IsJWTUsed checks if a JWT has been used before
func (s *FositeStore) IsJWTUsed(ctx context.Context, jti string) (bool, error) {
	// For this simple implementation, we'll always return false (not used)
	return false, nil
}

// MarkJWTUsedForTime marks a JWT as used for a specific time
func (s *FositeStore) MarkJWTUsedForTime(ctx context.Context, jti string, exp time.Time) error {
	// For this simple implementation, we'll just return nil
	return nil
}

// GetPublicKey returns the public key for JWT verification
func (s *FositeStore) GetPublicKey(ctx context.Context, issuer string, subject string, keyId string) (*jose.JSONWebKey, error) {
	// For this simple implementation, we'll return an error indicating not found
	return nil, fosite.ErrNotFound
}

// GetPublicKeys returns public keys for JWT verification
func (s *FositeStore) GetPublicKeys(ctx context.Context, issuer string, subject string) (*jose.JSONWebKeySet, error) {
	// For this simple implementation, we'll return an error indicating not found
	return nil, fosite.ErrNotFound
}

// GetPublicKeyScopes returns the scopes associated with a public key
func (s *FositeStore) GetPublicKeyScopes(ctx context.Context, issuer string, subject string, keyId string) ([]string, error) {
	// For this simple implementation, we'll return empty scopes
	return []string{}, nil
}

func (s *FositeStore) AddClient(client fosite.Client) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.clients[client.GetID()] = client
}
