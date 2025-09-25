package storage

import (
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// User represents a user in the system
type User struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Password  []byte    `json:"-"` // hashed password, never serialize
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// UserStore manages users in memory
type UserStore struct {
	users    map[string]*User // username -> user
	usersByID map[string]*User // id -> user
	mutex    sync.RWMutex
	nextID   int
}

// NewUserStore creates a new in-memory user store
func NewUserStore() *UserStore {
	return &UserStore{
		users:     make(map[string]*User),
		usersByID: make(map[string]*User),
		nextID:    1,
	}
}

// RegisterUser creates a new user with hashed password
func (s *UserStore) RegisterUser(username, password string) (*User, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check if user already exists
	if _, exists := s.users[username]; exists {
		return nil, errors.New("user already exists")
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// Create user
	user := &User{
		ID:        generateUserID(s.nextID),
		Username:  username,
		Password:  hashedPassword,
		Email:     username + "@example.com", // Default email
		Name:      username,
		CreatedAt: time.Now(),
	}
	s.nextID++

	// Store user
	s.users[username] = user
	s.usersByID[user.ID] = user

	return user, nil
}

// AuthenticateUser validates username and password
func (s *UserStore) AuthenticateUser(username, password string) (*User, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	user, exists := s.users[username]
	if !exists {
		return nil, errors.New("user not found")
	}

	// Check password
	if err := bcrypt.CompareHashAndPassword(user.Password, []byte(password)); err != nil {
		return nil, errors.New("invalid password")
	}

	return user, nil
}

// GetUser retrieves a user by username
func (s *UserStore) GetUser(username string) (*User, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	user, exists := s.users[username]
	if !exists {
		return nil, errors.New("user not found")
	}

	return user, nil
}

// GetUserByID retrieves a user by ID
func (s *UserStore) GetUserByID(id string) (*User, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	user, exists := s.usersByID[id]
	if !exists {
		return nil, errors.New("user not found")
	}

	return user, nil
}

// UpdateUser updates user information
func (s *UserStore) UpdateUser(username string, email, name string) (*User, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	user, exists := s.users[username]
	if !exists {
		return nil, errors.New("user not found")
	}

	if email != "" {
		user.Email = email
	}
	if name != "" {
		user.Name = name
	}

	return user, nil
}

// ListUsers returns all users (for admin purposes)
func (s *UserStore) ListUsers() []*User {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	users := make([]*User, 0, len(s.users))
	for _, user := range s.users {
		users = append(users, user)
	}

	return users
}

// generateUserID generates a unique user ID
func generateUserID(id int) string {
	return "user_" + string(rune('0'+id%10)) + string(rune('0'+(id/10)%10)) + string(rune('0'+(id/100)%10))
}