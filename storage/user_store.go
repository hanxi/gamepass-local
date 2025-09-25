package storage

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

// User represents a user in the system
type User struct {
	ID        string             `json:"id" bson:"id"`
	Username  string             `json:"username" bson:"username"`
	Password  []byte             `json:"-" bson:"password"` // hashed password, never serialize
	Email     string             `json:"email" bson:"email"`
	Name      string             `json:"name" bson:"name"`
	CreatedAt time.Time          `json:"created_at" bson:"created_at"`
	ObjectID  primitive.ObjectID `json:"-" bson:"_id,omitempty"`
}

// UserConsent represents a user's consent for a specific client
type UserConsent struct {
	ID        primitive.ObjectID `json:"-" bson:"_id,omitempty"`
	UserID    string             `json:"user_id" bson:"user_id"`
	ClientID  string             `json:"client_id" bson:"client_id"`
	Consented bool               `json:"consented" bson:"consented"`
	CreatedAt time.Time          `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time          `json:"updated_at" bson:"updated_at"`
}

// UserStore manages users in MongoDB
type UserStore struct {
	client             *mongo.Client
	database           *mongo.Database
	usersCollection    *mongo.Collection
	consentsCollection *mongo.Collection
	nextID             int
}

// NewUserStore creates a new MongoDB user store
func NewUserStore(mongoURI, databaseName, usersCollectionName, consentsCollectionName string) (*UserStore, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Connect to MongoDB
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	// Test the connection
	if err := client.Ping(ctx, nil); err != nil {
		return nil, fmt.Errorf("failed to ping MongoDB: %w", err)
	}

	database := client.Database(databaseName)
	usersCollection := database.Collection(usersCollectionName)
	consentsCollection := database.Collection(consentsCollectionName)

	// Create unique index on username
	indexModel := mongo.IndexModel{
		Keys:    bson.D{{Key: "username", Value: 1}},
		Options: options.Index().SetUnique(true),
	}
	_, err = usersCollection.Indexes().CreateOne(ctx, indexModel)
	if err != nil {
		return nil, fmt.Errorf("failed to create username index: %w", err)
	}

	// Create compound unique index on user_id and client_id for consents
	consentIndexModel := mongo.IndexModel{
		Keys:    bson.D{{Key: "user_id", Value: 1}, {Key: "client_id", Value: 1}},
		Options: options.Index().SetUnique(true),
	}
	_, err = consentsCollection.Indexes().CreateOne(ctx, consentIndexModel)
	if err != nil {
		return nil, fmt.Errorf("failed to create consent index: %w", err)
	}

	// Get the next ID by finding the highest existing ID
	nextID := 1
	cursor, err := usersCollection.Find(ctx, bson.D{}, options.Find().SetSort(bson.D{{Key: "id", Value: -1}}).SetLimit(1))
	if err == nil {
		defer cursor.Close(ctx)
		if cursor.Next(ctx) {
			var user User
			if err := cursor.Decode(&user); err == nil {
				if id, err := extractIDNumber(user.ID); err == nil {
					nextID = id + 1
				}
			}
		}
	}

	return &UserStore{
		client:             client,
		database:           database,
		usersCollection:    usersCollection,
		consentsCollection: consentsCollection,
		nextID:             nextID,
	}, nil
}

// NewUserStoreWithConnection creates a new UserStore with an existing MongoDB connection
func NewUserStoreWithConnection(client *mongo.Client, database *mongo.Database, usersCollectionName, consentsCollectionName string) (*UserStore, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	usersCollection := database.Collection(usersCollectionName)
	consentsCollection := database.Collection(consentsCollectionName)

	// Create unique index on username
	indexModel := mongo.IndexModel{
		Keys:    bson.D{{Key: "username", Value: 1}},
		Options: options.Index().SetUnique(true),
	}
	_, err := usersCollection.Indexes().CreateOne(ctx, indexModel)
	if err != nil {
		return nil, fmt.Errorf("failed to create username index: %w", err)
	}

	// Create compound unique index on user_id and client_id for consents
	consentIndexModel := mongo.IndexModel{
		Keys:    bson.D{{Key: "user_id", Value: 1}, {Key: "client_id", Value: 1}},
		Options: options.Index().SetUnique(true),
	}
	_, err = consentsCollection.Indexes().CreateOne(ctx, consentIndexModel)
	if err != nil {
		return nil, fmt.Errorf("failed to create consent index: %w", err)
	}

	// Get the next ID by finding the highest existing ID
	nextID := 1
	cursor, err := usersCollection.Find(ctx, bson.D{}, options.Find().SetSort(bson.D{{Key: "id", Value: -1}}).SetLimit(1))
	if err == nil {
		defer cursor.Close(ctx)
		if cursor.Next(ctx) {
			var user User
			if err := cursor.Decode(&user); err == nil {
				if id, err := extractIDNumber(user.ID); err == nil {
					nextID = id + 1
				}
			}
		}
	}

	return &UserStore{
		client:             client,
		database:           database,
		usersCollection:    usersCollection,
		consentsCollection: consentsCollection,
		nextID:             nextID,
	}, nil
}

// GetMongoClient returns the MongoDB client for reuse
func (s *UserStore) GetMongoClient() *mongo.Client {
	return s.client
}

// GetDatabase returns the MongoDB database for reuse
func (s *UserStore) GetDatabase() *mongo.Database {
	return s.database
}

// Close closes the MongoDB connection
func (s *UserStore) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.client.Disconnect(ctx)
}

// RegisterUser creates a new user with hashed password
func (s *UserStore) RegisterUser(username, password string) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

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
		Email:     username + "@local.com", // Default email
		Name:      username,
		CreatedAt: time.Now(),
	}

	// Insert user into MongoDB
	_, err = s.usersCollection.InsertOne(ctx, user)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return nil, errors.New("user already exists")
		}
		return nil, fmt.Errorf("failed to insert user: %w", err)
	}

	s.nextID++
	return user, nil
}

// AuthenticateUser validates username and password
func (s *UserStore) AuthenticateUser(username, password string) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user User
	err := s.usersCollection.FindOne(ctx, bson.M{"username": username}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.New("user not found")
		}
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	// Check password
	if err := bcrypt.CompareHashAndPassword(user.Password, []byte(password)); err != nil {
		return nil, errors.New("invalid password")
	}

	return &user, nil
}

// GetUser retrieves a user by username
func (s *UserStore) GetUser(username string) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user User
	err := s.usersCollection.FindOne(ctx, bson.M{"username": username}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.New("user not found")
		}
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	return &user, nil
}

// GetUserByID retrieves a user by ID
func (s *UserStore) GetUserByID(id string) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user User
	err := s.usersCollection.FindOne(ctx, bson.M{"id": id}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.New("user not found")
		}
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	return &user, nil
}

// UpdateUser updates user information
func (s *UserStore) UpdateUser(username string, email, name string) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	update := bson.M{}
	if email != "" {
		update["email"] = email
	}
	if name != "" {
		update["name"] = name
	}

	if len(update) == 0 {
		return s.GetUser(username)
	}

	result := s.usersCollection.FindOneAndUpdate(
		ctx,
		bson.M{"username": username},
		bson.M{"$set": update},
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	)

	var user User
	if err := result.Decode(&user); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.New("user not found")
		}
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	return &user, nil
}

// ListUsers returns all users (for admin purposes)
func (s *UserStore) ListUsers() []*User {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cursor, err := s.usersCollection.Find(ctx, bson.D{})
	if err != nil {
		return []*User{}
	}
	defer cursor.Close(ctx)

	var users []*User
	for cursor.Next(ctx) {
		var user User
		if err := cursor.Decode(&user); err == nil {
			users = append(users, &user)
		}
	}

	return users
}

// HasUserConsented checks if a user has consented to a specific client
func (s *UserStore) HasUserConsented(userID, clientID string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var consent UserConsent
	err := s.consentsCollection.FindOne(ctx, bson.M{
		"user_id":   userID,
		"client_id": clientID,
	}).Decode(&consent)

	if err != nil {
		return false
	}

	return consent.Consented
}

// StoreUserConsent stores a user's consent decision for a specific client
func (s *UserStore) StoreUserConsent(userID, clientID string, consented bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	now := time.Now()
	consent := UserConsent{
		UserID:    userID,
		ClientID:  clientID,
		Consented: consented,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Use upsert to update if exists, insert if not
	opts := options.Replace().SetUpsert(true)
	_, err := s.consentsCollection.ReplaceOne(ctx, bson.M{
		"user_id":   userID,
		"client_id": clientID,
	}, consent, opts)

	if err != nil {
		return fmt.Errorf("failed to store user consent: %w", err)
	}

	return nil
}

// RevokeUserConsent revokes a user's consent for a specific client
func (s *UserStore) RevokeUserConsent(userID, clientID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.consentsCollection.DeleteOne(ctx, bson.M{
		"user_id":   userID,
		"client_id": clientID,
	})

	if err != nil {
		return fmt.Errorf("failed to revoke user consent: %w", err)
	}

	return nil
}

// generateUserID generates a unique user ID
func generateUserID(id int) string {
	return fmt.Sprintf("user_%03d", id)
}

// extractIDNumber extracts the numeric part from a user ID
func extractIDNumber(userID string) (int, error) {
	if len(userID) < 5 || userID[:5] != "user_" {
		return 0, errors.New("invalid user ID format")
	}
	return strconv.Atoi(userID[5:])
}
