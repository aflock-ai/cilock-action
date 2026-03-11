package user

import (
	"context"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Service provides user-related business logic
type Service struct {
	repo Repository
}

// NewService creates a new user service
func NewService(repo Repository) *Service {
	return &Service{repo: repo}
}

// Register creates a new user with hashed password
func (s *Service) Register(ctx context.Context, input *CreateUserInput) (*User, error) {
	if err := input.Validate(); err != nil {
		return nil, err
	}

	// Hash the password
	hashedPassword, err := hashPassword(input.Password)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	user := &User{
		ID:           uuid.New(),
		Email:        input.Email,
		PasswordHash: hashedPassword,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.repo.Create(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}

// Authenticate verifies user credentials and returns the user
func (s *Service) Authenticate(ctx context.Context, email, password string) (*User, error) {
	user, err := s.repo.GetByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	if !checkPassword(password, user.PasswordHash) {
		return nil, ErrInvalidPassword
	}

	return user, nil
}

// GetByID retrieves a user by ID
func (s *Service) GetByID(ctx context.Context, id uuid.UUID) (*User, error) {
	return s.repo.GetByID(ctx, id)
}

// GetByEmail retrieves a user by email
func (s *Service) GetByEmail(ctx context.Context, email string) (*User, error) {
	return s.repo.GetByEmail(ctx, email)
}

// hashPassword hashes a password using bcrypt
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// checkPassword compares a password with a hash
func checkPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// HashPassword is exported for testing
func HashPassword(password string) (string, error) {
	return hashPassword(password)
}

// CheckPassword is exported for testing
func CheckPassword(password, hash string) bool {
	return checkPassword(password, hash)
}
