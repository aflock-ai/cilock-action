package user

import (
	"time"

	"github.com/google/uuid"
)

// User represents a user in the system
type User struct {
	ID           uuid.UUID `json:"id" db:"id"`
	Email        string    `json:"email" db:"email"`
	PasswordHash string    `json:"-" db:"password_hash"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}

// CreateUserInput represents the input for creating a new user
type CreateUserInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Validate validates the create user input
func (c *CreateUserInput) Validate() error {
	if c.Email == "" {
		return ErrEmailRequired
	}
	if c.Password == "" {
		return ErrPasswordRequired
	}
	if len(c.Password) < 8 {
		return ErrPasswordTooShort
	}
	return nil
}
