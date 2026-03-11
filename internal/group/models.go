package group

import (
	"time"

	"github.com/google/uuid"
)

// Group represents a group in the system
type Group struct {
	ID        uuid.UUID `json:"id" db:"id"`
	Name      string    `json:"name" db:"name"`
	CreatedBy uuid.UUID `json:"created_by" db:"created_by"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// Membership represents a user's membership in a group
type Membership struct {
	UserID   uuid.UUID `json:"user_id" db:"user_id"`
	GroupID  uuid.UUID `json:"group_id" db:"group_id"`
	Role     string    `json:"role" db:"role"`
	JoinedAt time.Time `json:"joined_at" db:"joined_at"`
}

// Role constants
const (
	RoleAdmin  = "admin"
	RoleMember = "member"
)

// CreateGroupInput represents the input for creating a new group
type CreateGroupInput struct {
	Name string `json:"name"`
}

// Validate validates the create group input
func (c *CreateGroupInput) Validate() error {
	if c.Name == "" {
		return ErrNameRequired
	}
	return nil
}

// AddMemberInput represents the input for adding a member to a group
type AddMemberInput struct {
	UserID uuid.UUID `json:"user_id"`
	Role   string    `json:"role"`
}

// Validate validates the add member input
func (a *AddMemberInput) Validate() error {
	if a.UserID == uuid.Nil {
		return ErrUserIDRequired
	}
	if a.Role != "" && a.Role != RoleAdmin && a.Role != RoleMember {
		return ErrInvalidRole
	}
	return nil
}
