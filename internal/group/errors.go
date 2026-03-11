package group

import "errors"

var (
	ErrGroupNotFound    = errors.New("group not found")
	ErrNameRequired     = errors.New("name is required")
	ErrUserIDRequired   = errors.New("user ID is required")
	ErrInvalidRole      = errors.New("invalid role")
	ErrNotMember        = errors.New("user is not a member of this group")
	ErrAlreadyMember    = errors.New("user is already a member of this group")
	ErrCannotRemoveSelf = errors.New("cannot remove yourself from the group")
	ErrNotAdmin         = errors.New("user is not an admin of this group")
)
