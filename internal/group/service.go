package group

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Service provides group-related business logic
type Service struct {
	repo Repository
}

// NewService creates a new group service
func NewService(repo Repository) *Service {
	return &Service{repo: repo}
}

// Create creates a new group and adds the creator as admin
func (s *Service) Create(ctx context.Context, input *CreateGroupInput, creatorID uuid.UUID) (*Group, error) {
	if err := input.Validate(); err != nil {
		return nil, err
	}

	now := time.Now()
	group := &Group{
		ID:        uuid.New(),
		Name:      input.Name,
		CreatedBy: creatorID,
		CreatedAt: now,
	}

	if err := s.repo.Create(ctx, group); err != nil {
		return nil, err
	}

	// Add creator as admin
	membership := &Membership{
		UserID:   creatorID,
		GroupID:  group.ID,
		Role:     RoleAdmin,
		JoinedAt: now,
	}

	if err := s.repo.AddMember(ctx, membership); err != nil {
		// Rollback group creation on failure (best effort)
		_ = s.repo.Delete(ctx, group.ID)
		return nil, err
	}

	return group, nil
}

// GetByID retrieves a group by ID
func (s *Service) GetByID(ctx context.Context, id uuid.UUID) (*Group, error) {
	return s.repo.GetByID(ctx, id)
}

// ListByUserID retrieves all groups that a user is a member of
func (s *Service) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*Group, error) {
	return s.repo.ListByUserID(ctx, userID)
}

// AddMember adds a user to a group (requires admin permission)
func (s *Service) AddMember(ctx context.Context, groupID uuid.UUID, input *AddMemberInput, requestingUserID uuid.UUID) (*Membership, error) {
	if err := input.Validate(); err != nil {
		return nil, err
	}

	// Check if requesting user is admin
	membership, err := s.repo.GetMembership(ctx, groupID, requestingUserID)
	if err != nil {
		return nil, err
	}
	if membership.Role != RoleAdmin {
		return nil, ErrNotAdmin
	}

	// Set default role if not specified
	role := input.Role
	if role == "" {
		role = RoleMember
	}

	now := time.Now()
	newMembership := &Membership{
		UserID:   input.UserID,
		GroupID:  groupID,
		Role:     role,
		JoinedAt: now,
	}

	if err := s.repo.AddMember(ctx, newMembership); err != nil {
		return nil, err
	}

	return newMembership, nil
}

// RemoveMember removes a user from a group (requires admin permission)
func (s *Service) RemoveMember(ctx context.Context, groupID, userID, requestingUserID uuid.UUID) error {
	// Check if requesting user is admin
	membership, err := s.repo.GetMembership(ctx, groupID, requestingUserID)
	if err != nil {
		return err
	}
	if membership.Role != RoleAdmin {
		return ErrNotAdmin
	}

	// Prevent removing self (admin must transfer ownership first)
	if userID == requestingUserID {
		return ErrCannotRemoveSelf
	}

	return s.repo.RemoveMember(ctx, groupID, userID)
}

// IsMember checks if a user is a member of a group
func (s *Service) IsMember(ctx context.Context, groupID, userID uuid.UUID) (bool, error) {
	_, err := s.repo.GetMembership(ctx, groupID, userID)
	if err != nil {
		if err == ErrNotMember {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// GetMembership retrieves a user's membership in a group
func (s *Service) GetMembership(ctx context.Context, groupID, userID uuid.UUID) (*Membership, error) {
	return s.repo.GetMembership(ctx, groupID, userID)
}

// ListMembers retrieves all members of a group
func (s *Service) ListMembers(ctx context.Context, groupID uuid.UUID) ([]*Membership, error) {
	return s.repo.ListMembers(ctx, groupID)
}

// GetUserGroupIDs retrieves all group IDs that a user is a member of
func (s *Service) GetUserGroupIDs(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error) {
	return s.repo.GetUserGroupIDs(ctx, userID)
}

// Delete deletes a group (requires admin permission)
func (s *Service) Delete(ctx context.Context, groupID, requestingUserID uuid.UUID) error {
	// Check if requesting user is admin
	membership, err := s.repo.GetMembership(ctx, groupID, requestingUserID)
	if err != nil {
		return err
	}
	if membership.Role != RoleAdmin {
		return ErrNotAdmin
	}

	return s.repo.Delete(ctx, groupID)
}
