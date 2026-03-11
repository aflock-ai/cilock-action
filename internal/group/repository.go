package group

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
)

// Repository defines the interface for group data operations
type Repository interface {
	Create(ctx context.Context, group *Group) error
	GetByID(ctx context.Context, id uuid.UUID) (*Group, error)
	Delete(ctx context.Context, id uuid.UUID) error
	ListByUserID(ctx context.Context, userID uuid.UUID) ([]*Group, error)

	// Membership operations
	AddMember(ctx context.Context, membership *Membership) error
	RemoveMember(ctx context.Context, groupID, userID uuid.UUID) error
	GetMembership(ctx context.Context, groupID, userID uuid.UUID) (*Membership, error)
	ListMembers(ctx context.Context, groupID uuid.UUID) ([]*Membership, error)
	GetUserGroupIDs(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error)
}

// PostgresRepository implements Repository using PostgreSQL
type PostgresRepository struct {
	db *sql.DB
}

// NewPostgresRepository creates a new PostgresRepository
func NewPostgresRepository(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{db: db}
}

// Create inserts a new group into the database
func (r *PostgresRepository) Create(ctx context.Context, group *Group) error {
	query := `
		INSERT INTO groups (id, name, created_by, created_at)
		VALUES ($1, $2, $3, $4)
	`
	_, err := r.db.ExecContext(ctx, query,
		group.ID, group.Name, group.CreatedBy, group.CreatedAt)
	return err
}

// GetByID retrieves a group by ID
func (r *PostgresRepository) GetByID(ctx context.Context, id uuid.UUID) (*Group, error) {
	query := `
		SELECT id, name, created_by, created_at
		FROM groups
		WHERE id = $1
	`
	group := &Group{}
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&group.ID, &group.Name, &group.CreatedBy, &group.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrGroupNotFound
		}
		return nil, err
	}
	return group, nil
}

// Delete removes a group from the database
func (r *PostgresRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM groups WHERE id = $1`
	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return ErrGroupNotFound
	}
	return nil
}

// ListByUserID retrieves all groups that a user is a member of
func (r *PostgresRepository) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*Group, error) {
	query := `
		SELECT g.id, g.name, g.created_by, g.created_at
		FROM groups g
		INNER JOIN user_groups ug ON g.id = ug.group_id
		WHERE ug.user_id = $1
		ORDER BY g.created_at DESC
	`
	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var groups []*Group
	for rows.Next() {
		group := &Group{}
		if err := rows.Scan(&group.ID, &group.Name, &group.CreatedBy, &group.CreatedAt); err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, rows.Err()
}

// AddMember adds a user to a group
func (r *PostgresRepository) AddMember(ctx context.Context, membership *Membership) error {
	query := `
		INSERT INTO user_groups (user_id, group_id, role, joined_at)
		VALUES ($1, $2, $3, $4)
	`
	_, err := r.db.ExecContext(ctx, query,
		membership.UserID, membership.GroupID, membership.Role, membership.JoinedAt)
	if err != nil {
		// Check for unique constraint violation
		if isUniqueViolation(err) {
			return ErrAlreadyMember
		}
		return err
	}
	return nil
}

// RemoveMember removes a user from a group
func (r *PostgresRepository) RemoveMember(ctx context.Context, groupID, userID uuid.UUID) error {
	query := `DELETE FROM user_groups WHERE group_id = $1 AND user_id = $2`
	result, err := r.db.ExecContext(ctx, query, groupID, userID)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return ErrNotMember
	}
	return nil
}

// GetMembership retrieves a user's membership in a group
func (r *PostgresRepository) GetMembership(ctx context.Context, groupID, userID uuid.UUID) (*Membership, error) {
	query := `
		SELECT user_id, group_id, role, joined_at
		FROM user_groups
		WHERE group_id = $1 AND user_id = $2
	`
	membership := &Membership{}
	err := r.db.QueryRowContext(ctx, query, groupID, userID).Scan(
		&membership.UserID, &membership.GroupID, &membership.Role, &membership.JoinedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotMember
		}
		return nil, err
	}
	return membership, nil
}

// ListMembers retrieves all members of a group
func (r *PostgresRepository) ListMembers(ctx context.Context, groupID uuid.UUID) ([]*Membership, error) {
	query := `
		SELECT user_id, group_id, role, joined_at
		FROM user_groups
		WHERE group_id = $1
		ORDER BY joined_at ASC
	`
	rows, err := r.db.QueryContext(ctx, query, groupID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var members []*Membership
	for rows.Next() {
		membership := &Membership{}
		if err := rows.Scan(&membership.UserID, &membership.GroupID, &membership.Role, &membership.JoinedAt); err != nil {
			return nil, err
		}
		members = append(members, membership)
	}
	return members, rows.Err()
}

// GetUserGroupIDs retrieves all group IDs that a user is a member of
func (r *PostgresRepository) GetUserGroupIDs(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error) {
	query := `SELECT group_id FROM user_groups WHERE user_id = $1`
	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var groupIDs []uuid.UUID
	for rows.Next() {
		var groupID uuid.UUID
		if err := rows.Scan(&groupID); err != nil {
			return nil, err
		}
		groupIDs = append(groupIDs, groupID)
	}
	return groupIDs, rows.Err()
}

// isUniqueViolation checks if the error is a unique constraint violation
func isUniqueViolation(err error) bool {
	return err != nil && (contains(err.Error(), "23505") || contains(err.Error(), "unique"))
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
