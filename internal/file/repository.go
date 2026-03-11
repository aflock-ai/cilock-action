package file

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
)

// Repository defines the interface for file metadata operations
type Repository interface {
	Create(ctx context.Context, file *File) error
	GetByID(ctx context.Context, id uuid.UUID) (*File, error)
	Delete(ctx context.Context, id uuid.UUID) error
	ListByGroupID(ctx context.Context, groupID uuid.UUID) ([]*File, error)
}

// PostgresRepository implements Repository using PostgreSQL
type PostgresRepository struct {
	db *sql.DB
}

// NewPostgresRepository creates a new PostgresRepository
func NewPostgresRepository(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{db: db}
}

// Create inserts a new file record into the database
func (r *PostgresRepository) Create(ctx context.Context, file *File) error {
	query := `
		INSERT INTO files (id, name, s3_key, size_bytes, content_type, group_id, uploaded_by, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := r.db.ExecContext(ctx, query,
		file.ID, file.Name, file.S3Key, file.SizeBytes, file.ContentType,
		file.GroupID, file.UploadedBy, file.CreatedAt)
	return err
}

// GetByID retrieves a file by ID
func (r *PostgresRepository) GetByID(ctx context.Context, id uuid.UUID) (*File, error) {
	query := `
		SELECT id, name, s3_key, size_bytes, content_type, group_id, uploaded_by, created_at
		FROM files
		WHERE id = $1
	`
	file := &File{}
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&file.ID, &file.Name, &file.S3Key, &file.SizeBytes, &file.ContentType,
		&file.GroupID, &file.UploadedBy, &file.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrFileNotFound
		}
		return nil, err
	}
	return file, nil
}

// Delete removes a file record from the database
func (r *PostgresRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM files WHERE id = $1`
	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return ErrFileNotFound
	}
	return nil
}

// ListByGroupID retrieves all files in a group
func (r *PostgresRepository) ListByGroupID(ctx context.Context, groupID uuid.UUID) ([]*File, error) {
	query := `
		SELECT id, name, s3_key, size_bytes, content_type, group_id, uploaded_by, created_at
		FROM files
		WHERE group_id = $1
		ORDER BY created_at DESC
	`
	rows, err := r.db.QueryContext(ctx, query, groupID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var files []*File
	for rows.Next() {
		file := &File{}
		if err := rows.Scan(
			&file.ID, &file.Name, &file.S3Key, &file.SizeBytes, &file.ContentType,
			&file.GroupID, &file.UploadedBy, &file.CreatedAt); err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	return files, rows.Err()
}
