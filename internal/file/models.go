package file

import (
	"time"

	"github.com/google/uuid"
)

// File represents a file in the system
type File struct {
	ID          uuid.UUID `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	S3Key       string    `json:"s3_key" db:"s3_key"`
	SizeBytes   int64     `json:"size_bytes" db:"size_bytes"`
	ContentType string    `json:"content_type" db:"content_type"`
	GroupID     uuid.UUID `json:"group_id" db:"group_id"`
	UploadedBy  uuid.UUID `json:"uploaded_by" db:"uploaded_by"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

// UploadFileInput represents the input for uploading a file
type UploadFileInput struct {
	Name        string
	ContentType string
	SizeBytes   int64
	GroupID     uuid.UUID
	UploadedBy  uuid.UUID
}

// Validate validates the upload file input
func (u *UploadFileInput) Validate() error {
	if u.Name == "" {
		return ErrNameRequired
	}
	if u.GroupID == uuid.Nil {
		return ErrGroupIDRequired
	}
	if u.UploadedBy == uuid.Nil {
		return ErrUploadedByRequired
	}
	return nil
}
