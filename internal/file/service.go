package file

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/testifysec/dropbox-clone/internal/group"
)

// MaxFileSize is the maximum allowed file size (1 GB)
const MaxFileSize = 1 * 1024 * 1024 * 1024

// Service provides file-related business logic
type Service struct {
	repo         Repository
	storage      Storage
	groupService *group.Service
}

// NewService creates a new file service
func NewService(repo Repository, storage Storage, groupService *group.Service) *Service {
	return &Service{
		repo:         repo,
		storage:      storage,
		groupService: groupService,
	}
}

// Upload uploads a file to storage and saves metadata
func (s *Service) Upload(ctx context.Context, input *UploadFileInput, body io.Reader) (*File, error) {
	if err := input.Validate(); err != nil {
		return nil, err
	}

	// Check file size
	if input.SizeBytes > MaxFileSize {
		return nil, ErrFileTooLarge
	}

	// Check if user is a member of the group
	isMember, err := s.groupService.IsMember(ctx, input.GroupID, input.UploadedBy)
	if err != nil {
		return nil, err
	}
	if !isMember {
		return nil, group.ErrNotMember
	}

	// Generate S3 key: groups/{group_id}/{file_id}/{filename}
	fileID := uuid.New()
	s3Key := fmt.Sprintf("groups/%s/%s/%s", input.GroupID, fileID, input.Name)

	// Upload to S3
	if err := s.storage.Upload(ctx, s3Key, body, input.ContentType, input.SizeBytes); err != nil {
		return nil, ErrUploadFailed
	}

	// Save metadata
	now := time.Now()
	file := &File{
		ID:          fileID,
		Name:        input.Name,
		S3Key:       s3Key,
		SizeBytes:   input.SizeBytes,
		ContentType: input.ContentType,
		GroupID:     input.GroupID,
		UploadedBy:  input.UploadedBy,
		CreatedAt:   now,
	}

	if err := s.repo.Create(ctx, file); err != nil {
		// Try to clean up S3 file on failure (best effort)
		_ = s.storage.Delete(ctx, s3Key)
		return nil, err
	}

	return file, nil
}

// Download returns a file's content
func (s *Service) Download(ctx context.Context, fileID, userID uuid.UUID) (io.ReadCloser, *File, error) {
	// Get file metadata
	file, err := s.repo.GetByID(ctx, fileID)
	if err != nil {
		return nil, nil, err
	}

	// Check if user is a member of the group
	isMember, err := s.groupService.IsMember(ctx, file.GroupID, userID)
	if err != nil {
		return nil, nil, err
	}
	if !isMember {
		return nil, nil, group.ErrNotMember
	}

	// Download from S3
	body, err := s.storage.Download(ctx, file.S3Key)
	if err != nil {
		return nil, nil, ErrDownloadFailed
	}

	return body, file, nil
}

// GetByID retrieves a file by ID (with permission check)
func (s *Service) GetByID(ctx context.Context, fileID, userID uuid.UUID) (*File, error) {
	file, err := s.repo.GetByID(ctx, fileID)
	if err != nil {
		return nil, err
	}

	// Check if user is a member of the group
	isMember, err := s.groupService.IsMember(ctx, file.GroupID, userID)
	if err != nil {
		return nil, err
	}
	if !isMember {
		return nil, group.ErrNotMember
	}

	return file, nil
}

// ListByGroupID retrieves all files in a group
func (s *Service) ListByGroupID(ctx context.Context, groupID, userID uuid.UUID) ([]*File, error) {
	// Check if user is a member of the group
	isMember, err := s.groupService.IsMember(ctx, groupID, userID)
	if err != nil {
		return nil, err
	}
	if !isMember {
		return nil, group.ErrNotMember
	}

	return s.repo.ListByGroupID(ctx, groupID)
}

// Delete removes a file from storage and database
func (s *Service) Delete(ctx context.Context, fileID, userID uuid.UUID) error {
	// Get file metadata
	file, err := s.repo.GetByID(ctx, fileID)
	if err != nil {
		return err
	}

	// Check if user is a member of the group
	isMember, err := s.groupService.IsMember(ctx, file.GroupID, userID)
	if err != nil {
		return err
	}
	if !isMember {
		return group.ErrNotMember
	}

	// Delete from database first
	if err := s.repo.Delete(ctx, fileID); err != nil {
		return err
	}

	// Delete from S3 (best effort)
	_ = s.storage.Delete(ctx, file.S3Key)

	return nil
}

// GetDownloadURL returns a presigned URL for downloading a file
func (s *Service) GetDownloadURL(ctx context.Context, fileID, userID uuid.UUID) (string, error) {
	file, err := s.GetByID(ctx, fileID, userID)
	if err != nil {
		return "", err
	}

	return s.storage.GetURL(ctx, file.S3Key)
}
