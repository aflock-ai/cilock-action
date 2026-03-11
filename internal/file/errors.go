package file

import "errors"

var (
	ErrFileNotFound       = errors.New("file not found")
	ErrNameRequired       = errors.New("name is required")
	ErrGroupIDRequired    = errors.New("group ID is required")
	ErrUploadedByRequired = errors.New("uploaded by is required")
	ErrFileTooLarge       = errors.New("file exceeds maximum size")
	ErrInvalidContentType = errors.New("invalid content type")
	ErrUploadFailed       = errors.New("failed to upload file")
	ErrDownloadFailed     = errors.New("failed to download file")
)
