package file

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/testifysec/dropbox-clone/internal/auth"
	"github.com/testifysec/dropbox-clone/internal/group"
)

// Handler handles file-related HTTP requests
type Handler struct {
	service *Service
}

// NewHandler creates a new file handler
func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// FileResponse represents a file in API responses
type FileResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	SizeBytes   int64  `json:"size_bytes"`
	ContentType string `json:"content_type"`
	GroupID     string `json:"group_id"`
	UploadedBy  string `json:"uploaded_by"`
	CreatedAt   string `json:"created_at"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error"`
}

// Upload handles file upload
func (h *Handler) Upload(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.GetUserID(r.Context())
	if !ok {
		respondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	groupIDStr := chi.URLParam(r, "groupId")
	groupID, err := uuid.Parse(groupIDStr)
	if err != nil {
		respondError(w, "Invalid group ID", http.StatusBadRequest)
		return
	}

	// Parse multipart form (32 MB max in memory)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		respondError(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		respondError(w, "File is required", http.StatusBadRequest)
		return
	}
	defer func() { _ = file.Close() }()

	// Get content type
	contentType := header.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	input := &UploadFileInput{
		Name:        header.Filename,
		ContentType: contentType,
		SizeBytes:   header.Size,
		GroupID:     groupID,
		UploadedBy:  userID,
	}

	uploadedFile, err := h.service.Upload(r.Context(), input, file)
	if err != nil {
		switch {
		case errors.Is(err, ErrFileTooLarge):
			respondError(w, "File exceeds maximum size (1 GB)", http.StatusRequestEntityTooLarge)
		case errors.Is(err, group.ErrNotMember):
			respondError(w, "You are not a member of this group", http.StatusForbidden)
		default:
			respondError(w, "Failed to upload file", http.StatusInternalServerError)
		}
		return
	}

	respondJSON(w, http.StatusCreated, FileResponse{
		ID:          uploadedFile.ID.String(),
		Name:        uploadedFile.Name,
		SizeBytes:   uploadedFile.SizeBytes,
		ContentType: uploadedFile.ContentType,
		GroupID:     uploadedFile.GroupID.String(),
		UploadedBy:  uploadedFile.UploadedBy.String(),
		CreatedAt:   uploadedFile.CreatedAt.Format("2006-01-02T15:04:05Z"),
	})
}

// List handles listing files in a group
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.GetUserID(r.Context())
	if !ok {
		respondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	groupIDStr := chi.URLParam(r, "groupId")
	groupID, err := uuid.Parse(groupIDStr)
	if err != nil {
		respondError(w, "Invalid group ID", http.StatusBadRequest)
		return
	}

	files, err := h.service.ListByGroupID(r.Context(), groupID, userID)
	if err != nil {
		switch {
		case errors.Is(err, group.ErrNotMember):
			respondError(w, "You are not a member of this group", http.StatusForbidden)
		default:
			respondError(w, "Failed to list files", http.StatusInternalServerError)
		}
		return
	}

	response := make([]FileResponse, len(files))
	for i, f := range files {
		response[i] = FileResponse{
			ID:          f.ID.String(),
			Name:        f.Name,
			SizeBytes:   f.SizeBytes,
			ContentType: f.ContentType,
			GroupID:     f.GroupID.String(),
			UploadedBy:  f.UploadedBy.String(),
			CreatedAt:   f.CreatedAt.Format("2006-01-02T15:04:05Z"),
		}
	}

	respondJSON(w, http.StatusOK, response)
}

// Download handles file download
func (h *Handler) Download(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.GetUserID(r.Context())
	if !ok {
		respondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	fileIDStr := chi.URLParam(r, "fileId")
	fileID, err := uuid.Parse(fileIDStr)
	if err != nil {
		respondError(w, "Invalid file ID", http.StatusBadRequest)
		return
	}

	body, file, err := h.service.Download(r.Context(), fileID, userID)
	if err != nil {
		switch {
		case errors.Is(err, ErrFileNotFound):
			respondError(w, "File not found", http.StatusNotFound)
		case errors.Is(err, group.ErrNotMember):
			respondError(w, "You are not a member of this group", http.StatusForbidden)
		default:
			respondError(w, "Failed to download file", http.StatusInternalServerError)
		}
		return
	}
	defer func() { _ = body.Close() }()

	// Set headers
	w.Header().Set("Content-Type", file.ContentType)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+file.Name+"\"")
	w.Header().Set("Content-Length", strconv.FormatInt(file.SizeBytes, 10))

	// Stream the file
	_, _ = io.Copy(w, body)
}

// Delete handles file deletion
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.GetUserID(r.Context())
	if !ok {
		respondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	fileIDStr := chi.URLParam(r, "fileId")
	fileID, err := uuid.Parse(fileIDStr)
	if err != nil {
		respondError(w, "Invalid file ID", http.StatusBadRequest)
		return
	}

	err = h.service.Delete(r.Context(), fileID, userID)
	if err != nil {
		switch {
		case errors.Is(err, ErrFileNotFound):
			respondError(w, "File not found", http.StatusNotFound)
		case errors.Is(err, group.ErrNotMember):
			respondError(w, "You are not a member of this group", http.StatusForbidden)
		default:
			respondError(w, "Failed to delete file", http.StatusInternalServerError)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Helper functions

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, message string, status int) {
	respondJSON(w, status, ErrorResponse{Error: message})
}
