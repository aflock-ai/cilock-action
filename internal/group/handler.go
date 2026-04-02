package group

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/testifysec/dropbox-clone/internal/auth"
)

// Handler handles group-related HTTP requests
type Handler struct {
	service *Service
}

// NewHandler creates a new group handler
func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// CreateRequest represents a create group request
type CreateRequest struct {
	Name string `json:"name"`
}

// AddMemberRequest represents an add member request
type AddMemberRequest struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

// GroupResponse represents a group in API responses
type GroupResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedBy string `json:"created_by"`
	CreatedAt string `json:"created_at"`
}

// MembershipResponse represents a membership in API responses
type MembershipResponse struct {
	UserID   string `json:"user_id"`
	GroupID  string `json:"group_id"`
	Role     string `json:"role"`
	JoinedAt string `json:"joined_at"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error"`
}

// Create handles group creation
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.GetUserID(r.Context())
	if !ok {
		respondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req CreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	input := &CreateGroupInput{Name: req.Name}
	group, err := h.service.Create(r.Context(), input, userID)
	if err != nil {
		switch {
		case errors.Is(err, ErrNameRequired):
			respondError(w, "Name is required", http.StatusBadRequest)
		default:
			respondError(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	respondJSON(w, http.StatusCreated, GroupResponse{
		ID:        group.ID.String(),
		Name:      group.Name,
		CreatedBy: group.CreatedBy.String(),
		CreatedAt: group.CreatedAt.Format("2006-01-02T15:04:05Z"),
	})
}

// List handles listing user's groups
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.GetUserID(r.Context())
	if !ok {
		respondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	groups, err := h.service.ListByUserID(r.Context(), userID)
	if err != nil {
		respondError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	response := make([]GroupResponse, len(groups))
	for i, group := range groups {
		response[i] = GroupResponse{
			ID:        group.ID.String(),
			Name:      group.Name,
			CreatedBy: group.CreatedBy.String(),
			CreatedAt: group.CreatedAt.Format("2006-01-02T15:04:05Z"),
		}
	}

	respondJSON(w, http.StatusOK, response)
}

// AddMember handles adding a member to a group
func (h *Handler) AddMember(w http.ResponseWriter, r *http.Request) {
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

	var req AddMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	memberUserID, err := uuid.Parse(req.UserID)
	if err != nil {
		respondError(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	input := &AddMemberInput{
		UserID: memberUserID,
		Role:   req.Role,
	}

	membership, err := h.service.AddMember(r.Context(), groupID, input, userID)
	if err != nil {
		switch {
		case errors.Is(err, ErrNotMember):
			respondError(w, "You are not a member of this group", http.StatusForbidden)
		case errors.Is(err, ErrNotAdmin):
			respondError(w, "Only admins can add members", http.StatusForbidden)
		case errors.Is(err, ErrAlreadyMember):
			respondError(w, "User is already a member", http.StatusConflict)
		case errors.Is(err, ErrInvalidRole):
			respondError(w, "Invalid role", http.StatusBadRequest)
		default:
			respondError(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	respondJSON(w, http.StatusCreated, MembershipResponse{
		UserID:   membership.UserID.String(),
		GroupID:  membership.GroupID.String(),
		Role:     membership.Role,
		JoinedAt: membership.JoinedAt.Format("2006-01-02T15:04:05Z"),
	})
}

// RemoveMember handles removing a member from a group
func (h *Handler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	requestingUserID, ok := auth.GetUserID(r.Context())
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

	userIDStr := chi.URLParam(r, "userId")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		respondError(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	err = h.service.RemoveMember(r.Context(), groupID, userID, requestingUserID)
	if err != nil {
		switch {
		case errors.Is(err, ErrNotMember):
			respondError(w, "User is not a member of this group", http.StatusNotFound)
		case errors.Is(err, ErrNotAdmin):
			respondError(w, "Only admins can remove members", http.StatusForbidden)
		case errors.Is(err, ErrCannotRemoveSelf):
			respondError(w, "Cannot remove yourself from the group", http.StatusBadRequest)
		default:
			respondError(w, "Internal server error", http.StatusInternalServerError)
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
