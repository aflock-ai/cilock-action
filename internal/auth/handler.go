package auth

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/testifysec/dropbox-clone/internal/user"
)

// Handler handles authentication-related HTTP requests
type Handler struct {
	userService *user.Service
	jwtService  *JWTService
}

// NewHandler creates a new auth handler
func NewHandler(userService *user.Service, jwtService *JWTService) *Handler {
	return &Handler{
		userService: userService,
		jwtService:  jwtService,
	}
}

// RegisterRequest represents a registration request
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginRequest represents a login request
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// RefreshRequest represents a token refresh request
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// AuthResponse represents an authentication response
type AuthResponse struct {
	User         *UserResponse `json:"user"`
	AccessToken  string        `json:"access_token"`
	RefreshToken string        `json:"refresh_token"`
	ExpiresAt    string        `json:"expires_at"`
}

// UserResponse represents a user in API responses
type UserResponse struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	CreatedAt string `json:"created_at"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error"`
}

// Register handles user registration
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	input := &user.CreateUserInput{
		Email:    req.Email,
		Password: req.Password,
	}

	newUser, err := h.userService.Register(r.Context(), input)
	if err != nil {
		switch {
		case errors.Is(err, user.ErrEmailExists):
			respondError(w, "Email already exists", http.StatusConflict)
		case errors.Is(err, user.ErrEmailRequired):
			respondError(w, "Email is required", http.StatusBadRequest)
		case errors.Is(err, user.ErrPasswordRequired):
			respondError(w, "Password is required", http.StatusBadRequest)
		case errors.Is(err, user.ErrPasswordTooShort):
			respondError(w, "Password must be at least 8 characters", http.StatusBadRequest)
		default:
			respondError(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// Generate tokens
	tokens, err := h.jwtService.GenerateTokenPair(newUser.ID, newUser.Email, nil)
	if err != nil {
		respondError(w, "Failed to generate tokens", http.StatusInternalServerError)
		return
	}

	respondJSON(w, http.StatusCreated, AuthResponse{
		User: &UserResponse{
			ID:        newUser.ID.String(),
			Email:     newUser.Email,
			CreatedAt: newUser.CreatedAt.Format("2006-01-02T15:04:05Z"),
		},
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresAt:    tokens.ExpiresAt.Format("2006-01-02T15:04:05Z"),
	})
}

// Login handles user login
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" {
		respondError(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	authenticatedUser, err := h.userService.Authenticate(r.Context(), req.Email, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, user.ErrUserNotFound):
			respondError(w, "Invalid email or password", http.StatusUnauthorized)
		case errors.Is(err, user.ErrInvalidPassword):
			respondError(w, "Invalid email or password", http.StatusUnauthorized)
		default:
			respondError(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// Generate tokens (TODO: include actual group IDs)
	tokens, err := h.jwtService.GenerateTokenPair(authenticatedUser.ID, authenticatedUser.Email, nil)
	if err != nil {
		respondError(w, "Failed to generate tokens", http.StatusInternalServerError)
		return
	}

	respondJSON(w, http.StatusOK, AuthResponse{
		User: &UserResponse{
			ID:        authenticatedUser.ID.String(),
			Email:     authenticatedUser.Email,
			CreatedAt: authenticatedUser.CreatedAt.Format("2006-01-02T15:04:05Z"),
		},
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresAt:    tokens.ExpiresAt.Format("2006-01-02T15:04:05Z"),
	})
}

// Refresh handles token refresh
func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.RefreshToken == "" {
		respondError(w, "Refresh token is required", http.StatusBadRequest)
		return
	}

	// Validate the refresh token
	claims, err := h.jwtService.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		switch {
		case errors.Is(err, ErrExpiredToken):
			respondError(w, "Refresh token has expired", http.StatusUnauthorized)
		default:
			respondError(w, "Invalid refresh token", http.StatusUnauthorized)
		}
		return
	}

	// Get the user to ensure they still exist
	existingUser, err := h.userService.GetByID(r.Context(), claims.UserID)
	if err != nil {
		if errors.Is(err, user.ErrUserNotFound) {
			respondError(w, "User not found", http.StatusUnauthorized)
			return
		}
		respondError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Generate new tokens (TODO: include actual group IDs)
	tokens, err := h.jwtService.GenerateTokenPair(existingUser.ID, existingUser.Email, nil)
	if err != nil {
		respondError(w, "Failed to generate tokens", http.StatusInternalServerError)
		return
	}

	respondJSON(w, http.StatusOK, AuthResponse{
		User: &UserResponse{
			ID:        existingUser.ID.String(),
			Email:     existingUser.Email,
			CreatedAt: existingUser.CreatedAt.Format("2006-01-02T15:04:05Z"),
		},
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresAt:    tokens.ExpiresAt.Format("2006-01-02T15:04:05Z"),
	})
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
