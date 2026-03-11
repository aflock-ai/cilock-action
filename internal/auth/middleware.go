package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

// ContextKey is a custom type for context keys
type ContextKey string

const (
	// UserIDKey is the context key for the user ID
	UserIDKey ContextKey = "user_id"
	// EmailKey is the context key for the user email
	EmailKey ContextKey = "email"
	// GroupIDsKey is the context key for the user's group IDs
	GroupIDsKey ContextKey = "group_ids"
	// ClaimsKey is the context key for the full claims
	ClaimsKey ContextKey = "claims"
)

// Middleware returns an HTTP middleware that validates JWT tokens
func Middleware(jwtService *JWTService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get the Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Authorization header required", http.StatusUnauthorized)
				return
			}

			// Check for Bearer prefix
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
				return
			}

			tokenString := parts[1]

			// Validate the token
			claims, err := jwtService.ValidateAccessToken(tokenString)
			if err != nil {
				if err == ErrExpiredToken {
					http.Error(w, "Token has expired", http.StatusUnauthorized)
					return
				}
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			// Add claims to context
			ctx := r.Context()
			ctx = context.WithValue(ctx, UserIDKey, claims.UserID)
			ctx = context.WithValue(ctx, EmailKey, claims.Email)
			ctx = context.WithValue(ctx, GroupIDsKey, claims.GroupIDs)
			ctx = context.WithValue(ctx, ClaimsKey, claims)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetUserID extracts the user ID from the request context
func GetUserID(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(UserIDKey).(uuid.UUID)
	return id, ok
}

// GetEmail extracts the email from the request context
func GetEmail(ctx context.Context) (string, bool) {
	email, ok := ctx.Value(EmailKey).(string)
	return email, ok
}

// GetGroupIDs extracts the group IDs from the request context
func GetGroupIDs(ctx context.Context) ([]string, bool) {
	groupIDs, ok := ctx.Value(GroupIDsKey).([]string)
	return groupIDs, ok
}

// GetClaims extracts the full claims from the request context
func GetClaims(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(ClaimsKey).(*Claims)
	return claims, ok
}
