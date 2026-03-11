package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestJWTService_GenerateAndValidate(t *testing.T) {
	svc := NewJWTService("test-secret-key-that-is-long-enough", 15*time.Minute, 7*24*time.Hour, "test-issuer")

	userID := uuid.New()
	email := "test@example.com"
	groupIDs := []string{"group-1", "group-2"}

	// Generate token pair
	pair, err := svc.GenerateTokenPair(userID, email, groupIDs)
	if err != nil {
		t.Fatalf("failed to generate token pair: %v", err)
	}

	if pair.AccessToken == "" {
		t.Error("access token should not be empty")
	}
	if pair.RefreshToken == "" {
		t.Error("refresh token should not be empty")
	}
	if pair.ExpiresAt.IsZero() {
		t.Error("expires_at should not be zero")
	}

	// Validate access token
	claims, err := svc.ValidateAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("failed to validate access token: %v", err)
	}

	if claims.UserID != userID {
		t.Errorf("expected user ID %s, got %s", userID, claims.UserID)
	}
	if claims.Email != email {
		t.Errorf("expected email %s, got %s", email, claims.Email)
	}
	if len(claims.GroupIDs) != len(groupIDs) {
		t.Errorf("expected %d group IDs, got %d", len(groupIDs), len(claims.GroupIDs))
	}
	if claims.Type != AccessToken {
		t.Errorf("expected type %s, got %s", AccessToken, claims.Type)
	}

	// Validate refresh token
	refreshClaims, err := svc.ValidateRefreshToken(pair.RefreshToken)
	if err != nil {
		t.Fatalf("failed to validate refresh token: %v", err)
	}

	if refreshClaims.UserID != userID {
		t.Errorf("expected user ID %s, got %s", userID, refreshClaims.UserID)
	}
	if refreshClaims.Type != RefreshToken {
		t.Errorf("expected type %s, got %s", RefreshToken, refreshClaims.Type)
	}
}

func TestJWTService_InvalidToken(t *testing.T) {
	svc := NewJWTService("test-secret-key-that-is-long-enough", 15*time.Minute, 7*24*time.Hour, "test-issuer")

	_, err := svc.ValidateToken("invalid-token")
	if err == nil {
		t.Error("expected error for invalid token")
	}
}

func TestJWTService_WrongTokenType(t *testing.T) {
	svc := NewJWTService("test-secret-key-that-is-long-enough", 15*time.Minute, 7*24*time.Hour, "test-issuer")

	userID := uuid.New()
	pair, err := svc.GenerateTokenPair(userID, "test@example.com", nil)
	if err != nil {
		t.Fatalf("failed to generate token pair: %v", err)
	}

	// Try to validate access token as refresh token
	_, err = svc.ValidateRefreshToken(pair.AccessToken)
	if err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}

	// Try to validate refresh token as access token
	_, err = svc.ValidateAccessToken(pair.RefreshToken)
	if err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestJWTService_ExpiredToken(t *testing.T) {
	// Create a service with very short TTL
	svc := NewJWTService("test-secret-key-that-is-long-enough", 1*time.Millisecond, 1*time.Millisecond, "test-issuer")

	userID := uuid.New()
	pair, err := svc.GenerateTokenPair(userID, "test@example.com", nil)
	if err != nil {
		t.Fatalf("failed to generate token pair: %v", err)
	}

	// Wait for token to expire
	time.Sleep(10 * time.Millisecond)

	_, err = svc.ValidateToken(pair.AccessToken)
	if err != ErrExpiredToken {
		t.Errorf("expected ErrExpiredToken, got %v", err)
	}
}

func TestJWTService_DifferentSecret(t *testing.T) {
	svc1 := NewJWTService("secret-one-that-is-long-enough-123", 15*time.Minute, 7*24*time.Hour, "test-issuer")
	svc2 := NewJWTService("secret-two-that-is-long-enough-456", 15*time.Minute, 7*24*time.Hour, "test-issuer")

	userID := uuid.New()
	pair, err := svc1.GenerateTokenPair(userID, "test@example.com", nil)
	if err != nil {
		t.Fatalf("failed to generate token pair: %v", err)
	}

	// Try to validate with different secret
	_, err = svc2.ValidateToken(pair.AccessToken)
	if err == nil {
		t.Error("expected error when validating with different secret")
	}
}
