package artifacts

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/nektos/act/pkg/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOIDCIntegration(t *testing.T) {
	ctx := context.Background()

	// Create OIDC key manager
	keyManager, err := common.NewOIDCKeyManager()
	require.NoError(t, err)

	// Start artifacts server with OIDC support
	addr := "127.0.0.1"
	port := "8765" // Use a different port to avoid conflicts
	cancel := Serve(ctx, t.TempDir(), addr, port, keyManager)
	defer cancel()

	// Give the server time to start
	time.Sleep(100 * time.Millisecond)

	baseURL := fmt.Sprintf("http://%s:%s", addr, port)

	// Create GitHub context
	ghCtx := &common.GitHubContext{
		Repository:      "test-org/test-repo",
		RepositoryOwner: "test-org",
		Workflow:        "CI",
		WorkflowFile:    "ci.yml",
		Ref:             "refs/heads/main",
		Sha:             "abc123",
		Actor:           "testuser",
		RunID:           "12345",
		RunNumber:       "42",
		RunAttempt:      "1",
		EventName:       "push",
		RefName:         "main",
		RefType:         "branch",
		BaseRef:         "",
		HeadRef:         "",
		Job:             "build",
	}

	// Create OIDC request token
	requestToken, err := common.CreateOIDCRequestToken(ghCtx)
	require.NoError(t, err)

	t.Run("POST /token", func(t *testing.T) {
		// Create request to /token endpoint
		req, err := http.NewRequest("POST", baseURL+"/token?audience=sigstore", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+requestToken)

		// Make request
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Verify response
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var tokenResp map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&tokenResp)
		require.NoError(t, err)

		assert.Equal(t, float64(1), tokenResp["count"])
		assert.NotEmpty(t, tokenResp["value"])

		// Parse and verify the ID token
		idTokenString := tokenResp["value"].(string)
		token, err := jwt.ParseWithClaims(idTokenString, &common.GitHubOIDCClaims{}, func(t *jwt.Token) (interface{}, error) {
			return keyManager.GetPublicKey(), nil
		})
		require.NoError(t, err)
		require.True(t, token.Valid)

		claims := token.Claims.(*common.GitHubOIDCClaims)
		assert.Equal(t, "test-org/test-repo", claims.Repository)
		assert.Equal(t, "CI", claims.Workflow)
		assert.Equal(t, "refs/heads/main", claims.Ref)
		assert.Equal(t, "testuser", claims.Actor)
		assert.Contains(t, claims.Audience, "sigstore")
	})

	t.Run("POST /token without Authorization", func(t *testing.T) {
		req, err := http.NewRequest("POST", baseURL+"/token", nil)
		require.NoError(t, err)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("POST /token with invalid token", func(t *testing.T) {
		req, err := http.NewRequest("POST", baseURL+"/token", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer invalid.token.here")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("GET /.well-known/jwks", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/.well-known/jwks")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var jwks common.JWKS
		err = json.NewDecoder(resp.Body).Decode(&jwks)
		require.NoError(t, err)

		require.Len(t, jwks.Keys, 1)
		key := jwks.Keys[0]

		assert.Equal(t, "RSA", key.KeyType)
		assert.Equal(t, "sig", key.Use)
		assert.Equal(t, "RS256", key.Algorithm)
		assert.Equal(t, keyManager.GetKeyID(), key.KeyID)
		assert.NotEmpty(t, key.N)
		assert.NotEmpty(t, key.E)
	})

	t.Run("POST /token with custom audience", func(t *testing.T) {
		customAudience := "https://vault.example.com"
		req, err := http.NewRequest("POST", baseURL+"/token?audience="+customAudience, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+requestToken)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var tokenResp map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&tokenResp)
		require.NoError(t, err)

		idTokenString := tokenResp["value"].(string)
		token, err := jwt.ParseWithClaims(idTokenString, &common.GitHubOIDCClaims{}, func(t *jwt.Token) (interface{}, error) {
			return keyManager.GetPublicKey(), nil
		})
		require.NoError(t, err)

		claims := token.Claims.(*common.GitHubOIDCClaims)
		assert.Contains(t, claims.Audience, customAudience)
	})

	t.Run("POST /token with default audience", func(t *testing.T) {
		req, err := http.NewRequest("POST", baseURL+"/token", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+requestToken)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var tokenResp map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&tokenResp)
		require.NoError(t, err)

		idTokenString := tokenResp["value"].(string)
		token, err := jwt.ParseWithClaims(idTokenString, &common.GitHubOIDCClaims{}, func(t *jwt.Token) (interface{}, error) {
			return keyManager.GetPublicKey(), nil
		})
		require.NoError(t, err)

		claims := token.Claims.(*common.GitHubOIDCClaims)
		// Default audience should be https://github.com/<owner>
		assert.Contains(t, claims.Audience, "https://github.com/test-org")
	})
}
