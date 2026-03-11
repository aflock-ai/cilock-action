package common

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOIDCKeyManager(t *testing.T) {
	km, err := NewOIDCKeyManager()
	require.NoError(t, err)
	require.NotNil(t, km)

	assert.NotNil(t, km.GetPrivateKey())
	assert.NotNil(t, km.GetPublicKey())
	assert.Equal(t, "act-oidc-key", km.GetKeyID())
}

func TestCreateOIDCRequestToken(t *testing.T) {
	ctx := &GitHubContext{
		Repository:      "owner/repo",
		RepositoryOwner: "owner",
		Workflow:        "test-workflow",
		WorkflowFile:    "workflow.yml",
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
		Job:             "test-job",
	}

	token, err := CreateOIDCRequestToken(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	// Parse the token to verify it contains the context
	parsed, err := jwt.ParseWithClaims(token, &oidcRequestClaims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte{}, nil
	})
	require.NoError(t, err)

	claims, ok := parsed.Claims.(*oidcRequestClaims)
	require.True(t, ok)

	assert.Equal(t, "owner/repo", claims.Repository)
	assert.Equal(t, "owner", claims.RepositoryOwner)
	assert.Equal(t, "test-workflow", claims.Workflow)
	assert.Equal(t, "workflow.yml", claims.WorkflowFile)
	assert.Equal(t, "refs/heads/main", claims.Ref)
	assert.Equal(t, "abc123", claims.Sha)
	assert.Equal(t, "testuser", claims.Actor)
	assert.Equal(t, "12345", claims.RunID)
	assert.Equal(t, "42", claims.RunNumber)
	assert.Equal(t, "push", claims.EventName)
}

func TestParseOIDCRequestToken(t *testing.T) {
	ctx := &GitHubContext{
		Repository:      "owner/repo",
		RepositoryOwner: "owner",
		Workflow:        "test-workflow",
		WorkflowFile:    "workflow.yml",
		Ref:             "refs/heads/main",
		Sha:             "abc123",
		Actor:           "testuser",
		RunID:           "12345",
		RunNumber:       "42",
		RunAttempt:      "1",
		EventName:       "push",
		RefName:         "main",
		RefType:         "branch",
		Job:             "test-job",
	}

	token, err := CreateOIDCRequestToken(ctx)
	require.NoError(t, err)

	parsed, err := ParseOIDCRequestToken(token)
	require.NoError(t, err)
	require.NotNil(t, parsed)

	assert.Equal(t, ctx.Repository, parsed.Repository)
	assert.Equal(t, ctx.RepositoryOwner, parsed.RepositoryOwner)
	assert.Equal(t, ctx.Workflow, parsed.Workflow)
	assert.Equal(t, ctx.WorkflowFile, parsed.WorkflowFile)
	assert.Equal(t, ctx.Ref, parsed.Ref)
	assert.Equal(t, ctx.Sha, parsed.Sha)
	assert.Equal(t, ctx.Actor, parsed.Actor)
	assert.Equal(t, ctx.RunID, parsed.RunID)
}

func TestParseOIDCRequestToken_Invalid(t *testing.T) {
	_, err := ParseOIDCRequestToken("invalid.token.here")
	assert.Error(t, err)
}

func TestGenerateOIDCToken(t *testing.T) {
	// Generate RSA key pair for testing
	keyManager, err := NewOIDCKeyManager()
	require.NoError(t, err)

	ctx := &GitHubContext{
		Repository:      "owner/repo",
		RepositoryOwner: "owner",
		Workflow:        "test-workflow",
		WorkflowFile:    "workflow.yml",
		Ref:             "refs/heads/main",
		Sha:             "abc123def456",
		Actor:           "testuser",
		RunID:           "12345",
		RunNumber:       "42",
		RunAttempt:      "1",
		EventName:       "push",
		RefName:         "main",
		RefType:         "branch",
		BaseRef:         "",
		HeadRef:         "",
		Job:             "test-job",
	}

	audience := "https://example.com"

	tokenString, err := GenerateOIDCToken(keyManager, ctx, audience)
	require.NoError(t, err)
	require.NotEmpty(t, tokenString)

	// Parse and validate the token
	token, err := jwt.ParseWithClaims(tokenString, &GitHubOIDCClaims{}, func(t *jwt.Token) (interface{}, error) {
		// Verify it's RS256
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return keyManager.GetPublicKey(), nil
	})
	require.NoError(t, err)

	claims, ok := token.Claims.(*GitHubOIDCClaims)
	require.True(t, ok)

	// Verify standard claims
	assert.Equal(t, "https://token.actions.githubusercontent.com", claims.Issuer)
	assert.Equal(t, "repo:owner/repo:ref:refs/heads/main", claims.Subject)
	assert.Contains(t, claims.Audience, audience)

	// Verify GitHub-specific claims
	assert.Equal(t, "owner/repo", claims.Repository)
	assert.Equal(t, "owner", claims.RepositoryOwner)
	assert.Equal(t, "test-workflow", claims.Workflow)
	assert.Equal(t, "refs/heads/main", claims.Ref)
	assert.Equal(t, "abc123def456", claims.Sha)
	assert.Equal(t, "testuser", claims.Actor)
	assert.Equal(t, "12345", claims.RunID)
	assert.Equal(t, "42", claims.RunNumber)
	assert.Equal(t, "1", claims.RunAttempt)
	assert.Equal(t, "push", claims.EventName)
	assert.Equal(t, "branch", claims.RefType)

	// Verify derived claims
	assert.Equal(t, "owner/repo/.github/workflows/workflow.yml@refs/heads/main", claims.WorkflowRef)
	assert.Equal(t, "abc123def456", claims.WorkflowSha)
	assert.Equal(t, "owner/repo/.github/workflows/workflow.yml@refs/heads/main", claims.JobWorkflowRef)
	assert.Equal(t, "abc123def456", claims.JobWorkflowSha)
	assert.Equal(t, "public", claims.RepositoryVisibility)
	assert.Equal(t, "false", claims.RefProtected)
	assert.Equal(t, "self-hosted", claims.RunnerEnvironment)

	// Verify IDs are generated consistently
	assert.NotEmpty(t, claims.RepositoryID)
	assert.NotEmpty(t, claims.RepositoryOwnerID)
	assert.NotEmpty(t, claims.ActorID)

	// Verify timestamps
	assert.True(t, claims.ExpiresAt.Time.After(time.Now()))
	assert.True(t, claims.IssuedAt.Time.Before(time.Now().Add(time.Second)))
}

func TestGenerateOIDCToken_DifferentAudiences(t *testing.T) {
	keyManager, err := NewOIDCKeyManager()
	require.NoError(t, err)

	ctx := &GitHubContext{
		Repository:   "owner/repo",
		Workflow:     "test",
		WorkflowFile: "test.yml",
		Ref:          "refs/heads/main",
		Sha:          "abc123",
		Actor:        "user",
		RunID:        "1",
		RunNumber:    "1",
		RunAttempt:   "1",
	}

	// Test with different audiences
	audiences := []string{
		"sigstore",
		"https://vault.example.com",
		"sts.amazonaws.com",
	}

	for _, aud := range audiences {
		tokenString, err := GenerateOIDCToken(keyManager, ctx, aud)
		require.NoError(t, err)

		token, err := jwt.ParseWithClaims(tokenString, &GitHubOIDCClaims{}, func(t *jwt.Token) (interface{}, error) {
			return keyManager.GetPublicKey(), nil
		})
		require.NoError(t, err)

		claims := token.Claims.(*GitHubOIDCClaims)
		assert.Contains(t, claims.Audience, aud)
	}
}

func TestGenerateJWKS(t *testing.T) {
	keyManager, err := NewOIDCKeyManager()
	require.NoError(t, err)

	jwksBytes, err := GenerateJWKS(keyManager)
	require.NoError(t, err)
	require.NotEmpty(t, jwksBytes)

	// Parse the JWKS
	var jwks JWKS
	err = json.Unmarshal(jwksBytes, &jwks)
	require.NoError(t, err)

	require.Len(t, jwks.Keys, 1)
	key := jwks.Keys[0]

	assert.Equal(t, "RSA", key.KeyType)
	assert.Equal(t, "sig", key.Use)
	assert.Equal(t, "RS256", key.Algorithm)
	assert.Equal(t, "act-oidc-key", key.KeyID)
	assert.NotEmpty(t, key.N)
	assert.NotEmpty(t, key.E)
}

func TestDeterministicIDs(t *testing.T) {
	// Test that IDs are generated consistently for the same input
	id1 := generateDeterministicID("owner/repo")
	id2 := generateDeterministicID("owner/repo")
	assert.Equal(t, id1, id2)

	// Test that different inputs generate different IDs
	id3 := generateDeterministicID("different/repo")
	assert.NotEqual(t, id1, id3)

	// Test that IDs are numeric strings
	assert.Regexp(t, `^\d+$`, id1)
}

func TestRoundTripOIDCToken(t *testing.T) {
	// Create a complete round trip: request token -> parse -> ID token -> verify
	keyManager, err := NewOIDCKeyManager()
	require.NoError(t, err)

	originalCtx := &GitHubContext{
		Repository:      "test-org/test-repo",
		RepositoryOwner: "test-org",
		Workflow:        "CI",
		WorkflowFile:    "ci.yml",
		Ref:             "refs/heads/feature-branch",
		Sha:             "deadbeef123456",
		Actor:           "developer",
		RunID:           "999",
		RunNumber:       "100",
		RunAttempt:      "2",
		EventName:       "pull_request",
		RefName:         "feature-branch",
		RefType:         "branch",
		BaseRef:         "main",
		HeadRef:         "feature-branch",
		Job:             "build",
	}

	// Step 1: Create request token (what act puts in ACTIONS_ID_TOKEN_REQUEST_TOKEN)
	requestToken, err := CreateOIDCRequestToken(originalCtx)
	require.NoError(t, err)

	// Step 2: Parse request token (what the OIDC endpoint does)
	parsedCtx, err := ParseOIDCRequestToken(requestToken)
	require.NoError(t, err)

	// Verify context was preserved
	assert.Equal(t, originalCtx.Repository, parsedCtx.Repository)
	assert.Equal(t, originalCtx.Workflow, parsedCtx.Workflow)
	assert.Equal(t, originalCtx.Ref, parsedCtx.Ref)

	// Step 3: Generate OIDC ID token (what the OIDC endpoint returns)
	idToken, err := GenerateOIDCToken(keyManager, parsedCtx, "sigstore")
	require.NoError(t, err)

	// Step 4: Verify ID token (what the consumer like SIGSTORE does)
	token, err := jwt.ParseWithClaims(idToken, &GitHubOIDCClaims{}, func(t *jwt.Token) (interface{}, error) {
		return keyManager.GetPublicKey(), nil
	})
	require.NoError(t, err)
	require.True(t, token.Valid)

	claims := token.Claims.(*GitHubOIDCClaims)
	assert.Equal(t, "test-org/test-repo", claims.Repository)
	assert.Equal(t, "CI", claims.Workflow)
	assert.Equal(t, "refs/heads/feature-branch", claims.Ref)
	assert.Equal(t, "developer", claims.Actor)
	assert.Equal(t, "pull_request", claims.EventName)
}
