package common

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// GitHubContext contains all the GitHub Actions context needed for OIDC token generation
type GitHubContext struct {
	Repository      string
	RepositoryOwner string
	Workflow        string
	WorkflowFile    string
	Ref             string
	Sha             string
	Actor           string
	RunID           string
	RunNumber       string
	RunAttempt      string
	EventName       string
	RefName         string
	RefType         string
	BaseRef         string
	HeadRef         string
	Job             string
}

// oidcRequestClaims are the claims embedded in ACTIONS_ID_TOKEN_REQUEST_TOKEN
// This token is passed from the workflow container to the OIDC server to provide context
type oidcRequestClaims struct {
	jwt.RegisteredClaims
	Repository      string `json:"repository"`
	RepositoryOwner string `json:"repository_owner"`
	Workflow        string `json:"workflow"`
	WorkflowFile    string `json:"workflow_file"`
	Ref             string `json:"ref"`
	Sha             string `json:"sha"`
	Actor           string `json:"actor"`
	RunID           string `json:"run_id"`
	RunNumber       string `json:"run_number"`
	RunAttempt      string `json:"run_attempt"`
	EventName       string `json:"event_name"`
	RefName         string `json:"ref_name"`
	RefType         string `json:"ref_type"`
	BaseRef         string `json:"base_ref"`
	HeadRef         string `json:"head_ref"`
	Job             string `json:"job"`
}

// GitHubOIDCClaims represents the complete GitHub Actions OIDC token claims
// Based on: https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect
type GitHubOIDCClaims struct {
	jwt.RegisteredClaims

	// Workflow context
	Workflow       string `json:"workflow"`
	WorkflowRef    string `json:"workflow_ref"`
	WorkflowSha    string `json:"workflow_sha"`
	JobWorkflowRef string `json:"job_workflow_ref"`
	JobWorkflowSha string `json:"job_workflow_sha"`

	// Repository context
	Repository           string `json:"repository"`
	RepositoryID         string `json:"repository_id"`
	RepositoryOwner      string `json:"repository_owner"`
	RepositoryOwnerID    string `json:"repository_owner_id"`
	RepositoryVisibility string `json:"repository_visibility"`

	// Execution context
	RunID        string `json:"run_id"`
	RunNumber    string `json:"run_number"`
	RunAttempt   string `json:"run_attempt"`
	EventName    string `json:"event_name"`
	Ref          string `json:"ref"`
	RefType      string `json:"ref_type"`
	RefProtected string `json:"ref_protected"`

	// Actor context
	Actor   string `json:"actor"`
	ActorID string `json:"actor_id"`

	// Branch context
	HeadRef string `json:"head_ref"`
	BaseRef string `json:"base_ref"`

	// Enterprise (optional)
	Enterprise   string `json:"enterprise,omitempty"`
	EnterpriseID string `json:"enterprise_id,omitempty"`

	// Environment (optional)
	Environment       string `json:"environment,omitempty"`
	EnvironmentNodeID string `json:"environment_node_id,omitempty"`

	// Infrastructure
	RunnerEnvironment string `json:"runner_environment"`
	Sha               string `json:"sha"`

	// Scope
	IssuerScope string `json:"issuer_scope,omitempty"`
}

// OIDCKeyManager manages RSA keys for OIDC token signing
type OIDCKeyManager interface {
	GetPrivateKey() *rsa.PrivateKey
	GetPublicKey() *rsa.PublicKey
	GetKeyID() string
}

type rsaKeyManager struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	kid        string
}

func (km *rsaKeyManager) GetPrivateKey() *rsa.PrivateKey {
	return km.privateKey
}

func (km *rsaKeyManager) GetPublicKey() *rsa.PublicKey {
	return km.publicKey
}

func (km *rsaKeyManager) GetKeyID() string {
	return km.kid
}

// NewOIDCKeyManager creates a new RSA key manager with a generated key pair
func NewOIDCKeyManager() (OIDCKeyManager, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	return &rsaKeyManager{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		kid:        "act-oidc-key",
	}, nil
}

// CreateOIDCRequestToken creates a JWT token containing GitHub context
// This token is set as ACTIONS_ID_TOKEN_REQUEST_TOKEN
func CreateOIDCRequestToken(ctx *GitHubContext) (string, error) {
	now := time.Now()

	claims := oidcRequestClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		Repository:      ctx.Repository,
		RepositoryOwner: ctx.RepositoryOwner,
		Workflow:        ctx.Workflow,
		WorkflowFile:    ctx.WorkflowFile,
		Ref:             ctx.Ref,
		Sha:             ctx.Sha,
		Actor:           ctx.Actor,
		RunID:           ctx.RunID,
		RunNumber:       ctx.RunNumber,
		RunAttempt:      ctx.RunAttempt,
		EventName:       ctx.EventName,
		RefName:         ctx.RefName,
		RefType:         ctx.RefType,
		BaseRef:         ctx.BaseRef,
		HeadRef:         ctx.HeadRef,
		Job:             ctx.Job,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte{})
	if err != nil {
		return "", fmt.Errorf("failed to sign OIDC request token: %w", err)
	}

	return tokenString, nil
}

// ParseOIDCRequestToken parses an OIDC request token and extracts the GitHub context
func ParseOIDCRequestToken(tokenString string) (*GitHubContext, error) {
	token, err := jwt.ParseWithClaims(tokenString, &oidcRequestClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte{}, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse OIDC request token: %w", err)
	}

	claims, ok := token.Claims.(*oidcRequestClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid OIDC request token claims")
	}

	return &GitHubContext{
		Repository:      claims.Repository,
		RepositoryOwner: claims.RepositoryOwner,
		Workflow:        claims.Workflow,
		WorkflowFile:    claims.WorkflowFile,
		Ref:             claims.Ref,
		Sha:             claims.Sha,
		Actor:           claims.Actor,
		RunID:           claims.RunID,
		RunNumber:       claims.RunNumber,
		RunAttempt:      claims.RunAttempt,
		EventName:       claims.EventName,
		RefName:         claims.RefName,
		RefType:         claims.RefType,
		BaseRef:         claims.BaseRef,
		HeadRef:         claims.HeadRef,
		Job:             claims.Job,
	}, nil
}

// generateDeterministicID generates a consistent ID from a string (for repository_id, actor_id, etc.)
func generateDeterministicID(input string) string {
	hash := sha256.Sum256([]byte(input))
	// Take first 8 bytes and convert to a number-like string
	num := new(big.Int).SetBytes(hash[:8])
	return num.String()
}

// GenerateOIDCToken generates a GitHub Actions-compatible OIDC ID token
func GenerateOIDCToken(keyManager OIDCKeyManager, ctx *GitHubContext, audience string) (string, error) {
	now := time.Now()

	// Construct workflow_ref (format: {repository}/.github/workflows/{workflow_file}@{ref})
	workflowRef := fmt.Sprintf("%s/.github/workflows/%s@%s", ctx.Repository, ctx.WorkflowFile, ctx.Ref)

	// Construct subject (format: repo:{repository}:ref:{ref})
	subject := fmt.Sprintf("repo:%s:ref:%s", ctx.Repository, ctx.Ref)

	claims := GitHubOIDCClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://token.actions.githubusercontent.com",
			Subject:   subject,
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        fmt.Sprintf("act-oidc-%d", now.Unix()),
		},

		// Workflow context
		Workflow:       ctx.Workflow,
		WorkflowRef:    workflowRef,
		WorkflowSha:    ctx.Sha,
		JobWorkflowRef: workflowRef,
		JobWorkflowSha: ctx.Sha,

		// Repository context
		Repository:           ctx.Repository,
		RepositoryID:         generateDeterministicID(ctx.Repository),
		RepositoryOwner:      ctx.RepositoryOwner,
		RepositoryOwnerID:    generateDeterministicID(ctx.RepositoryOwner),
		RepositoryVisibility: "public", // Default to public, could be made configurable

		// Execution context
		RunID:        ctx.RunID,
		RunNumber:    ctx.RunNumber,
		RunAttempt:   ctx.RunAttempt,
		EventName:    ctx.EventName,
		Ref:          ctx.Ref,
		RefType:      ctx.RefType,
		RefProtected: "false", // Default to false, could be made configurable

		// Actor context
		Actor:   ctx.Actor,
		ActorID: generateDeterministicID(ctx.Actor),

		// Branch context
		HeadRef: ctx.HeadRef,
		BaseRef: ctx.BaseRef,

		// Infrastructure
		RunnerEnvironment: "self-hosted", // act runs locally
		Sha:               ctx.Sha,
	}

	// Create token with RS256 signing
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyManager.GetKeyID()

	tokenString, err := token.SignedString(keyManager.GetPrivateKey())
	if err != nil {
		return "", fmt.Errorf("failed to sign OIDC token: %w", err)
	}

	return tokenString, nil
}

// JWK represents a JSON Web Key
type JWK struct {
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	N         string `json:"n"`
	E         string `json:"e"`
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// GenerateJWKS generates a JWKS (JSON Web Key Set) from the public key
func GenerateJWKS(keyManager OIDCKeyManager) ([]byte, error) {
	publicKey := keyManager.GetPublicKey()

	// Encode N (modulus) and E (exponent) as base64url
	nBytes := publicKey.N.Bytes()
	eBytes := big.NewInt(int64(publicKey.E)).Bytes()

	jwk := JWK{
		KeyType:   "RSA",
		Use:       "sig",
		Algorithm: "RS256",
		KeyID:     keyManager.GetKeyID(),
		N:         base64.RawURLEncoding.EncodeToString(nBytes),
		E:         base64.RawURLEncoding.EncodeToString(eBytes),
	}

	jwks := JWKS{
		Keys: []JWK{jwk},
	}

	return json.Marshal(jwks)
}
