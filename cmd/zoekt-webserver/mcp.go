package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	sglog "github.com/sourcegraph/log"

	"github.com/sourcegraph/zoekt"
	"github.com/sourcegraph/zoekt/index"
	"github.com/sourcegraph/zoekt/query"
	"github.com/sourcegraph/zoekt/web"
)

const (
	mcpPath               = "/mcp"
	protectedResourcePath = "/.well-known/oauth-protected-resource/"
)

type mcpContextKey string

const tokenSubjectKey mcpContextKey = "token_subject"

func subjectFromContext(ctx context.Context) (string, bool) {
	sub, ok := ctx.Value(tokenSubjectKey).(string)
	return sub, ok && sub != ""
}

// addMCPHandlers registers the MCP server and OAuth discovery routes on mux.
func addMCPHandlers(mux *http.ServeMux, webSrv *web.Server) {
	logger := sglog.Scoped("mcp")

	oktaBaseURL := os.Getenv("ZOEKT_OKTA_BASE_URL")
	if oktaBaseURL == "" {
		logger.Warn("ZOEKT_OKTA_BASE_URL not set, MCP routes will return 503")
		unavailable := "MCP not configured: ZOEKT_OKTA_BASE_URL not set"
		mux.HandleFunc(mcpPath, func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, unavailable, http.StatusServiceUnavailable)
		})
		mux.HandleFunc(protectedResourcePath, func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, unavailable, http.StatusServiceUnavailable)
		})
		return
	}

	verifier, err := newJWTVerifier(context.Background(), oktaBaseURL, logger)
	if err != nil {
		logger.Error("failed to initialize JWT verifier", sglog.Error(err))
		errMsg := fmt.Sprintf("MCP unavailable: JWT verifier init failed: %v", err)
		mux.HandleFunc(mcpPath, func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, errMsg, http.StatusServiceUnavailable)
		})
		mux.HandleFunc(protectedResourcePath, makeProtectedResourceHandler(oktaBaseURL))
		return
	}

	mcpServer := buildMCPServer(webSrv, logger)
	httpServer := server.NewStreamableHTTPServer(mcpServer)

	mux.Handle(mcpPath, jwtAuthMiddleware(verifier, logger, httpServer))
	mux.HandleFunc(protectedResourcePath, makeProtectedResourceHandler(oktaBaseURL))
}

// tokenVerifier is an interface for JWT verification, allowing test doubles.
type tokenVerifier interface {
	verify(authHeader string) (string, error)
}

// errInvalidRequest signals a malformed or missing Authorization header (RFC 6750 §3 invalid_request).
// Distinct from a well-formed token that fails validation (invalid_token).
var errInvalidRequest = fmt.Errorf("invalid_request")

// jwtAuthMiddleware validates the Bearer token and injects the subject into the request context.
func jwtAuthMiddleware(v tokenVerifier, logger sglog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sub, err := v.verify(r.Header.Get("Authorization"))
		if err != nil {
			if isJWKSError(err) {
				logger.Error("JWKS verification infrastructure failure",
					sglog.Error(err),
					sglog.String("remote_addr", r.RemoteAddr),
				)
			}
			oauthErr := "invalid_token"
			if errors.Is(err, errInvalidRequest) {
				oauthErr = "invalid_request"
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="zoekt", error=%q`, oauthErr))
			w.WriteHeader(http.StatusUnauthorized)
			if encErr := json.NewEncoder(w).Encode(map[string]string{
				"error":             oauthErr,
				"error_description": "Authentication required",
			}); encErr != nil {
				logger.Warn("failed to write 401 response body", sglog.Error(encErr))
			}
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), tokenSubjectKey, sub)))
	})
}

// isJWKSError distinguishes infrastructure failures (JWKS fetch) from routine token
// validation failures (bad token, expired, wrong issuer), so callers can log
// infrastructure failures without spamming logs for every bad client request.
func isJWKSError(err error) bool {
	return strings.Contains(err.Error(), "failed to fetch JWKS")
}

// makeProtectedResourceHandler serves RFC 9728 Protected Resource Metadata.
// Claude Code checks this endpoint first before falling back to /.well-known/oauth-authorization-server.
func makeProtectedResourceHandler(oktaBaseURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resource := "http://" + r.Host + mcpPath
		w.Header().Set("Content-Type", "application/json")
		if encErr := json.NewEncoder(w).Encode(map[string]any{
			"resource":             resource,
			"authorization_servers": []string{oktaBaseURL},
			"scopes_supported":     []string{"openid", "profile", "offline_access"},
		}); encErr != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
	}
}

// jwtVerifier validates Okta JWT tokens via JWKS.
type jwtVerifier struct {
	jwksURL  string
	issuer   string
	clientID string
	cache    *jwk.Cache
}

func newJWTVerifier(ctx context.Context, oktaBaseURL string, logger sglog.Logger) (*jwtVerifier, error) {
	jwksURL := oktaBaseURL + "/oauth2/v1/keys"

	cache := jwk.NewCache(ctx)
	if err := cache.Register(jwksURL, jwk.WithMinRefreshInterval(15*time.Minute)); err != nil {
		return nil, fmt.Errorf("failed to register JWKS URL: %w", err)
	}
	go func() {
		if _, err := cache.Refresh(ctx, jwksURL); err != nil {
			logger.Error("initial JWKS fetch failed; authentication unavailable until cache refreshes",
				sglog.String("url", jwksURL),
				sglog.Error(err),
			)
		}
	}()

	clientID := os.Getenv("ZOEKT_OKTA_CLIENT_ID")
	if clientID == "" {
		return nil, fmt.Errorf("ZOEKT_OKTA_CLIENT_ID is required")
	}

	return &jwtVerifier{
		jwksURL:  jwksURL,
		issuer:   oktaBaseURL,
		clientID: clientID,
		cache:    cache,
	}, nil
}

// verify extracts and validates the Bearer token, returning the subject claim.
func (v *jwtVerifier) verify(authHeader string) (string, error) {
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", fmt.Errorf("missing Bearer token: %w", errInvalidRequest)
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	// CachedSet resolves keys from RAM; triggers a JWKS refresh only on unknown kid (okta key rotation).
	// WithClaimValue("cid") guards against token substitution: it avoids needing a custom authorization server.
	tok, err := jwt.Parse([]byte(tokenStr),
		jwt.WithKeySet(jwk.NewCachedSet(v.cache, v.jwksURL)),
		jwt.WithIssuer(v.issuer),
		jwt.WithClaimValue("cid", v.clientID),
		jwt.WithValidate(true),
	)
	if err != nil {
		return "", fmt.Errorf("invalid token: %w", err)
	}

	return tok.Subject(), nil
}

// buildMCPServer creates the MCP server with the zoekt_search tool.
func buildMCPServer(webSrv *web.Server, logger sglog.Logger) *server.MCPServer {
	s := server.NewMCPServer("zoekt-search", index.Version,
		server.WithToolCapabilities(false),
	)

	zoektSearchTool := mcp.NewTool("zoekt_search",
		mcp.WithDescription("Search code across all internal LBC repositories using Zoekt."),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithString("query",
			mcp.Required(),
			mcp.Description(`Zoekt query string. Examples:
              "needle"           full-text search
              "r:reponame"       repo filter
              "file:template"    filename filter
              "lang:yaml"        language filter
              "sym:data"         symbol definitions
              "fork:no"          exclude forks
              "-lang:go"         negation (exclude)
              "foo or bar"       logical OR (AND is implicit)`),
		),
		mcp.WithNumber("num",
			mcp.Description("Max number of results (default 200)"),
		),
	)

	s.AddTool(zoektSearchTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		queryStr, err := req.RequireString("query")
		if err != nil {
			return mcp.NewToolResultError("query parameter is required"), nil
		}

		num := 200
		if n := req.GetFloat("num", 0); n > 0 {
			num = int(n) //nolint:gosec
		}

		sub, ok := subjectFromContext(ctx)
		if !ok {
			logger.Error("zoekt_search reached tool handler without authenticated subject")
			return mcp.NewToolResultError("internal error: unauthenticated request"), nil
		}
		logger.Info("zoekt_search called",
			sglog.String("subject", sub),
			sglog.String("query", queryStr),
			sglog.Int("num", num),
		)

		results, err := runSearch(ctx, webSrv, queryStr, num)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("search failed: %v", err)), nil
		}

		out, err := json.Marshal(results)
		if err != nil {
			logger.Error("failed to marshal search results",
				sglog.Error(err),
				sglog.String("query", queryStr),
			)
			return mcp.NewToolResultError("internal error: failed to serialize results"), nil
		}
		return mcp.NewToolResultText(string(out)), nil
	})

	return s
}

type searchResult struct {
	FileCountTotal  int              `json:"file_count_total"`
	MatchCountTotal int              `json:"match_count_total"`
	Truncated       bool             `json:"truncated"`
	Files           []*web.FileMatch `json:"files"`
}

func runSearch(ctx context.Context, webSrv *web.Server, queryStr string, num int) (*searchResult, error) {
	if webSrv.Searcher == nil {
		return nil, fmt.Errorf("searcher not configured")
	}

	q, err := query.Parse(queryStr)
	if err != nil {
		return nil, fmt.Errorf("invalid query: %w", err)
	}

	sr, err := webSrv.Searcher.Search(ctx, q, &zoekt.SearchOptions{
		MaxDocDisplayCount: num,
		MaxWallTime:        10 * time.Second,
	})
	if err != nil {
		return nil, err
	}

	files, err := webSrv.FormatResults(sr, queryStr)
	if err != nil {
		return nil, fmt.Errorf("format results: %w", err)
	}

	return &searchResult{
		FileCountTotal:  sr.Stats.FileCount,
		MatchCountTotal: sr.Stats.MatchCount,
		Truncated:       len(sr.Files) < sr.Stats.FileCount,
		Files:           files,
	}, nil
}
