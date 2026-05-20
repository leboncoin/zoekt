package web

import "github.com/sourcegraph/zoekt"

// FormatResults applies the web presentation layer to a raw SearchResult.
// Defined here rather than in snippets.go to avoid touching upstream code and
// because formatResults is private to this package.
// Note: template rendering errors produce empty URLs rather than a returned error —
// this is the upstream behavior of formatResults.
func (s *Server) FormatResults(result *zoekt.SearchResult, query string) ([]*FileMatch, error) {
	return s.formatResults(result, query, false)
}
