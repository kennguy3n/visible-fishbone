package engine

import "github.com/kennguy3n/visible-fishbone/internal/repository"

// Match describes a single detection hit inside classified content.
// Defined in the engine package to avoid an import cycle between
// engine → dlp → engine.
type Match struct {
	RuleType   repository.DLPRuleType
	Pattern    string
	Offset     int
	Length     int
	Snippet    string
	Confidence float64
}
