package identity

import (
	"fmt"
	"strings"
)

// --- SCIM filter expression grammar (RFC 7644 §3.4.2.2) -------------------
//
// This file implements the full filter grammar SCIM clients (Okta,
// Microsoft Entra ID, OneLogin, JumpCloud) emit against the /Users and
// /Groups collections:
//
//	FILTER    = attrExp / logExp / *1"not" "(" FILTER ")" / "(" FILTER ")"
//	logExp    = FILTER SP ("and" / "or") SP FILTER
//	attrExp   = (attrPath SP "pr") / (attrPath SP compareOp SP compValue)
//	compareOp = "eq" / "ne" / "co" / "sw" / "ew" / "gt" / "lt" / "ge" / "le"
//	compValue = false / null / true / number / string
//
// `and` binds tighter than `or`; parentheses override precedence and
// `not (...)` negates a grouped sub-expression.
//
// The simpler single-clause [ParseSCIMFilter] is retained for the
// repository pushdown fast path (a `userName eq "x"` dedup lookup must
// stay an indexed query, never an in-memory scan). [parseFilterExpr]
// is the general parser the list endpoints use; a parsed expression
// that happens to be a single pushdownable clause is recognised by
// [filterExpr.pushdown] so the optimisation still applies.

// scimCompareOp enumerates every RFC 7644 comparison operator. It is a
// superset of the pushdown-only [SCIMFilterOp] (eq/co/sw).
type scimCompareOp string

const (
	opEq scimCompareOp = "eq"
	opNe scimCompareOp = "ne"
	opCo scimCompareOp = "co"
	opSw scimCompareOp = "sw"
	opEw scimCompareOp = "ew"
	opGt scimCompareOp = "gt"
	opGe scimCompareOp = "ge"
	opLt scimCompareOp = "lt"
	opLe scimCompareOp = "le"
	opPr scimCompareOp = "pr" // presence; takes no value
)

func parseCompareOp(s string) (scimCompareOp, bool) {
	switch scimCompareOp(strings.ToLower(s)) {
	case opEq, opNe, opCo, opSw, opEw, opGt, opGe, opLt, opLe, opPr:
		return scimCompareOp(strings.ToLower(s)), true
	default:
		return "", false
	}
}

// filterExpr is a parsed SCIM filter AST node. Implementations evaluate
// against a SCIM resource in memory; the list endpoints fall back to
// in-memory evaluation for any filter that is not a single pushdownable
// clause.
type filterExpr interface {
	matchUser(SCIMUser) bool
	matchGroup(SCIMGroup) bool
}

// compareExpr is a single `attr op value` (or `attr pr`) clause.
type compareExpr struct {
	attr  string
	op    scimCompareOp
	value string
}

func (e compareExpr) matchUser(u SCIMUser) bool {
	field, present := userAttr(u, e.attr)
	return evalCompare(e.op, field, present, e.value)
}

func (e compareExpr) matchGroup(g SCIMGroup) bool {
	field, present := groupAttr(g, e.attr)
	return evalCompare(e.op, field, present, e.value)
}

// notExpr negates its child.
type notExpr struct{ child filterExpr }

func (e notExpr) matchUser(u SCIMUser) bool   { return !e.child.matchUser(u) }
func (e notExpr) matchGroup(g SCIMGroup) bool { return !e.child.matchGroup(g) }

// andExpr / orExpr combine two sub-expressions.
type andExpr struct{ left, right filterExpr }

func (e andExpr) matchUser(u SCIMUser) bool   { return e.left.matchUser(u) && e.right.matchUser(u) }
func (e andExpr) matchGroup(g SCIMGroup) bool { return e.left.matchGroup(g) && e.right.matchGroup(g) }

type orExpr struct{ left, right filterExpr }

func (e orExpr) matchUser(u SCIMUser) bool   { return e.left.matchUser(u) || e.right.matchUser(u) }
func (e orExpr) matchGroup(g SCIMGroup) bool { return e.left.matchGroup(g) || e.right.matchGroup(g) }

// pushdown reports the single-clause SCIMFilter equivalent of this
// expression when (and only when) the whole filter is one comparison
// using an operator the repository can push down to an indexed query
// (eq/co/sw). Compound, negated, or richer-operator filters return
// false and are evaluated in memory.
func pushdown(e filterExpr) (SCIMFilter, bool) {
	c, ok := e.(compareExpr)
	if !ok {
		return SCIMFilter{}, false
	}
	switch c.op {
	case opEq:
		return SCIMFilter{Attribute: c.attr, Op: SCIMFilterEq, Value: c.value}, true
	case opCo:
		return SCIMFilter{Attribute: c.attr, Op: SCIMFilterCo, Value: c.value}, true
	case opSw:
		return SCIMFilter{Attribute: c.attr, Op: SCIMFilterSw, Value: c.value}, true
	default:
		return SCIMFilter{}, false
	}
}

// evalCompare evaluates one comparison operator. String comparisons are
// case-insensitive per RFC 7644 §3.4.2.2 (the default caseExact=false
// for the User/Group string attributes SNG exposes). `pr` tests
// presence; ordering operators (gt/ge/lt/le) compare case-insensitively
// and lexicographically, matching how IdPs filter on `meta.lastModified`
// style attributes.
func evalCompare(op scimCompareOp, field string, present bool, value string) bool {
	if op == opPr {
		return present
	}
	fl := strings.ToLower(field)
	vl := strings.ToLower(value)
	switch op {
	case opEq:
		return fl == vl
	case opNe:
		return fl != vl
	case opCo:
		return strings.Contains(fl, vl)
	case opSw:
		return strings.HasPrefix(fl, vl)
	case opEw:
		return strings.HasSuffix(fl, vl)
	case opGt:
		return fl > vl
	case opGe:
		return fl >= vl
	case opLt:
		return fl < vl
	case opLe:
		return fl <= vl
	default:
		return false
	}
}

// canonicalAttr normalises a SCIM filter attribute path for lookup: it
// strips a leading core-schema URN prefix (User or Group) and lowercases
// the result. Microsoft Entra ID emits fully-qualified attribute names
// (e.g. "urn:ietf:params:scim:schemas:core:2.0:User:userName"), so this
// keeps the qualified and short forms resolving to the same field across
// both the in-memory matcher and the repository pushdown path. The
// prefix match is case-insensitive: a URN namespace identifier is
// case-insensitive (RFC 8141 §2), so a qualified path differing only in
// the casing of its schema prefix must still canonicalise to the same
// short attribute.
func canonicalAttr(attr string) string {
	return strings.ToLower(trimSchemaPrefix(attr))
}

// trimSchemaPrefix removes a leading core-schema URN prefix (User or
// Group) from a qualified attribute path, comparing the prefix
// case-insensitively. The post-prefix attribute portion is returned
// unchanged (callers lowercase as needed).
func trimSchemaPrefix(attr string) string {
	for _, prefix := range [...]string{SCIMSchemaUser + ":", SCIMSchemaGroup + ":"} {
		if len(attr) >= len(prefix) && strings.EqualFold(attr[:len(prefix)], prefix) {
			return attr[len(prefix):]
		}
	}
	return attr
}

// userAttr resolves a SCIM filter attribute path to a user's field
// value and whether it is present (non-empty). It mirrors the resource
// shape userToSCIM emits so a filter can target any returned attribute.
func userAttr(u SCIMUser, attr string) (string, bool) {
	switch canonicalAttr(attr) {
	case "id":
		return u.ID, u.ID != ""
	case "username":
		return u.UserName, u.UserName != ""
	case "displayname":
		return u.DisplayName, u.DisplayName != ""
	case "externalid":
		return u.ExternalID, u.ExternalID != ""
	case "name.formatted":
		return u.Name.Formatted, u.Name.Formatted != ""
	case "name.givenname":
		return u.Name.GivenName, u.Name.GivenName != ""
	case "name.familyname":
		return u.Name.FamilyName, u.Name.FamilyName != ""
	case "active":
		if u.Active != nil && *u.Active {
			return "true", true
		}
		return "false", true
	case "email", "emails", "emails.value":
		return primaryEmail(u), primaryEmail(u) != ""
	default:
		return "", false
	}
}

// groupAttr resolves a SCIM filter attribute path to a group's field.
func groupAttr(g SCIMGroup, attr string) (string, bool) {
	switch canonicalAttr(attr) {
	case "id":
		return g.ID, g.ID != ""
	case "displayname":
		return g.DisplayName, g.DisplayName != ""
	case "externalid":
		return g.ExternalID, g.ExternalID != ""
	default:
		return "", false
	}
}

func primaryEmail(u SCIMUser) string {
	for _, e := range u.Emails {
		if e.Primary {
			return e.Value
		}
	}
	if len(u.Emails) > 0 {
		return u.Emails[0].Value
	}
	return u.UserName
}

// --- Tokeniser ------------------------------------------------------------

type scimTokenKind int

const (
	tokWord   scimTokenKind = iota // attrPath, operator, keyword, or bareword value
	tokString                      // quoted string literal
	tokLParen
	tokRParen
)

type scimToken struct {
	kind scimTokenKind
	text string
}

// tokenizeFilter splits a SCIM filter string into tokens. Quoted
// strings honour `\"` and `\\` escapes; everything else is whitespace-
// or paren-delimited. Brackets ('[' / ']') are rejected explicitly so a
// valuePath filter fails with a clear error rather than mis-parsing.
func tokenizeFilter(raw string) ([]scimToken, error) {
	var toks []scimToken
	i := 0
	for i < len(raw) {
		c := raw[i]
		switch c {
		case ' ', '\t', '\n', '\r':
			i++
		case '(':
			toks = append(toks, scimToken{tokLParen, "("})
			i++
		case ')':
			toks = append(toks, scimToken{tokRParen, ")"})
			i++
		case '"':
			var sb strings.Builder
			i++ // consume opening quote
			closed := false
			for i < len(raw) {
				ch := raw[i]
				if ch == '\\' && i+1 < len(raw) {
					sb.WriteByte(raw[i+1])
					i += 2
					continue
				}
				if ch == '"' {
					i++
					closed = true
					break
				}
				sb.WriteByte(ch)
				i++
			}
			if !closed {
				return nil, fmt.Errorf("unterminated string literal in filter")
			}
			toks = append(toks, scimToken{tokString, sb.String()})
		case '[', ']':
			return nil, fmt.Errorf("valuePath filters (attr[...]) are not supported")
		default:
			start := i
			for i < len(raw) {
				ch := raw[i]
				if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '(' || ch == ')' || ch == '"' {
					break
				}
				i++
			}
			toks = append(toks, scimToken{tokWord, raw[start:i]})
		}
	}
	return toks, nil
}

// --- Recursive-descent parser --------------------------------------------

type filterParser struct {
	toks []scimToken
	pos  int
}

func (p *filterParser) peek() (scimToken, bool) {
	if p.pos >= len(p.toks) {
		return scimToken{}, false
	}
	return p.toks[p.pos], true
}

func (p *filterParser) next() (scimToken, bool) {
	t, ok := p.peek()
	if ok {
		p.pos++
	}
	return t, ok
}

// parseFilterExpr parses a complete SCIM filter expression. It returns
// an error for empty input, trailing tokens, or malformed clauses.
func parseFilterExpr(raw string) (filterExpr, error) {
	toks, err := tokenizeFilter(raw)
	if err != nil {
		return nil, err
	}
	if len(toks) == 0 {
		return nil, fmt.Errorf("empty filter")
	}
	p := &filterParser{toks: toks}
	expr, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) {
		return nil, fmt.Errorf("unexpected token %q after filter", p.toks[p.pos].text)
	}
	return expr, nil
}

func (p *filterParser) parseOr() (filterExpr, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		t, ok := p.peek()
		if !ok || t.kind != tokWord || !strings.EqualFold(t.text, "or") {
			return left, nil
		}
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = orExpr{left: left, right: right}
	}
}

func (p *filterParser) parseAnd() (filterExpr, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		t, ok := p.peek()
		if !ok || t.kind != tokWord || !strings.EqualFold(t.text, "and") {
			return left, nil
		}
		p.next()
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = andExpr{left: left, right: right}
	}
}

func (p *filterParser) parseUnary() (filterExpr, error) {
	t, ok := p.peek()
	if !ok {
		return nil, fmt.Errorf("unexpected end of filter")
	}
	if t.kind == tokWord && strings.EqualFold(t.text, "not") {
		p.next()
		open, ok := p.next()
		if !ok || open.kind != tokLParen {
			return nil, fmt.Errorf("expected '(' after 'not'")
		}
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		closeTok, ok := p.next()
		if !ok || closeTok.kind != tokRParen {
			return nil, fmt.Errorf("expected ')' to close 'not (...)'")
		}
		return notExpr{child: inner}, nil
	}
	return p.parsePrimary()
}

func (p *filterParser) parsePrimary() (filterExpr, error) {
	t, ok := p.next()
	if !ok {
		return nil, fmt.Errorf("unexpected end of filter")
	}
	if t.kind == tokLParen {
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		closeTok, ok := p.next()
		if !ok || closeTok.kind != tokRParen {
			return nil, fmt.Errorf("expected ')'")
		}
		return inner, nil
	}
	if t.kind != tokWord {
		return nil, fmt.Errorf("expected attribute name, got %q", t.text)
	}
	return p.parseAttrExp(t.text)
}

// parseAttrExp parses `attr pr` or `attr op value` given the already-
// consumed attribute word.
func (p *filterParser) parseAttrExp(attr string) (filterExpr, error) {
	opTok, ok := p.next()
	if !ok || opTok.kind != tokWord {
		return nil, fmt.Errorf("expected operator after attribute %q", attr)
	}
	op, ok := parseCompareOp(opTok.text)
	if !ok {
		return nil, fmt.Errorf("unsupported filter operator %q", opTok.text)
	}
	if op == opPr {
		return compareExpr{attr: attr, op: op}, nil
	}
	valTok, ok := p.next()
	if !ok {
		return nil, fmt.Errorf("expected value after operator %q", opTok.text)
	}
	if valTok.kind != tokString && valTok.kind != tokWord {
		return nil, fmt.Errorf("expected value after operator %q", opTok.text)
	}
	return compareExpr{attr: attr, op: op, value: valTok.text}, nil
}
