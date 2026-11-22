package audit

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"net/url"
	"slices"
	"strings"
	"unicode"
)

// MaxBaselineSize is the largest baseline document LoadRules accepts.
const MaxBaselineSize = 1 << 20

// ErrInvalidBaseline is returned when a baseline document can't be used.
var ErrInvalidBaseline = errors.New("invalid baseline")

//go:embed baseline.json
var embeddedBaseline []byte

// Category groups rules in the knowledge base.
type Category int16

const (
	General  Category = 0
	Cache    Category = 1
	Security Category = 2
)

func (c Category) String() string {
	switch c {
	case General:
		return "general"
	case Cache:
		return "cache"
	case Security:
		return "security"
	}
	return "unknown"
}

// MarshalText implements encoding.TextMarshaler.
func (c Category) MarshalText() ([]byte, error) {
	if c.String() == "unknown" {
		return nil, fmt.Errorf("unknown category %d", c)
	}
	return []byte(c.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (c *Category) UnmarshalText(b []byte) error {
	for _, v := range []Category{General, Cache, Security} {
		if string(b) == v.String() {
			*c = v
			return nil
		}
	}
	return fmt.Errorf("unknown category %q", b)
}

// Expectation says whether a rule's header should be sent or not.
type Expectation int16

const (
	// Present rules expect the header to be sent, optionally with an allowed value.
	Present Expectation = 0
	// Absent rules expect the header not to be sent, e.g. version banners.
	Absent Expectation = 1
)

func (e Expectation) String() string {
	switch e {
	case Present:
		return "present"
	case Absent:
		return "absent"
	}
	return "unknown"
}

// MarshalText implements encoding.TextMarshaler.
func (e Expectation) MarshalText() ([]byte, error) {
	if e.String() == "unknown" {
		return nil, fmt.Errorf("unknown expectation %d", e)
	}
	return []byte(e.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (e *Expectation) UnmarshalText(b []byte) error {
	for _, v := range []Expectation{Present, Absent} {
		if string(b) == v.String() {
			*e = v
			return nil
		}
	}
	return fmt.Errorf("unknown expectation %q", b)
}

// Rule is one baseline entry: what a header should look like and why.
type Rule struct {
	// Name is the canonical header name, e.g. "X-Content-Type-Options".
	Name     string      `json:"name"`
	Category Category    `json:"category"`
	Expect   Expectation `json:"expect"`
	// Allowed lists acceptable values (case-insensitive). Empty means any value.
	Allowed []string `json:"allowed,omitempty"`
	// Recommended is the header value to set. Present rules only.
	Recommended string `json:"recommended,omitempty"`
	Doc         string `json:"doc"`
	// Sources cite where the rule comes from (OWASP, MDN, RFC).
	Sources []string `json:"sources"`
}

type baseline struct {
	Rules []Rule `json:"rules"`
}

// KnowledgeBase returns the rules of the baseline embedded in the binary.
func KnowledgeBase() ([]Rule, error) {
	return LoadRules(bytes.NewReader(embeddedBaseline))
}

// LoadRules reads and validates a JSON baseline document of at most
// MaxBaselineSize bytes. Rules are returned sorted by name.
func LoadRules(r io.Reader) ([]Rule, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: nil reader", ErrInvalidBaseline)
	}
	data, err := io.ReadAll(io.LimitReader(r, MaxBaselineSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxBaselineSize {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrInvalidBaseline, MaxBaselineSize)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var b baseline
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidBaseline, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: unexpected data after the baseline object", ErrInvalidBaseline)
	}
	if len(b.Rules) == 0 {
		return nil, fmt.Errorf("%w: no rules", ErrInvalidBaseline)
	}

	seen := make(map[string]bool, len(b.Rules))
	for _, rule := range b.Rules {
		if err := validateRule(rule); err != nil {
			return nil, err
		}
		if seen[rule.Name] {
			return nil, fmt.Errorf("%w: %q: duplicate rule", ErrInvalidBaseline, rule.Name)
		}
		seen[rule.Name] = true
	}

	slices.SortFunc(b.Rules, func(a, b Rule) int { return strings.Compare(a.Name, b.Name) })
	return b.Rules, nil
}

func validateRule(rule Rule) error {
	invalid := func(format string, args ...any) error {
		return fmt.Errorf("%w: %q: %s", ErrInvalidBaseline, rule.Name, fmt.Sprintf(format, args...))
	}

	if rule.Name == "" {
		return invalid("empty name")
	}
	if !isToken(rule.Name) {
		return invalid("name is not a valid header name")
	}
	if canon := textproto.CanonicalMIMEHeaderKey(rule.Name); canon != rule.Name {
		return invalid("name must be canonical (%s)", canon)
	}
	if strings.TrimSpace(rule.Doc) == "" {
		return invalid("empty doc")
	}
	if !printable(rule.Doc) {
		return invalid("doc contains control or format characters")
	}
	if len(rule.Sources) == 0 {
		return invalid("no sources")
	}
	for _, s := range rule.Sources {
		u, err := url.Parse(s)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return invalid("source %q is not an https URL", s)
		}
	}

	switch rule.Expect {
	case Present:
		if rule.Recommended == "" {
			return invalid("present rule needs a recommended value")
		}
		if err := checkValue(rule.Recommended); err != "" {
			return invalid("recommended value %q %s", rule.Recommended, err)
		}
		for _, v := range rule.Allowed {
			if err := checkValue(v); err != "" {
				return invalid("allowed value %q %s", v, err)
			}
		}
		if len(rule.Allowed) > 0 && !containsFold(rule.Allowed, rule.Recommended) {
			return invalid("recommended value %q is not in allowed", rule.Recommended)
		}
	case Absent:
		if rule.Recommended != "" || len(rule.Allowed) > 0 {
			return invalid("absent rule can't have recommended or allowed values")
		}
	}
	return nil
}

// checkValue describes why v can't be used as a header value in a rule, or
// returns "" if it can. Values are compared with trimmed server values, so
// they must be trimmed themselves, and they are printed in reports.
func checkValue(v string) string {
	switch {
	case v == "":
		return "is empty"
	case strings.TrimSpace(v) != v:
		return "has leading or trailing whitespace"
	case !printable(v):
		return "contains control or format characters"
	}
	return ""
}

// printable reports whether s is free of control characters (including ANSI
// escape introducers) and Unicode format characters such as bidi overrides
// and zero-width spaces, so it can't alter the terminal when printed.
func printable(s string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
	})
}

func containsFold(list []string, s string) bool {
	return slices.ContainsFunc(list, func(v string) bool { return strings.EqualFold(v, s) })
}

// isToken reports whether s is an HTTP token (RFC 9110, section 5.6.2).
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("!#$%&'*+-.^_`|~", r):
		default:
			return false
		}
	}
	return true
}
