package audit

import "net/http"

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

type Header struct {
	Header   http.Header `json:"header"`
	Value    string      `json:"value"`
	Doc      string      `json:"doc"`
	Category string      `json:"category"`
	Rec      string      `json:"recommendation"`
}

// KnowledgeBase returns the baseline the target headers are audited against.
func KnowledgeBase() (map[string]Header, error) {
	kb := map[string]Header{
		// Source: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Type
		// and https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#content-type
		"Content-Type": {
			Doc:      "The `Content-Type` representation header is used to indicate the original media type of the resource (before any content encoding is applied for sending). If not set correctly, the resource (e.g. an image) may be interpreted as HTML, making XSS vulnerabilities possible.",
			Category: "general",
			Rec:      "",
		},
	}
	return kb, nil
}
