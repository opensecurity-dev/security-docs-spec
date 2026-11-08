package spec

import (
	"regexp"
	"strings"
)

// placeholderRe matches {{key}} with optional inner spaces, such as
// {{ product.name }}. Keys are lower-case dotted words.
var placeholderRe = regexp.MustCompile(`\{\{\s*([a-zA-Z][a-zA-Z0-9_.-]*)\s*\}\}`)

// Placeholders returns the values prose may refer to as {{key}}. It is a
// fixed substitution, not a template language: prose cannot reach fields
// that are not listed here.
//
// Keys: org.name, org.legalName, org.url, product.name, product.url,
// contact.<role> (Markdown link target) and contact.<role>.email for
// security, support, privacy and abuse, and doc.<slug> (relative link to a
// rendered document).
func (s *DocumentSet) Placeholders() map[string]string {
	m := map[string]string{
		"org.name":      s.Organization.Name,
		"org.legalName": firstNonEmpty(s.Organization.LegalName, s.Organization.Name),
		"org.url":       s.Organization.URL,
		"product.name":  s.Product.Name,
		"product.url":   s.Product.URL,
	}
	for role, c := range map[string]*Contact{
		"security": s.Contacts.Security, "support": s.Contacts.Support,
		"privacy": s.Contacts.Privacy, "abuse": s.Contacts.Abuse,
	} {
		if c == nil {
			continue
		}
		m["contact."+role] = c.Link()
		if c.Email != "" {
			m["contact."+role+".email"] = c.Email
		}
	}
	for _, ref := range s.Documents.List() {
		m["doc."+ref.Slug()] = ref.Slug() + ".md"
	}
	return m
}

// Expand replaces each {{key}} in text with its value. Unknown keys are left
// as they are, so lint and readers can see them.
func Expand(text string, values map[string]string) string {
	if !strings.Contains(text, "{{") {
		return text
	}
	return placeholderRe.ReplaceAllStringFunc(text, func(m string) string {
		key := placeholderRe.FindStringSubmatch(m)[1]
		if v, ok := values[key]; ok {
			return v
		}
		return m
	})
}

// PlaceholderKeys returns the keys referenced in text, in order.
func PlaceholderKeys(text string) []string {
	var keys []string
	for _, m := range placeholderRe.FindAllStringSubmatch(text, -1) {
		keys = append(keys, m[1])
	}
	return keys
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
