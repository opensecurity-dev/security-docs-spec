package render

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/opensecurity-dev/security-docs-spec/spec"
)

// SecurityTxt renders an RFC 9116 security.txt from the set's public
// security-response document. It needs at least one public channel and an
// Expires value.
func SecurityTxt(set *spec.DocumentSet) (string, error) {
	view, err := set.ForAudience(spec.VisibilityPublic)
	if err != nil {
		return "", err
	}
	d := view.Documents.SecurityResponse
	if d == nil {
		return "", errors.New("render: security.txt needs a public securityResponse document")
	}
	if d.SecurityTxtExpires == "" {
		return "", errors.New("render: security.txt needs documents.securityResponse.securityTxtExpires")
	}
	var b strings.Builder
	contacts := 0
	// Prefer dedicated security channels (email, bug bounty); fall back to
	// forms only when there is no dedicated one.
	dedicated := slices.ContainsFunc(d.Channels, func(c spec.ReportingChannel) bool {
		return live(c) && (c.Kind == spec.ChannelEmail || c.Kind == spec.ChannelBugBounty)
	})
	for _, c := range d.Channels {
		if !live(c) || (dedicated && c.Kind != spec.ChannelEmail && c.Kind != spec.ChannelBugBounty) {
			continue
		}
		switch {
		case c.Kind == spec.ChannelEmail && c.Address != "":
			fmt.Fprintf(&b, "Contact: mailto:%s\n", c.Address)
		case c.URL != "":
			fmt.Fprintf(&b, "Contact: %s\n", c.URL)
		default:
			continue
		}
		contacts++
	}
	if contacts == 0 {
		return "", errors.New("render: security.txt needs at least one implemented public reporting channel")
	}
	expires := d.SecurityTxtExpires
	if len(expires) == len("2006-01-02") {
		expires += "T00:00:00Z"
	}
	fmt.Fprintf(&b, "Expires: %s\n", expires)
	if d.EncryptionKey != nil && d.EncryptionKey.URL != "" {
		fmt.Fprintf(&b, "Encryption: %s\n", d.EncryptionKey.URL)
	}
	slug := spec.DefaultSlugs[spec.KindSecurityResponse]
	if d.Slug != "" {
		slug = d.Slug
	}
	if u := view.Publication.DocURL(slug); u != "" {
		fmt.Fprintf(&b, "Policy: %s\n", u)
		if len(d.Acknowledgements) > 0 {
			fmt.Fprintf(&b, "Acknowledgments: %s\n", u)
		}
	}
	if view.Publication.SecurityTxtURL != "" {
		fmt.Fprintf(&b, "Canonical: %s\n", view.Publication.SecurityTxtURL)
	}
	b.WriteString("Preferred-Languages: en\n")
	return b.String(), nil
}

func live(c spec.ReportingChannel) bool {
	return c.Status == spec.StatusImplemented || c.Status == spec.StatusAlternative
}
