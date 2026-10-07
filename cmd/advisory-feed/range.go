package main

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	// versionPattern is the authoring guide's rule: bare MAJOR.MINOR.PATCH.
	versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	// constraintPattern splits one constraint into its operator and version.
	constraintPattern = regexp.MustCompile(`^(>=|<=|>|<|=)\s*(\S+)$`)
)

// Range is one affected version range for a product: every version from
// Introduced (inclusive, or all earlier versions when nil) up to but not
// including Fixed.
type Range struct {
	Introduced *string `json:"introduced"`
	Fixed      string  `json:"fixed"`
}

// ParseRange converts GitHub's affected-version string, for example
// ">= 1.32.0, < 1.40.0", into a Range. Only ">=" and "<" constraints are
// accepted. patched is the row's patched_versions value; it supplies the
// upper bound when the range has none and must agree with it otherwise.
func ParseRange(rangeText, patched string) (Range, error) {
	var introduced, fixed *string
	for _, part := range strings.Split(rangeText, ",") {
		part = strings.TrimSpace(part)
		m := constraintPattern.FindStringSubmatch(part)
		if m == nil {
			return Range{}, fmt.Errorf("cannot parse constraint %q in range %q", part, rangeText)
		}
		op, v := m[1], m[2]
		if !versionPattern.MatchString(v) {
			return Range{}, fmt.Errorf("invalid version %q in range %q", v, rangeText)
		}
		switch op {
		case ">=":
			if introduced != nil {
				return Range{}, fmt.Errorf("range %q has more than one lower bound", rangeText)
			}
			introduced = &v
		case "<":
			if fixed != nil {
				return Range{}, fmt.Errorf("range %q has more than one upper bound", rangeText)
			}
			fixed = &v
		default:
			return Range{}, fmt.Errorf("unsupported operator in range %q: only >= and < are allowed", rangeText)
		}
	}
	if p := strings.TrimSpace(patched); p != "" {
		if !versionPattern.MatchString(p) {
			return Range{}, fmt.Errorf("invalid patched version %q", p)
		}
		if fixed == nil {
			fixed = &p
		} else if *fixed != p {
			return Range{}, fmt.Errorf("range %q upper bound %s differs from patched version %s", rangeText, *fixed, p)
		}
	}
	if fixed == nil {
		return Range{}, fmt.Errorf("range %q has no upper bound and no patched version", rangeText)
	}
	return Range{Introduced: introduced, Fixed: *fixed}, nil
}
