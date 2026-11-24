package main

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// commentPattern matches one HTML comment, capturing its interior, together
// with the spaces and the single line ending that follow it, so that
// removing a comment on a line of its own removes the whole line. Nothing
// before the comment is touched.
var commentPattern = regexp.MustCompile(`(?s)<!--(.*?)-->[ \t]*(?:\r\n|\n|\r)?`)

// extraction is what extractAnnotations found in one description.
type extraction struct {
	Description string              // the description with every HTML comment removed
	Blocks      map[string][]string // entries by key, in authored order; never nil
	Warnings    []string            // one per unrecognized comment, in order of appearance
}

// extractAnnotations finds every HTML comment in description, classifies
// it against reg for an advisory naming products, and removes it. A
// comment whose first line is a registered key is an annotation block and
// must be well formed; any other comment is stripped with a warning. An
// unterminated comment is an error, because the generator cannot tell
// where it ends.
func extractAnnotations(description string, products []string, reg Registry) (extraction, error) {
	out := extraction{Blocks: make(map[string][]string)}
	var stripped strings.Builder
	last := 0
	for _, m := range commentPattern.FindAllStringSubmatchIndex(description, -1) {
		stripped.WriteString(description[last:m[0]])
		last = m[1]
		inner := description[m[2]:m[3]]
		comment := description[m[0] : m[3]+len("-->")]

		// Split on CR, LF, or CRLF alike: empty pieces are dropped below, so
		// a CRLF pair needs no special case.
		var lines []string
		for _, line := range strings.FieldsFunc(inner, func(r rune) bool { return r == '\n' || r == '\r' }) {
			line, _, _ = strings.Cut(line, "#")
			if line = strings.TrimSpace(line); line != "" {
				lines = append(lines, line)
			}
		}
		if len(lines) == 0 {
			out.Warnings = append(out.Warnings, unrecognized(comment))
			continue
		}
		key, entries := lines[0], lines[1:]
		block, ok := reg.Blocks[key]
		if !ok {
			out.Warnings = append(out.Warnings, unrecognized(comment))
			continue
		}
		if _, dup := out.Blocks[key]; dup {
			return extraction{}, fmt.Errorf("second block for key %q", key)
		}
		if !slices.ContainsFunc(products, func(p string) bool { return slices.Contains(block.Products, p) }) {
			return extraction{}, fmt.Errorf("block %q is not registered for any product this advisory names (%s)", key, strings.Join(products, ", "))
		}
		if len(entries) == 0 {
			return extraction{}, fmt.Errorf("block %q has no entries", key)
		}
		for i, e := range entries {
			if !block.pattern.MatchString(e) {
				return extraction{}, fmt.Errorf("entry %q in block %q does not match the registered pattern", e, key)
			}
			if slices.Contains(entries[:i], e) {
				return extraction{}, fmt.Errorf("duplicate entry %q in block %q", e, key)
			}
		}
		out.Blocks[key] = entries
	}
	stripped.WriteString(description[last:])
	out.Description = stripped.String()
	if strings.Contains(out.Description, "<!--") {
		return extraction{}, errors.New("unterminated HTML comment")
	}
	return out, nil
}

// unrecognized is the warning for a comment that is not an annotation
// block, shortened so that a log line stays readable.
func unrecognized(comment string) string {
	return fmt.Sprintf("removed unrecognized HTML comment %q", truncate(comment, 60))
}

// annotationsFor returns the entries of the blocks whose key is registered
// for product. Never nil, so the feed carries {} rather than null.
func (r Registry) annotationsFor(product string, blocks map[string][]string) map[string][]string {
	out := make(map[string][]string)
	for key, entries := range blocks {
		if slices.Contains(r.Blocks[key].Products, product) {
			out[key] = entries
		}
	}
	return out
}
