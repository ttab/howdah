package docform

import (
	"net/url"
	"strings"

	"github.com/ttab/newsdoc"
)

// Form orchestrates a set of components for extracting, validating, and
// applying document form data.
type Form struct {
	components []Component
}

// New creates a Form with the given components.
func New(components ...Component) *Form {
	return &Form{components: components}
}

// ExtractAll returns an ordered slice of ComponentBlocks, one per registered
// component, preserving registration order. Templates can range over the
// slice to render all components without knowing their names.
func (f *Form) ExtractAll(doc newsdoc.Document) []ComponentBlock {
	result := make([]ComponentBlock, 0, len(f.components))

	for _, c := range f.components {
		blocks := blocksForTarget(doc, c.Target())
		matched := newsdoc.AllBlocks(blocks, c.Matcher())

		result = append(result, ComponentBlock{
			Template: c.TemplateName(),
			Data:     c.Extract(matched),
		})
	}

	return result
}

// ValidateAll validates all components. Returns nil if no errors.
func (f *Form) ValidateAll(values url.Values) map[string][]FieldError {
	parsed := f.ParseValues(values)

	var result map[string][]FieldError

	for _, c := range f.components {
		errs := c.Validate(parsed[c.Name()])
		if len(errs) > 0 {
			if result == nil {
				result = make(map[string][]FieldError)
			}

			result[c.Name()] = errs
		}
	}

	return result
}

// ApplyAll applies all components to the document, replacing managed blocks
// while preserving unmanaged ones in their original positions.
func (f *Form) ApplyAll(doc newsdoc.Document, values url.Values) newsdoc.Document {
	parsed := f.ParseValues(values)

	for _, c := range f.components {
		blocks := blocksForTarget(doc, c.Target())
		matched := newsdoc.AllBlocks(blocks, c.Matcher())
		replacement := c.Apply(matched, parsed[c.Name()])
		blocks = replaceBlocks(blocks, c.Matcher(), replacement)

		switch c.Target() {
		case TargetMeta:
			doc.Meta = blocks
		case TargetLinks:
			doc.Links = blocks
		}
	}

	return doc
}

// ParseValues strips prefixes and returns per-component url.Values.
func (f *Form) ParseValues(values url.Values) map[string]url.Values {
	result := make(map[string]url.Values, len(f.components))

	for _, c := range f.components {
		result[c.Name()] = stripPrefix(c.Name(), values)
	}

	return result
}

// replaceBlocks finds blocks matching the matcher, records the position of the
// first match, drops all matches, and inserts the replacement blocks at the
// recorded position. If no previous match existed, appends at end.
func replaceBlocks(
	blocks []newsdoc.Block,
	matcher newsdoc.BlockMatcher,
	replacement []newsdoc.Block,
) []newsdoc.Block {
	firstIdx := -1

	for i, b := range blocks {
		if matcher.Match(b) {
			if firstIdx == -1 {
				firstIdx = i
			}
		}
	}

	filtered := newsdoc.DropBlocks(blocks, matcher)

	if len(replacement) == 0 {
		return filtered
	}

	if firstIdx == -1 {
		return append(filtered, replacement...)
	}

	// Adjust firstIdx for removed blocks before it.
	adjustedIdx := 0
	removed := 0

	for i, b := range blocks {
		if i == firstIdx {
			adjustedIdx = i - removed

			break
		}

		if matcher.Match(b) {
			removed++
		}
	}

	// Clamp to length.
	if adjustedIdx > len(filtered) {
		adjustedIdx = len(filtered)
	}

	result := make([]newsdoc.Block, 0, len(filtered)+len(replacement))
	result = append(result, filtered[:adjustedIdx]...)
	result = append(result, replacement...)
	result = append(result, filtered[adjustedIdx:]...)

	return result
}

// stripPrefix returns a new url.Values containing only keys that start with
// the given prefix followed by a dot, with that prefix stripped.
func stripPrefix(prefix string, values url.Values) url.Values {
	dot := prefix + "."
	result := make(url.Values)

	for key, vals := range values {
		if after, ok := strings.CutPrefix(key, dot); ok {
			result[after] = vals
		}
	}

	return result
}

func blocksForTarget(doc newsdoc.Document, target BlockTarget) []newsdoc.Block {
	switch target {
	case TargetMeta:
		return doc.Meta
	case TargetLinks:
		return doc.Links
	default:
		return nil
	}
}
