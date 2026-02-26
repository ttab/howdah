package docform

import (
	"net/url"

	"github.com/ttab/newsdoc"
)

// BlockTarget indicates whether a component operates on Meta or Links blocks.
type BlockTarget int

const (
	TargetMeta BlockTarget = iota
	TargetLinks
)

// FieldError represents a validation error for a specific form field.
type FieldError struct {
	Field   string
	Message string
}

// ComponentBlock pairs a component's template name with its extracted data,
// allowing dynamic dispatch via renderBlock in templates.
type ComponentBlock struct {
	Template string
	Data     any
}

// Component is a self-contained handler for a specific block type in a
// document form. Each component knows how to extract template data from
// document blocks, validate submitted form values, and apply form values
// back to blocks.
type Component interface {
	// Name returns a unique identifier, also used as the form field prefix.
	Name() string

	// TemplateName returns the name of the {{define}} block that renders
	// this component's form fields.
	TemplateName() string

	// Target returns whether this component operates on Meta or Links.
	Target() BlockTarget

	// Matcher returns the BlockMatcher that selects this component's blocks.
	Matcher() newsdoc.BlockMatcher

	// Extract returns template-ready data from the matched blocks.
	Extract(blocks []newsdoc.Block) any

	// Validate checks form values (prefix already stripped) and returns errors.
	Validate(values url.Values) []FieldError

	// Apply receives the originally matched blocks and stripped form values,
	// returns the replacement blocks.
	Apply(original []newsdoc.Block, values url.Values) []newsdoc.Block
}
