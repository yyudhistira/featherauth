// Package config holds the configuration types of FeatherAuth, their strict
// decoding from YAML and the defaults of the Configuration reference in
// docs/DESIGN.md.
package config

import "fmt"

// Severity tells whether a diagnostic stops a configuration from loading.
type Severity int

const (
	// Error makes the file invalid.
	Error Severity = iota + 1
	// Warning is reported but does not make the file invalid.
	Warning
)

func (s Severity) String() string {
	switch s {
	case Error:
		return "error"
	case Warning:
		return "warning"
	}
	return "unknown"
}

// Diagnostic is one problem found in a configuration file. Field is the
// option path such as "providers.google.timeout" or "keys[0].kid"; it is
// empty when the problem concerns the whole file.
type Diagnostic struct {
	File     string
	Line     int
	Field    string
	Severity Severity
	Message  string
}

func (d Diagnostic) String() string {
	pos := d.File
	if d.Line > 0 {
		pos = fmt.Sprintf("%s:%d", d.File, d.Line)
	}
	if d.Field != "" {
		return fmt.Sprintf("%s: %s: %s: %s", pos, d.Severity, d.Field, d.Message)
	}
	return fmt.Sprintf("%s: %s: %s", pos, d.Severity, d.Message)
}
