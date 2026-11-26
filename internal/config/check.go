package config

import (
	"context"
	"errors"

	"github.com/yyudhistira/featherauth/internal/clock"
)

// Check loads the configuration in dir as the service would at startup and
// returns every diagnostic, errors and warnings, in the order the loader gives
// them. The configuration is valid when none has the severity Error; a
// configuration that cannot start always yields at least one error. It is what
// `featherauth config check` prints.
func Check(ctx context.Context, dir string, c clock.Clock) []Diagnostic {
	l, err := NewLoader(dir, c, nil)
	if err != nil {
		var le *LoadError
		if errors.As(err, &le) && hasError(le.Diagnostics) {
			return le.Diagnostics
		}
		ds := []Diagnostic{{File: dir, Severity: Error, Message: err.Error()}}
		if le != nil {
			ds = append(le.Diagnostics, ds...)
		}
		return ds
	}
	return l.Status().Last.Diagnostics
}
