package config

import (
	"fmt"
	"time"

	"go.yaml.in/yaml/v3"
)

// Duration is a time.Duration written in Go syntax (30s, 15m, 720h). The
// plain number 0 is accepted too. Range checks belong to validation.
type Duration time.Duration

// ParseDuration parses Go duration syntax.
func ParseDuration(s string) (Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("cannot parse `%s` as a duration (Go syntax such as 30s, 15m or 720h)", s)
	}
	return Duration(d), nil
}

// Std returns the value as a time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

func (d Duration) String() string { return time.Duration(d).String() }

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return &yaml.TypeError{Errors: []string{fmt.Sprintf("line %d: a duration must be a text such as 30s", n.Line)}}
	}
	v, err := ParseDuration(n.Value)
	if err != nil {
		return &yaml.TypeError{Errors: []string{fmt.Sprintf("line %d: %s", n.Line, err)}}
	}
	*d = v
	return nil
}
