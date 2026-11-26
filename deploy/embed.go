// Package deploy holds the files shipped with the binary: the annotated
// configuration examples that `featherauth config init` writes.
package deploy

import "embed"

// ConfigExample holds config.example: server.yaml, database.yaml,
// realms/example.yaml and locales/en.yaml.example.
//
//go:embed config.example
var ConfigExample embed.FS
