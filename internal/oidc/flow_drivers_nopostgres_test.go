//go:build !postgres

package oidc_test

// postgresFlowDrivers is empty without the postgres tag: make postgres runs the
// flows on Postgres too (flow_drivers_postgres_test.go).
func postgresFlowDrivers() []flowDriver { return nil }
