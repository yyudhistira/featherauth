//go:build !postgres

package main

// postgresDrivers is empty without the postgres tag: make postgres runs the
// admin tests on Postgres too (admin_drivers_postgres_test.go).
func postgresDrivers() []dbDriver { return nil }
