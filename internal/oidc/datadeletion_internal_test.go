package oidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Covers: FR-34 (part)
func TestDataDeletionWithoutRealmIsServerError(t *testing.T) {
	w := httptest.NewRecorder()
	NewDataDeletion().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/data-deletion", nil))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status %d, want 500", w.Code)
	}
}
