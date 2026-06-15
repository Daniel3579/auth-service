package testfile

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEnableCORSHandlesPreflight(t *testing.T) {
	handlerCalled := false

	handler := EnableCORS(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})

	req := httptest.NewRequest(http.MethodOptions, "/test", nil)
	rr := httptest.NewRecorder()

	handler(rr, req)

	if handlerCalled {
		t.Fatal("handler should not be called for OPTIONS request")
	}

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}

	if rr.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal("missing CORS allow origin header")
	}

	if !strings.Contains(rr.Header().Get("Access-Control-Allow-Methods"), "OPTIONS") {
		t.Fatal("missing OPTIONS method in CORS allow methods header")
	}
}

func TestValidateRequiresAuthorization(t *testing.T) {
	server := &HttpServer{}

	req := httptest.NewRequest(http.MethodGet, "/validate", nil)
	rr := httptest.NewRecorder()

	server.Validate(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestRefreshTokenRequiresAuthorization(t *testing.T) {
	server := &HttpServer{}

	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	rr := httptest.NewRecorder()

	server.RefreshToken(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestDeleteRequiresAuthorization(t *testing.T) {
	server := &HttpServer{}

	body := strings.NewReader(`{"id":1}`)
	req := httptest.NewRequest(http.MethodDelete, "/delete", body)
	rr := httptest.NewRecorder()

	server.Delete(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestLoginRejectsInvalidJSON(t *testing.T) {
	server := &HttpServer{}

	body := strings.NewReader(`{invalid json}`)
	req := httptest.NewRequest(http.MethodPost, "/login", body)
	rr := httptest.NewRecorder()

	server.Login(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestSignUpRejectsInvalidJSON(t *testing.T) {
	server := &HttpServer{}

	body := strings.NewReader(`{invalid json}`)
	req := httptest.NewRequest(http.MethodPost, "/signup", body)
	rr := httptest.NewRecorder()

	server.SignUp(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}
