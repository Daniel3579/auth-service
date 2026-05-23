package utils

import (
	"auth-service/logger"
	"context"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"
)

// ——————————————————————————————————————————————————————————————————————————————

func TestMain(m *testing.M) {
	// init logger
	if err := logger.Init(true); err != nil {
		panic(err)
	}
	code := m.Run()
	logger.Sync()
	os.Exit(code)
}

// ——————————————————————————————————————————————————————————————————————————————

func TestHashAndCheckPassword(t *testing.T) {
	password := "StrongP@ssw0rd!"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}
	if hash == "" {
		t.Fatal("expected non-empty hash")
	}

	// Correct password should pass
	if err := CheckPassword(hash, password); err != nil {
		t.Fatalf("CheckPassword failed for correct password: %v", err)
	}

	// Incorrect password should fail
	if err := CheckPassword(hash, "wrongpassword"); err == nil {
		t.Fatal("CheckPassword succeeded for wrong password; expected failure")
	}
}

func TestGenerateAndValidateToken_Success(t *testing.T) {
	// Ensure SECRET_KEY set for tests
	os.Setenv("SECRET_KEY", "test-secret-key")
	defer os.Unsetenv("SECRET_KEY")

	id := 13
	// generate access token
	token, err := GenerateToken(id, "user", "access", time.Minute*5)
	if err != nil {
		t.Fatalf("GenerateToken returned error: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}

	// validate token
	gotId, _, err := IsValid(token, "access")
	if err != nil {
		t.Fatalf("IsValid returned error for valid token: %v", err)
	}
	if gotId != id {
		t.Fatalf("IsValid returned username %q, want %q", gotId, id)
	}
}

func TestGenerateAndValidateToken_WrongType(t *testing.T) {
	os.Setenv("SECRET_KEY", "test-secret-key")
	defer os.Unsetenv("SECRET_KEY")

	id := 17
	// generate refresh token
	token, err := GenerateToken(id, "user", "refresh", time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken returned error: %v", err)
	}

	// Try validate as access token -> should fail
	_, _, err = IsValid(token, "access")
	if err == nil {
		t.Fatal("IsValid succeeded for token with wrong type; expected error")
	}
}

func TestGenerateAndValidateToken_Expired(t *testing.T) {
	os.Setenv("SECRET_KEY", "test-secret-key")
	defer os.Unsetenv("SECRET_KEY")

	id := 19
	// generate token with negative duration (already expired)
	token, err := GenerateToken(id, "user", "access", -time.Minute)
	if err != nil {
		t.Fatalf("GenerateToken returned error: %v", err)
	}

	_, _, err = IsValid(token, "access")
	if err == nil {
		t.Fatal("IsValid succeeded for expired token; expected error")
	}
}

func TestGetTokenMetadata_FromContext(t *testing.T) {
	ctxWithMeta := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer abc.xyz"))
	token, err := GetTokenMetadata(ctxWithMeta)
	if err != nil {
		t.Fatalf("GetTokenMetadata returned error: %v", err)
	}
	if token != "Bearer abc.xyz" {
		t.Fatalf("unexpected token: got %q want %q", token, "Bearer abc.xyz")
	}
}

func TestGetTokenMetadata_Missing(t *testing.T) {
	_, err := GetTokenMetadata(context.Background())
	if err == nil {
		t.Fatal("GetTokenMetadata succeeded with missing metadata; expected error")
	}
}
