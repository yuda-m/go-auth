package service

import (
	"testing"
	"time"

	"go-auth/internal/repository/memory"
)

func TestAuthServiceRegisterLoginRefresh(t *testing.T) {
	store := memory.NewStore()
	tokens := NewTokenService("test-secret", time.Minute, time.Hour)
	svc := NewAuthService(store, tokens)

	user, pair, err := svc.Register(RegisterInput{
		Name:     "Test User",
		Email:    "test@example.com",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	if user.Email != "test@example.com" {
		t.Fatalf("unexpected email: %s", user.Email)
	}

	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatalf("expected tokens to be issued")
	}

	if _, err := tokens.ParseAndValidate(pair.AccessToken, "access"); err != nil {
		t.Fatalf("validate access token: %v", err)
	}

	loginUser, loginPair, err := svc.Login(LoginInput{
		Email:    "test@example.com",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	if loginUser.ID != user.ID {
		t.Fatalf("unexpected login user id: %s", loginUser.ID)
	}

	refreshedUser, refreshedPair, err := svc.Refresh(loginPair.RefreshToken)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}

	if refreshedUser.ID != user.ID {
		t.Fatalf("unexpected refresh user id: %s", refreshedUser.ID)
	}

	if refreshedPair.RefreshToken == loginPair.RefreshToken {
		t.Fatalf("refresh token should rotate")
	}

	if _, _, err := svc.Refresh(loginPair.RefreshToken); err == nil {
		t.Fatalf("expected consumed refresh token to fail")
	}
}
