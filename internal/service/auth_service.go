package service

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"go-auth/internal/model"
	"go-auth/internal/repository/memory"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrRefreshUnavailable = errors.New("refresh token is not active")
)

type AuthService struct {
	store  *memory.Store
	tokens *TokenService
}

func NewAuthService(store *memory.Store, tokens *TokenService) *AuthService {
	return &AuthService{store: store, tokens: tokens}
}

type RegisterInput struct {
	Name     string `json:"name" binding:"required,min=2,max=80"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8,max=128"`
}

type LoginInput struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

func (s *AuthService) Register(input RegisterInput) (*model.User, TokenPair, error) {
	email := strings.ToLower(strings.TrimSpace(input.Email))

	if _, err := s.store.GetUserByEmail(email); err == nil {
		return nil, TokenPair{}, ErrUserAlreadyExists
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, TokenPair{}, fmt.Errorf("hash password: %w", err)
	}

	user := &model.User{
		ID:           newID(),
		Name:         strings.TrimSpace(input.Name),
		Email:        email,
		PasswordHash: string(hash),
		Role:         model.RoleUser,
	}

	if err := s.store.CreateUser(user); err != nil {
		if errors.Is(err, memory.ErrAlreadyExists) {
			return nil, TokenPair{}, ErrUserAlreadyExists
		}
		return nil, TokenPair{}, err
	}

	pair, _, refreshJTI, err := s.IssueForUser(user)
	if err != nil {
		return nil, TokenPair{}, err
	}

	s.store.SaveRefreshToken(model.RefreshSession{
		TokenID:   refreshJTI,
		UserID:    user.ID,
		ExpiresAt: time.Now().UTC().Add(s.tokens.refreshTTL),
	})

	return user, pair, nil
}

func (s *AuthService) Login(input LoginInput) (*model.User, TokenPair, error) {
	user, err := s.store.GetUserByEmail(input.Email)
	if err != nil {
		return nil, TokenPair{}, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Password)); err != nil {
		return nil, TokenPair{}, ErrInvalidCredentials
	}

	pair, _, refreshJTI, err := s.IssueForUser(user)
	if err != nil {
		return nil, TokenPair{}, err
	}

	s.store.SaveRefreshToken(model.RefreshSession{
		TokenID:   refreshJTI,
		UserID:    user.ID,
		ExpiresAt: time.Now().UTC().Add(s.tokens.refreshTTL),
	})

	return user, pair, nil
}

func (s *AuthService) Refresh(refreshToken string) (*model.User, TokenPair, error) {
	claims, err := s.tokens.ParseAndValidate(refreshToken, "refresh")
	if err != nil {
		return nil, TokenPair{}, ErrInvalidCredentials
	}

	session, ok := s.store.ConsumeRefreshToken(claims.ID)
	if !ok {
		return nil, TokenPair{}, ErrRefreshUnavailable
	}

	if session.UserID != claims.UserID {
		return nil, TokenPair{}, ErrInvalidCredentials
	}

	user, err := s.store.GetUserByID(session.UserID)
	if err != nil {
		return nil, TokenPair{}, ErrInvalidCredentials
	}

	pair, _, refreshJTI, err := s.IssueForUser(user)
	if err != nil {
		return nil, TokenPair{}, err
	}

	s.store.SaveRefreshToken(model.RefreshSession{
		TokenID:   refreshJTI,
		UserID:    user.ID,
		ExpiresAt: time.Now().UTC().Add(s.tokens.refreshTTL),
	})

	return user, pair, nil
}

func (s *AuthService) Logout(refreshToken string) error {
	claims, err := s.tokens.ParseAndValidate(refreshToken, "refresh")
	if err != nil {
		return ErrInvalidCredentials
	}

	session, ok := s.store.ConsumeRefreshToken(claims.ID)
	if !ok || session.UserID != claims.UserID {
		return ErrRefreshUnavailable
	}

	return nil
}

func (s *AuthService) SeedAdmin(email, password string) error {
	if _, err := s.store.GetUserByEmail(email); err == nil {
		return nil
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash admin password: %w", err)
	}

	admin := &model.User{
		ID:           newID(),
		Name:         "Administrator",
		Email:        strings.ToLower(strings.TrimSpace(email)),
		PasswordHash: string(hash),
		Role:         model.RoleAdmin,
	}
	return s.store.SeedUser(admin)
}

func (s *AuthService) IssueForUser(user *model.User) (TokenPair, string, string, error) {
	pair, accessJTI, refreshJTI, err := s.tokens.IssuePair(user)
	if err != nil {
		return TokenPair{}, "", "", err
	}
	return pair, accessJTI, refreshJTI, nil
}

func (s *AuthService) Store() *memory.Store {
	return s.store
}

func newID() string {
	return newJTI()
}
