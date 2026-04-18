package memory

import (
	"errors"
	"strings"
	"sync"
	"time"

	"go-auth/internal/model"
)

var ErrNotFound = errors.New("not found")
var ErrAlreadyExists = errors.New("already exists")

type Store struct {
	mu            sync.RWMutex
	usersByID     map[string]*model.User
	userIDsByMail map[string]string
	refreshTokens map[string]model.RefreshSession
}

func NewStore() *Store {
	return &Store{
		usersByID:     make(map[string]*model.User),
		userIDsByMail: make(map[string]string),
		refreshTokens: make(map[string]model.RefreshSession),
	}
}

func (s *Store) CreateUser(user *model.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	email := normalizeEmail(user.Email)
	if _, exists := s.userIDsByMail[email]; exists {
		return ErrAlreadyExists
	}

	now := time.Now().UTC()
	copy := *user
	copy.Email = email
	if copy.CreatedAt.IsZero() {
		copy.CreatedAt = now
	}
	copy.UpdatedAt = now

	s.usersByID[copy.ID] = &copy
	s.userIDsByMail[email] = copy.ID
	return nil
}

func (s *Store) GetUserByEmail(email string) (*model.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, exists := s.userIDsByMail[normalizeEmail(email)]
	if !exists {
		return nil, ErrNotFound
	}

	user, ok := s.usersByID[id]
	if !ok {
		return nil, ErrNotFound
	}

	copy := *user
	return &copy, nil
}

func (s *Store) GetUserByID(id string) (*model.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, ok := s.usersByID[id]
	if !ok {
		return nil, ErrNotFound
	}

	copy := *user
	return &copy, nil
}

func (s *Store) SaveRefreshToken(session model.RefreshSession) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.refreshTokens[session.TokenID] = session
}

func (s *Store) ConsumeRefreshToken(tokenID string) (model.RefreshSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.refreshTokens[tokenID]
	if !ok {
		return model.RefreshSession{}, false
	}

	delete(s.refreshTokens, tokenID)
	return session, true
}

func (s *Store) RevokeRefreshToken(tokenID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.refreshTokens, tokenID)
}

func (s *Store) SeedUser(user *model.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	email := normalizeEmail(user.Email)
	if _, exists := s.userIDsByMail[email]; exists {
		return nil
	}

	now := time.Now().UTC()
	copy := *user
	copy.Email = email
	if copy.CreatedAt.IsZero() {
		copy.CreatedAt = now
	}
	copy.UpdatedAt = now

	s.usersByID[copy.ID] = &copy
	s.userIDsByMail[email] = copy.ID
	return nil
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
