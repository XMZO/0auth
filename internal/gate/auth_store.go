package gate

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

func newAuthSessionStore(kind string, path string, now func() time.Time) (authSessionStore, error) {
	switch normalizeAuthSessionStore(kind) {
	case "", defaultAuthSessionStore:
		return &memoryAuthSessionStore{
			sessions: map[string]authSession{},
			now:      now,
		}, nil
	case "file":
		return newFileAuthSessionStore(path, now)
	default:
		return nil, fmt.Errorf("unsupported auth session store %q", kind)
	}
}

func describeAuthSessionStore(cfg Config) string {
	switch cfg.AuthSessionStore {
	case "file":
		return "file:" + strings.TrimSpace(cfg.AuthSessionFile)
	default:
		return defaultAuthSessionStore
	}
}

type memoryAuthSessionStore struct {
	mu       sync.Mutex
	sessions map[string]authSession
	now      func() time.Time
}

func (s *memoryAuthSessionStore) Issue(ttl time.Duration, rotationEnabled bool, rotationInterval time.Duration) (authSession, error) {
	familyID, err := issueNonce(24)
	if err != nil {
		return authSession{}, err
	}

	now := s.currentTime()
	session := authSession{
		familyID:          familyID,
		currentGeneration: 1,
		expiresAt:         now.Add(ttl),
	}
	if rotationEnabled && rotationInterval > 0 {
		session.nextRotateAt = minTime(now.Add(rotationInterval), session.expiresAt)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)
	s.sessions[familyID] = session
	return session, nil
}

func (s *memoryAuthSessionStore) Validate(familyID string, generation uint64, rotationEnabled bool, rotationInterval time.Duration, rotationGrace time.Duration) (authSessionValidation, bool) {
	now := s.currentTime()

	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)

	session, ok := s.sessions[familyID]
	if !ok {
		return authSessionValidation{}, false
	}
	if now.After(session.expiresAt) {
		delete(s.sessions, familyID)
		return authSessionValidation{}, false
	}
	if generation == session.currentGeneration {
		if rotationEnabled && shouldRotateAuthSession(session, now, rotationInterval) {
			session.previousGeneration = session.currentGeneration
			session.previousValidUntil = minTime(now.Add(rotationGrace), session.expiresAt)
			session.currentGeneration++
			session.nextRotateAt = minTime(now.Add(rotationInterval), session.expiresAt)
			s.sessions[familyID] = session
			return authSessionValidation{
				familyID:          session.familyID,
				currentGeneration: session.currentGeneration,
				expiresAt:         session.expiresAt,
				reissue:           true,
			}, true
		}
		return authSessionValidation{
			familyID:          session.familyID,
			currentGeneration: session.currentGeneration,
			expiresAt:         session.expiresAt,
		}, true
	}
	if generation == session.previousGeneration && !session.previousValidUntil.IsZero() && !now.After(session.previousValidUntil) {
		return authSessionValidation{
			familyID:          session.familyID,
			currentGeneration: session.currentGeneration,
			expiresAt:         session.expiresAt,
			reissue:           true,
		}, true
	}
	return authSessionValidation{}, false
}

func (s *memoryAuthSessionStore) Delete(familyID string) {
	if strings.TrimSpace(familyID) == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, familyID)
}

func (s *memoryAuthSessionStore) cleanupLocked(now time.Time) {
	for familyID, session := range s.sessions {
		if now.After(session.expiresAt) {
			delete(s.sessions, familyID)
		}
	}
}

func (s *memoryAuthSessionStore) currentTime() time.Time {
	if s != nil && s.now != nil {
		return s.now()
	}
	return time.Now()
}

func shouldRotateAuthSession(session authSession, now time.Time, rotationInterval time.Duration) bool {
	if rotationInterval <= 0 || session.nextRotateAt.IsZero() {
		return false
	}
	return !now.Before(session.nextRotateAt) && now.Before(session.expiresAt)
}

func minTime(left time.Time, right time.Time) time.Time {
	if left.Before(right) {
		return left
	}
	return right
}
