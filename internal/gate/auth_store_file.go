package gate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type fileAuthSessionStore struct {
	mu       sync.Mutex
	path     string
	sessions map[string]authSession
	now      func() time.Time
}

type authSessionFileState struct {
	Version  int                     `json:"version"`
	Families []authSessionFileRecord `json:"families"`
}

type authSessionFileRecord struct {
	FamilyID           string    `json:"family_id"`
	CurrentGeneration  uint64    `json:"current_generation"`
	PreviousGeneration uint64    `json:"previous_generation,omitempty"`
	PreviousValidUntil time.Time `json:"previous_valid_until,omitempty"`
	ExpiresAt          time.Time `json:"expires_at"`
	NextRotateAt       time.Time `json:"next_rotate_at,omitempty"`
}

func newFileAuthSessionStore(path string, now func() time.Time) (*fileAuthSessionStore, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return nil, errors.New("AUTH_SESSION_FILE is empty")
	}

	store := &fileAuthSessionStore{
		path:     cleanPath,
		sessions: map[string]authSession{},
		now:      now,
	}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *fileAuthSessionStore) Issue(ttl time.Duration, rotationEnabled bool, rotationInterval time.Duration) (authSession, error) {
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

	snapshot := cloneAuthSessions(s.sessions)
	s.cleanupLocked(now)
	s.sessions[familyID] = session
	if err := s.persistLocked(); err != nil {
		s.sessions = snapshot
		return authSession{}, err
	}
	return session, nil
}

func (s *fileAuthSessionStore) Validate(familyID string, generation uint64, rotationEnabled bool, rotationInterval time.Duration, rotationGrace time.Duration) (authSessionValidation, bool) {
	now := s.currentTime()

	s.mu.Lock()
	defer s.mu.Unlock()

	snapshot := cloneAuthSessions(s.sessions)
	changed := s.cleanupLocked(now)

	session, ok := s.sessions[familyID]
	if !ok {
		if changed {
			s.restoreOnPersistFailure(snapshot)
		}
		return authSessionValidation{}, false
	}
	if now.After(session.expiresAt) {
		delete(s.sessions, familyID)
		s.restoreOnPersistFailure(snapshot)
		return authSessionValidation{}, false
	}

	if generation == session.currentGeneration {
		if rotationEnabled && shouldRotateAuthSession(session, now, rotationInterval) {
			session.previousGeneration = session.currentGeneration
			session.previousValidUntil = minTime(now.Add(rotationGrace), session.expiresAt)
			session.currentGeneration++
			session.nextRotateAt = minTime(now.Add(rotationInterval), session.expiresAt)
			s.sessions[familyID] = session
			if err := s.persistLocked(); err != nil {
				s.sessions = snapshot
				return authSessionValidation{
					familyID:          snapshot[familyID].familyID,
					currentGeneration: snapshot[familyID].currentGeneration,
					expiresAt:         snapshot[familyID].expiresAt,
				}, true
			}
			return authSessionValidation{
				familyID:          session.familyID,
				currentGeneration: session.currentGeneration,
				expiresAt:         session.expiresAt,
				reissue:           true,
			}, true
		}
		if changed {
			s.restoreOnPersistFailure(snapshot)
		}
		return authSessionValidation{
			familyID:          session.familyID,
			currentGeneration: session.currentGeneration,
			expiresAt:         session.expiresAt,
		}, true
	}

	if generation == session.previousGeneration && !session.previousValidUntil.IsZero() && !now.After(session.previousValidUntil) {
		if changed {
			s.restoreOnPersistFailure(snapshot)
		}
		return authSessionValidation{
			familyID:          session.familyID,
			currentGeneration: session.currentGeneration,
			expiresAt:         session.expiresAt,
			reissue:           true,
		}, true
	}

	if changed {
		s.restoreOnPersistFailure(snapshot)
	}
	return authSessionValidation{}, false
}

func (s *fileAuthSessionStore) Delete(familyID string) {
	if strings.TrimSpace(familyID) == "" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.sessions[familyID]; !ok {
		return
	}

	snapshot := cloneAuthSessions(s.sessions)
	delete(s.sessions, familyID)
	if err := s.persistLocked(); err != nil {
		s.sessions = snapshot
	}
}

func (s *fileAuthSessionStore) load() error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create auth session store dir: %w", err)
	}

	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read auth session store: %w", err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil
	}

	var state authSessionFileState
	if err := json.Unmarshal(raw, &state); err != nil {
		return fmt.Errorf("decode auth session store: %w", err)
	}

	now := s.currentTime()
	for _, record := range state.Families {
		if strings.TrimSpace(record.FamilyID) == "" {
			continue
		}
		if now.After(record.ExpiresAt) {
			continue
		}
		s.sessions[record.FamilyID] = authSession{
			familyID:           record.FamilyID,
			currentGeneration:  record.CurrentGeneration,
			previousGeneration: record.PreviousGeneration,
			previousValidUntil: record.PreviousValidUntil,
			expiresAt:          record.ExpiresAt,
			nextRotateAt:       record.NextRotateAt,
		}
	}
	return nil
}

func (s *fileAuthSessionStore) cleanupLocked(now time.Time) bool {
	changed := false
	for familyID, session := range s.sessions {
		if now.After(session.expiresAt) {
			delete(s.sessions, familyID)
			changed = true
		}
	}
	return changed
}

func (s *fileAuthSessionStore) persistLocked() error {
	state := authSessionFileState{
		Version:  2,
		Families: make([]authSessionFileRecord, 0, len(s.sessions)),
	}
	for _, session := range s.sessions {
		state.Families = append(state.Families, authSessionFileRecord{
			FamilyID:           session.familyID,
			CurrentGeneration:  session.currentGeneration,
			PreviousGeneration: session.previousGeneration,
			PreviousValidUntil: session.previousValidUntil,
			ExpiresAt:          session.expiresAt,
			NextRotateAt:       session.nextRotateAt,
		})
	}

	payload, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode auth session store: %w", err)
	}
	return writeAtomically(s.path, payload, 0o600)
}

func (s *fileAuthSessionStore) restoreOnPersistFailure(snapshot map[string]authSession) {
	if err := s.persistLocked(); err != nil {
		s.sessions = snapshot
	}
}

func (s *fileAuthSessionStore) currentTime() time.Time {
	if s != nil && s.now != nil {
		return s.now()
	}
	return time.Now()
}

func cloneAuthSessions(src map[string]authSession) map[string]authSession {
	clone := make(map[string]authSession, len(src))
	for familyID, session := range src {
		clone[familyID] = session
	}
	return clone
}

func writeAtomically(path string, payload []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create store dir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp store file: %w", err)
	}

	tmpPath := tmp.Name()
	renamed := false
	defer func() {
		_ = tmp.Close()
		if !renamed {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(mode); err != nil {
		return fmt.Errorf("chmod temp store file: %w", err)
	}
	if _, err := tmp.Write(payload); err != nil {
		return fmt.Errorf("write temp store file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp store file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return fmt.Errorf("replace store file: %w", err)
		}
		if err := os.Rename(tmpPath, path); err != nil {
			return fmt.Errorf("replace store file: %w", err)
		}
	}

	renamed = true
	return nil
}
