package gate

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type fileAuthSessionStore struct {
	mu              sync.Mutex
	path            string
	walPath         string
	sessions        map[string]authSession
	now             func() time.Time
	cleanupInterval time.Duration
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

type authSessionMutation struct {
	Op       string                 `json:"op"`
	FamilyID string                 `json:"family_id,omitempty"`
	Session  *authSessionFileRecord `json:"session,omitempty"`
}

func newFileAuthSessionStore(path string, now func() time.Time) (*fileAuthSessionStore, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return nil, errors.New("AUTH_SESSION_FILE is empty")
	}

	store := &fileAuthSessionStore{
		path:            cleanPath,
		walPath:         cleanPath + ".wal",
		sessions:        map[string]authSession{},
		now:             now,
		cleanupInterval: defaultAuthSessionCleanup,
	}

	changed, err := store.load()
	if err != nil {
		return nil, err
	}
	if changed {
		if err := store.persistSnapshotLocked(); err != nil {
			return nil, err
		}
	}

	store.startCleanupLoop()
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
	if err := s.persistMutationLocked(authSessionMutation{
		Op:      "upsert",
		Session: sessionRecordPtr(session),
	}); err != nil {
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
	s.cleanupLocked(now)

	session, ok := s.sessions[familyID]
	if !ok {
		return authSessionValidation{}, false
	}
	if now.After(session.expiresAt) {
		delete(s.sessions, familyID)
		if err := s.persistMutationLocked(authSessionMutation{
			Op:       "delete",
			FamilyID: familyID,
		}); err != nil {
			s.sessions = snapshot
		}
		return authSessionValidation{}, false
	}

	if generation == session.currentGeneration {
		if rotationEnabled && shouldRotateAuthSession(session, now, rotationInterval) {
			session.previousGeneration = session.currentGeneration
			session.previousValidUntil = minTime(now.Add(rotationGrace), session.expiresAt)
			session.currentGeneration++
			session.nextRotateAt = minTime(now.Add(rotationInterval), session.expiresAt)
			s.sessions[familyID] = session
			if err := s.persistMutationLocked(authSessionMutation{
				Op:      "upsert",
				Session: sessionRecordPtr(session),
			}); err != nil {
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
	if err := s.persistMutationLocked(authSessionMutation{
		Op:       "delete",
		FamilyID: familyID,
	}); err != nil {
		s.sessions = snapshot
	}
}

func (s *fileAuthSessionStore) load() (bool, error) {
	changedSnapshot, err := s.loadSnapshot()
	if err != nil {
		return false, err
	}

	changedWAL, err := s.replayWAL()
	if err != nil {
		return false, err
	}

	return changedSnapshot || changedWAL, nil
}

func (s *fileAuthSessionStore) loadSnapshot() (bool, error) {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, fmt.Errorf("create auth session store dir: %w", err)
	}

	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read auth session store: %w", err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return false, nil
	}

	var state authSessionFileState
	if err := json.Unmarshal(raw, &state); err != nil {
		return false, fmt.Errorf("decode auth session store: %w", err)
	}

	now := s.currentTime()
	changed := false
	for _, record := range state.Families {
		if strings.TrimSpace(record.FamilyID) == "" {
			changed = true
			continue
		}
		if now.After(record.ExpiresAt) {
			changed = true
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
	return changed, nil
}

func (s *fileAuthSessionStore) replayWAL() (bool, error) {
	raw, err := os.ReadFile(s.walPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read auth session wal: %w", err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return true, nil
	}

	lines := strings.Split(string(raw), "\n")
	changed := false
	for idx, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var mutation authSessionMutation
		if err := json.Unmarshal([]byte(line), &mutation); err != nil {
			if isTrailingMutationFragment(lines, idx) {
				return true, nil
			}
			return false, fmt.Errorf("decode auth session wal: %w", err)
		}
		if err := s.applyMutation(mutation); err != nil {
			return false, err
		}
		changed = true
	}
	return changed, nil
}

func (s *fileAuthSessionStore) applyMutation(mutation authSessionMutation) error {
	switch mutation.Op {
	case "upsert":
		if mutation.Session == nil || strings.TrimSpace(mutation.Session.FamilyID) == "" {
			return fmt.Errorf("decode auth session wal: invalid upsert mutation")
		}
		record := mutation.Session
		if s.currentTime().After(record.ExpiresAt) {
			return nil
		}
		s.sessions[record.FamilyID] = authSession{
			familyID:           record.FamilyID,
			currentGeneration:  record.CurrentGeneration,
			previousGeneration: record.PreviousGeneration,
			previousValidUntil: record.PreviousValidUntil,
			expiresAt:          record.ExpiresAt,
			nextRotateAt:       record.NextRotateAt,
		}
		return nil
	case "delete":
		if strings.TrimSpace(mutation.FamilyID) == "" {
			return fmt.Errorf("decode auth session wal: invalid delete mutation")
		}
		delete(s.sessions, mutation.FamilyID)
		return nil
	default:
		return fmt.Errorf("decode auth session wal: unsupported mutation %q", mutation.Op)
	}
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

func (s *fileAuthSessionStore) persistSnapshotLocked() error {
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
	if err := writeAtomically(s.path, payload, 0o600); err != nil {
		return err
	}
	if err := os.Remove(s.walPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove auth session wal: %w", err)
	}
	return nil
}

func (s *fileAuthSessionStore) persistMutationLocked(mutation authSessionMutation) error {
	if !s.snapshotExistsLocked() {
		return s.persistSnapshotLocked()
	}
	return s.appendMutationLocked(mutation)
}

func (s *fileAuthSessionStore) appendMutationLocked(mutation authSessionMutation) error {
	payload, err := json.Marshal(mutation)
	if err != nil {
		return fmt.Errorf("encode auth session wal mutation: %w", err)
	}
	payload = append(payload, '\n')

	file, err := os.OpenFile(s.walPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open auth session wal: %w", err)
	}
	defer file.Close()

	if _, err := file.Write(payload); err != nil {
		return fmt.Errorf("write auth session wal: %w", err)
	}
	return nil
}

func (s *fileAuthSessionStore) snapshotExistsLocked() bool {
	info, err := os.Stat(s.path)
	return err == nil && !info.IsDir()
}

func (s *fileAuthSessionStore) hasPendingWALLocked() bool {
	info, err := os.Stat(s.walPath)
	return err == nil && !info.IsDir()
}

func (s *fileAuthSessionStore) startCleanupLoop() {
	if s.cleanupInterval <= 0 {
		return
	}

	go func() {
		ticker := time.NewTicker(s.cleanupInterval)
		defer ticker.Stop()

		for range ticker.C {
			if err := s.cleanupExpiredAndPersist(); err != nil {
				log.Printf("cleanup auth session store: %v", err)
			}
		}
	}()
}

func (s *fileAuthSessionStore) cleanupExpiredAndPersist() error {
	now := s.currentTime()

	s.mu.Lock()
	defer s.mu.Unlock()

	snapshot := cloneAuthSessions(s.sessions)
	changed := s.cleanupLocked(now)
	if !changed && !s.hasPendingWALLocked() {
		return nil
	}
	if err := s.persistSnapshotLocked(); err != nil {
		s.sessions = snapshot
		return err
	}
	return nil
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

func sessionRecordPtr(session authSession) *authSessionFileRecord {
	record := authSessionFileRecord{
		FamilyID:           session.familyID,
		CurrentGeneration:  session.currentGeneration,
		PreviousGeneration: session.previousGeneration,
		PreviousValidUntil: session.previousValidUntil,
		ExpiresAt:          session.expiresAt,
		NextRotateAt:       session.nextRotateAt,
	}
	return &record
}

func isTrailingMutationFragment(lines []string, idx int) bool {
	for i := idx + 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != "" {
			return false
		}
	}
	return true
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
