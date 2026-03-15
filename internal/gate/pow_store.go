package gate

import (
	"fmt"
	"net/http"
	"time"
)

func newPowChallengeStore(now func() time.Time) *powChallengeStore {
	return &powChallengeStore{
		challenges: map[string]powChallenge{},
		now:        now,
	}
}

func (s *powChallengeStore) Issue(browserSessionKey string, difficulty int, ttl time.Duration) (powChallenge, error) {
	id, err := issueNonce(18)
	if err != nil {
		return powChallenge{}, fmt.Errorf("issue pow challenge id: %w", err)
	}
	token, err := issueNonce(18)
	if err != nil {
		return powChallenge{}, fmt.Errorf("issue pow challenge token: %w", err)
	}

	challenge := powChallenge{
		id:                id,
		token:             token,
		browserSessionKey: browserSessionKey,
		difficulty:        difficulty,
		expiresAt:         s.currentTime().Add(ttl),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(s.currentTime())
	s.challenges[challenge.id] = challenge
	return challenge, nil
}

func (s *powChallengeStore) Consume(browserSessionKey string, challengeID string, token string, nonce string) error {
	now := s.currentTime()

	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)

	challenge, ok := s.challenges[challengeID]
	if !ok {
		return localizedUserError{key: "pow_expired", status: http.StatusForbidden}
	}
	if challenge.browserSessionKey != browserSessionKey {
		return localizedUserError{key: "pow_invalid", status: http.StatusForbidden}
	}
	if now.After(challenge.expiresAt) {
		delete(s.challenges, challengeID)
		return localizedUserError{key: "pow_expired", status: http.StatusForbidden}
	}
	if !constantTimeEqual(token, challenge.token) {
		return localizedUserError{key: "pow_invalid", status: http.StatusForbidden}
	}
	if !powNonceMatches(challenge.token, nonce, challenge.difficulty) {
		return localizedUserError{key: "pow_invalid", status: http.StatusForbidden}
	}

	delete(s.challenges, challengeID)
	return nil
}

func (s *powChallengeStore) cleanupLocked(now time.Time) {
	for id, challenge := range s.challenges {
		if now.After(challenge.expiresAt) {
			delete(s.challenges, id)
		}
	}
}

func (s *powChallengeStore) currentTime() time.Time {
	if s != nil && s.now != nil {
		return s.now()
	}
	return time.Now()
}
