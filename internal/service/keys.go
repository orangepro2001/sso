package service

import (
	"context"
	"sync"

	"sso/internal/secure"
	"sso/internal/store"
)

// KeyPair is the active signing material, already decrypted.
type KeyPair struct {
	Kid        string
	Alg        string
	PrivatePEM string
	PublicPEM  string
}

// SigningKeyService owns the RS256 key pair used to sign access tokens.
//
// Keys live in the database (private half encrypted with APP_KEY) so the
// container filesystem can stay read-only and no key material has to be baked
// into an image (DESIGN.md §6). Generation is lazy: the first request that
// needs to sign, or the first JWKS read, creates the pair, so a brand new data
// file needs no provisioning step.
type SigningKeyService struct {
	store  *store.Store
	appKey string
	bits   int

	mu     sync.Mutex
	active *KeyPair
}

func NewSigningKeyService(st *store.Store, appKey string) *SigningKeyService {
	return &SigningKeyService{store: st, appKey: appKey, bits: 3072}
}

func (s *SigningKeyService) Active(ctx context.Context) (*KeyPair, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.active != nil {
		return s.active, nil
	}

	row, err := s.store.ActiveSigningKey(ctx)
	if err != nil {
		return nil, err
	}
	if row == nil {
		if row, err = s.generate(ctx); err != nil {
			return nil, err
		}
	}

	privatePEM, err := secure.DecryptPrivateKey(s.appKey, row.PrivateKey)
	if err != nil {
		return nil, err
	}
	s.active = &KeyPair{Kid: row.Kid, Alg: row.Alg, PrivatePEM: privatePEM, PublicPEM: row.PublicKey}
	return s.active, nil
}

// Publishable lists every key that may still have live tokens in circulation:
// all of them, newest active first, so a rotation does not invalidate a 7-day
// token that was signed an hour ago.
func (s *SigningKeyService) Publishable(ctx context.Context) ([]*store.SigningKey, error) {
	return s.store.PublishableKeys(ctx)
}

// JWKS is the public half of every published key, ready for the discovery
// endpoint.
func (s *SigningKeyService) JWKS(ctx context.Context) ([]secure.JWK, error) {
	keys, err := s.Publishable(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]secure.JWK, 0, len(keys))
	for _, key := range keys {
		if jwk, ok := secure.PublicJWK(key.PublicKey, key.Kid, key.Alg); ok {
			out = append(out, jwk)
		}
	}
	return out, nil
}

// PublicKeyFor finds the verification key for a kid, which is how a token
// signed before a rotation still resolves.
func (s *SigningKeyService) PublicKeyFor(ctx context.Context, kid string) (string, error) {
	row, err := s.store.SigningKeyByKid(ctx, kid)
	if err != nil || row == nil {
		return "", err
	}
	return row.PublicKey, nil
}

// Rotate retires the active key without invalidating tokens signed by it: the
// old key stays in the JWKS until somebody deletes the row.
func (s *SigningKeyService) Rotate(ctx context.Context) (*KeyPair, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.store.RetireActiveSigningKeys(ctx); err != nil {
		return nil, err
	}
	s.active = nil

	row, err := s.generate(ctx)
	if err != nil {
		return nil, err
	}
	privatePEM, err := secure.DecryptPrivateKey(s.appKey, row.PrivateKey)
	if err != nil {
		return nil, err
	}
	s.active = &KeyPair{Kid: row.Kid, Alg: row.Alg, PrivatePEM: privatePEM, PublicPEM: row.PublicKey}
	return s.active, nil
}

func (s *SigningKeyService) generate(ctx context.Context) (*store.SigningKey, error) {
	privatePEM, publicPEM, err := secure.GenerateKeyPair(s.bits)
	if err != nil {
		return nil, err
	}
	encrypted, err := secure.EncryptPrivateKey(s.appKey, privatePEM)
	if err != nil {
		return nil, err
	}
	row := &store.SigningKey{
		Kid:        secure.RandomString(16),
		Alg:        secure.Alg,
		PrivateKey: encrypted,
		PublicKey:  publicPEM,
		Active:     true,
	}
	if err := s.store.InsertSigningKey(ctx, row); err != nil {
		return nil, err
	}
	return row, nil
}
