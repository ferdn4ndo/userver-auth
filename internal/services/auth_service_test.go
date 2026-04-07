package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"userver-auth/internal/domain/models"
)

type memSystems struct {
	systems []*models.System
	err     error
}

func (m *memSystems) GetByName(ctx context.Context, name string) (*models.System, error) {
	if m.err != nil {
		return nil, m.err
	}
	for i := range m.systems {
		if m.systems[i].Name == name {
			return m.systems[i], nil
		}
	}
	return nil, nil
}

func (m *memSystems) GetByToken(ctx context.Context, token string) (*models.System, error) {
	if m.err != nil {
		return nil, m.err
	}
	for i := range m.systems {
		if m.systems[i].Token == token {
			return m.systems[i], nil
		}
	}
	return nil, nil
}

func (m *memSystems) Create(ctx context.Context, name, token string) (*models.System, error) {
	s := &models.System{
		ID:        len(m.systems) + 1,
		Name:      name,
		Token:     token,
		CreatedAt: time.Now().UTC(),
	}
	m.systems = append(m.systems, s)
	return s, nil
}

func (m *memSystems) UpdateToken(ctx context.Context, systemID int, newToken string) error {
	for i := range m.systems {
		if m.systems[i].ID == systemID {
			m.systems[i].Token = newToken
			return nil
		}
	}
	return errors.New("system not found")
}

type memUsers struct {
	users []*models.User
	err   error
}

func (m *memUsers) GetByUUID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	if m.err != nil {
		return nil, m.err
	}
	for i := range m.users {
		if m.users[i].UUID == id {
			return m.users[i], nil
		}
	}
	return nil, nil
}

func (m *memUsers) GetBySystemAndUsername(ctx context.Context, systemName, username string) (*models.User, error) {
	if m.err != nil {
		return nil, m.err
	}
	for i := range m.users {
		if m.users[i].SystemName == systemName && m.users[i].Username == username {
			return m.users[i], nil
		}
	}
	return nil, nil
}

func (m *memUsers) Create(ctx context.Context, u *models.User) error {
	if u.UUID == uuid.Nil {
		u.UUID = uuid.New()
	}
	now := time.Now().UTC()
	if u.RegisteredAt.IsZero() {
		u.RegisteredAt = now
	}
	if u.LastActivityAt.IsZero() {
		u.LastActivityAt = now
	}
	cp := *u
	m.users = append(m.users, &cp)
	return nil
}

func (m *memUsers) UpdatePassword(ctx context.Context, userID uuid.UUID, hashed string) error {
	for i := range m.users {
		if m.users[i].UUID == userID {
			m.users[i].Password = hashed
			return nil
		}
	}
	return errors.New("user not found")
}

func (m *memUsers) TouchActivity(ctx context.Context, userID uuid.UUID) error {
	for i := range m.users {
		if m.users[i].UUID == userID {
			m.users[i].LastActivityAt = time.Now().UTC()
			return nil
		}
	}
	return nil
}

func newAuthTestStack() (*AuthService, *memSystems, *memUsers, *stubBlocklist, *TokenService) {
	sys := &memSystems{}
	usr := &memUsers{}
	bl := &stubBlocklist{blocked: map[string]bool{}}
	env := testEnv()
	tok := NewTokenService(env, bl)
	auth := NewAuthService(env, sys, usr, bl, tok)
	return auth, sys, usr, bl, tok
}

func TestAuthService_CreateSystem_alreadyExists(t *testing.T) {
	ctx := context.Background()
	auth, sys, _, _, _ := newAuthTestStack()
	_, err := sys.Create(ctx, "acme", "t1")
	require.NoError(t, err)

	_, err = auth.CreateSystem(ctx, "acme", nil)
	require.Error(t, err)
	var he *HTTPError
	require.True(t, errors.As(err, &he))
	require.Equal(t, 409, he.Status)
}

func TestAuthService_CreateSystem_GetByNameError(t *testing.T) {
	ctx := context.Background()
	auth, sys, _, _, _ := newAuthTestStack()
	sys.err = errors.New("db")

	_, err := auth.CreateSystem(ctx, "acme", nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "db")
}

func TestAuthService_CreateSystem_tokenInUse(t *testing.T) {
	ctx := context.Background()
	auth, sys, _, _, _ := newAuthTestStack()
	custom := "shared-tok"
	_, err := sys.Create(ctx, "other", custom)
	require.NoError(t, err)

	_, err = auth.CreateSystem(ctx, "newsys", ptr(custom))
	require.Error(t, err)
	var he *HTTPError
	require.True(t, errors.As(err, &he))
	require.Equal(t, 409, he.Status)
	require.Contains(t, he.Message, "Token already in use")
}

func TestAuthService_CreateSystem_autoToken(t *testing.T) {
	ctx := context.Background()
	auth, sys, _, _, _ := newAuthTestStack()
	s, err := auth.CreateSystem(ctx, "acme", nil)
	require.NoError(t, err)
	require.Equal(t, "acme", s.Name)
	require.NotEmpty(t, s.Token)
	require.Len(t, sys.systems, 1)
}

func TestAuthService_CreateSystem_customToken(t *testing.T) {
	ctx := context.Background()
	auth, sys, _, _, _ := newAuthTestStack()
	want := "my-fixed-token-32byteslong!!!!"
	s, err := auth.CreateSystem(ctx, "acme", ptr(want))
	require.NoError(t, err)
	require.Equal(t, want, s.Token)
	require.Len(t, sys.systems, 1)
}

func TestAuthService_Register_invalidSystemCreds(t *testing.T) {
	ctx := context.Background()
	auth, sys, _, _, _ := newAuthTestStack()
	_, err := sys.Create(ctx, "acme", "sys-tok")
	require.NoError(t, err)

	_, err = auth.Register(ctx, "u1", "acme", "wrong", "pw", false)
	require.Error(t, err)
	var he *HTTPError
	require.True(t, errors.As(err, &he))
	require.Equal(t, 401, he.Status)
}

func TestAuthService_Register_duplicateUsername(t *testing.T) {
	ctx := context.Background()
	auth, sys, usr, _, _ := newAuthTestStack()
	_, err := sys.Create(ctx, "acme", "sys-tok")
	require.NoError(t, err)

	_, err = auth.Register(ctx, "u1", "acme", "sys-tok", "pw1", false)
	require.NoError(t, err)
	_, err = auth.Register(ctx, "u1", "acme", "sys-tok", "pw2", false)
	require.Error(t, err)
	var he *HTTPError
	require.True(t, errors.As(err, &he))
	require.Equal(t, 409, he.Status)
	require.Len(t, usr.users, 1)
}

func TestAuthService_Register_success(t *testing.T) {
	ctx := context.Background()
	auth, sys, usr, _, _ := newAuthTestStack()
	_, err := sys.Create(ctx, "acme", "sys-tok")
	require.NoError(t, err)

	out, err := auth.Register(ctx, "alice", "acme", "sys-tok", "secret", true)
	require.NoError(t, err)
	require.Equal(t, "alice", out["username"])
	require.Equal(t, "acme", out["system_name"])
	require.Equal(t, true, out["is_admin"])
	authMap, ok := out["auth"].(map[string]any)
	require.True(t, ok)
	require.NotEmpty(t, authMap["access_token"])
	require.NotEmpty(t, authMap["refresh_token"])
	require.Len(t, usr.users, 1)
}

func TestAuthService_Login_wrongPassword(t *testing.T) {
	ctx := context.Background()
	auth, sys, usr, _, _ := newAuthTestStack()
	_, err := sys.Create(ctx, "acme", "sys-tok")
	require.NoError(t, err)
	hash, err := bcrypt.GenerateFromPassword([]byte("right"), 4)
	require.NoError(t, err)
	u := &models.User{UUID: uuid.New(), SystemName: "acme", Username: "bob", Password: string(hash)}
	require.NoError(t, usr.Create(ctx, u))

	_, err = auth.Login(ctx, "bob", "acme", "sys-tok", "wrong")
	require.Error(t, err)
	var he *HTTPError
	require.True(t, errors.As(err, &he))
	require.Equal(t, 401, he.Status)
}

func TestAuthService_Login_unknownUser(t *testing.T) {
	ctx := context.Background()
	auth, sys, _, _, _ := newAuthTestStack()
	_, err := sys.Create(ctx, "acme", "sys-tok")
	require.NoError(t, err)

	_, err = auth.Login(ctx, "nobody", "acme", "sys-tok", "x")
	require.Error(t, err)
	var he *HTTPError
	require.True(t, errors.As(err, &he))
	require.Equal(t, 401, he.Status)
}

func TestAuthService_Login_success(t *testing.T) {
	ctx := context.Background()
	auth, sys, usr, _, _ := newAuthTestStack()
	_, err := sys.Create(ctx, "acme", "sys-tok")
	require.NoError(t, err)
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), 4)
	require.NoError(t, err)
	u := &models.User{UUID: uuid.New(), SystemName: "acme", Username: "bob", Password: string(hash)}
	require.NoError(t, usr.Create(ctx, u))

	out, err := auth.Login(ctx, "bob", "acme", "sys-tok", "secret")
	require.NoError(t, err)
	require.NotEmpty(t, out["access_token"])
}

func TestAuthService_Refresh_unknownUser_blocklists(t *testing.T) {
	ctx := context.Background()
	auth, _, usr, bl, tok := newAuthTestStack()
	ghost := uuid.New()
	_, _, refresh, _, err := tok.IssuePair(ctx, ghost)
	require.NoError(t, err)
	require.NoError(t, usr.Create(ctx, &models.User{
		UUID: ghost, SystemName: "acme", Username: "gone",
		Password: "x", RegisteredAt: time.Now(), LastActivityAt: time.Now(),
	}))
	usr.users = nil

	_, err = auth.Refresh(ctx, refresh)
	require.Error(t, err)
	var he *HTTPError
	require.True(t, errors.As(err, &he))
	require.Equal(t, 401, he.Status)
	require.Contains(t, bl.Added, refresh)
}

func TestAuthService_Refresh_success(t *testing.T) {
	ctx := context.Background()
	auth, sys, usr, _, tok := newAuthTestStack()
	_, err := sys.Create(ctx, "acme", "sys-tok")
	require.NoError(t, err)
	hash, err := bcrypt.GenerateFromPassword([]byte("p"), 4)
	require.NoError(t, err)
	u := &models.User{UUID: uuid.New(), SystemName: "acme", Username: "u", Password: string(hash)}
	require.NoError(t, usr.Create(ctx, u))
	_, _, ref, _, err := tok.IssuePair(ctx, u.UUID)
	require.NoError(t, err)

	out, err := auth.Refresh(ctx, ref)
	require.NoError(t, err)
	require.NotEmpty(t, out["access_token"])
}

func TestAuthService_Me_unknownUser(t *testing.T) {
	ctx := context.Background()
	auth, _, usr, bl, tok := newAuthTestStack()
	uid := uuid.New()
	access, _, _, _, err := tok.IssuePair(ctx, uid)
	require.NoError(t, err)
	require.NoError(t, usr.Create(ctx, &models.User{
		UUID: uid, SystemName: "acme", Username: "tmp", Password: "x",
		RegisteredAt: time.Now(), LastActivityAt: time.Now(),
	}))
	usr.users = nil

	_, err = auth.Me(ctx, access)
	require.Error(t, err)
	var he *HTTPError
	require.True(t, errors.As(err, &he))
	require.Equal(t, 401, he.Status)
	require.Contains(t, bl.Added, access)
}

func TestAuthService_Me_success(t *testing.T) {
	ctx := context.Background()
	auth, sys, usr, _, tok := newAuthTestStack()
	_, err := sys.Create(ctx, "acme", "sys-tok")
	require.NoError(t, err)
	u := &models.User{UUID: uuid.New(), SystemName: "acme", Username: "me", Password: "x"}
	require.NoError(t, usr.Create(ctx, u))
	access, _, _, _, err := tok.IssuePair(ctx, u.UUID)
	require.NoError(t, err)

	out, err := auth.Me(ctx, access)
	require.NoError(t, err)
	require.Equal(t, u.UUID.String(), out["uuid"])
	require.Equal(t, "me", out["username"])
}

func TestAuthService_LookupUser_notFound(t *testing.T) {
	ctx := context.Background()
	auth, sys, usr, _, tok := newAuthTestStack()
	_, err := sys.Create(ctx, "acme", "sys-tok")
	require.NoError(t, err)
	self := &models.User{UUID: uuid.New(), SystemName: "acme", Username: "self", Password: "x"}
	require.NoError(t, usr.Create(ctx, self))
	access, _, _, _, err := tok.IssuePair(ctx, self.UUID)
	require.NoError(t, err)

	_, err = auth.LookupUser(ctx, access, "acme", "missing")
	require.Error(t, err)
	var he *HTTPError
	require.True(t, errors.As(err, &he))
	require.Equal(t, 404, he.Status)
}

func TestAuthService_LookupUser_loggedUserUnknown(t *testing.T) {
	ctx := context.Background()
	auth, sys, usr, bl, tok := newAuthTestStack()
	_, err := sys.Create(ctx, "acme", "sys-tok")
	require.NoError(t, err)
	self := &models.User{UUID: uuid.New(), SystemName: "acme", Username: "self", Password: "x"}
	require.NoError(t, usr.Create(ctx, self))
	access, _, _, _, err := tok.IssuePair(ctx, self.UUID)
	require.NoError(t, err)
	usr.users = nil

	_, err = auth.LookupUser(ctx, access, "acme", "any")
	require.Error(t, err)
	var he *HTTPError
	require.True(t, errors.As(err, &he))
	require.Equal(t, 401, he.Status)
	require.Contains(t, bl.Added, access)
}

func TestAuthService_LookupUser_success(t *testing.T) {
	ctx := context.Background()
	auth, sys, usr, _, tok := newAuthTestStack()
	_, err := sys.Create(ctx, "acme", "sys-tok")
	require.NoError(t, err)
	self := &models.User{UUID: uuid.New(), SystemName: "acme", Username: "self", Password: "x"}
	target := &models.User{UUID: uuid.New(), SystemName: "acme", Username: "other", Password: "x"}
	require.NoError(t, usr.Create(ctx, self))
	require.NoError(t, usr.Create(ctx, target))
	access, _, _, _, err := tok.IssuePair(ctx, self.UUID)
	require.NoError(t, err)

	out, err := auth.LookupUser(ctx, access, "acme", "other")
	require.NoError(t, err)
	require.Equal(t, target.UUID.String(), out["uuid"])
}

func TestAuthService_RotateSystemToken_notFound(t *testing.T) {
	ctx := context.Background()
	auth, _, _, _, _ := newAuthTestStack()
	_, err := auth.RotateSystemToken(ctx, "nope", "tok", nil)
	require.Error(t, err)
	var he *HTTPError
	require.True(t, errors.As(err, &he))
	require.Equal(t, 404, he.Status)
}

func TestAuthService_RotateSystemToken_badCurrent(t *testing.T) {
	ctx := context.Background()
	auth, sys, _, _, _ := newAuthTestStack()
	_, err := sys.Create(ctx, "acme", "real")
	require.NoError(t, err)

	_, err = auth.RotateSystemToken(ctx, "acme", "wrong", nil)
	require.Error(t, err)
	var he *HTTPError
	require.True(t, errors.As(err, &he))
	require.Equal(t, 401, he.Status)
}

func TestAuthService_RotateSystemToken_sameNewAsCurrent(t *testing.T) {
	ctx := context.Background()
	auth, sys, _, _, _ := newAuthTestStack()
	_, err := sys.Create(ctx, "acme", "tok-a")
	require.NoError(t, err)
	same := "tok-a"
	out, err := auth.RotateSystemToken(ctx, "acme", "tok-a", &same)
	require.NoError(t, err)
	require.Equal(t, "tok-a", out["token"])
}

func TestAuthService_RotateSystemToken_newTokenConflict(t *testing.T) {
	ctx := context.Background()
	auth, sys, _, _, _ := newAuthTestStack()
	_, err := sys.Create(ctx, "a", "ta")
	require.NoError(t, err)
	_, err = sys.Create(ctx, "b", "tb")
	require.NoError(t, err)

	conflict := "tb"
	_, err = auth.RotateSystemToken(ctx, "a", "ta", &conflict)
	require.Error(t, err)
	var he *HTTPError
	require.True(t, errors.As(err, &he))
	require.Equal(t, 409, he.Status)
}

func TestAuthService_RotateSystemToken_generatesNew(t *testing.T) {
	ctx := context.Background()
	auth, sys, _, _, _ := newAuthTestStack()
	_, err := sys.Create(ctx, "acme", "oldtok")
	require.NoError(t, err)

	out, err := auth.RotateSystemToken(ctx, "acme", "oldtok", nil)
	require.NoError(t, err)
	newTok, _ := out["token"].(string)
	require.NotEmpty(t, newTok)
	require.NotEqual(t, "oldtok", newTok)
	require.Equal(t, newTok, sys.systems[0].Token)
}

func TestAuthService_RotateSystemToken_customNew(t *testing.T) {
	ctx := context.Background()
	auth, sys, _, _, _ := newAuthTestStack()
	_, err := sys.Create(ctx, "acme", "old")
	require.NoError(t, err)
	n := "new-fixed-token-32byteslong!!!!"
	out, err := auth.RotateSystemToken(ctx, "acme", "old", &n)
	require.NoError(t, err)
	require.Equal(t, n, out["token"])
}

func TestAuthService_ChangePassword_unknownUser(t *testing.T) {
	ctx := context.Background()
	auth, sys, usr, bl, tok := newAuthTestStack()
	_, err := sys.Create(ctx, "acme", "st")
	require.NoError(t, err)
	u := &models.User{UUID: uuid.New(), SystemName: "acme", Username: "u", Password: "x"}
	require.NoError(t, usr.Create(ctx, u))
	access, _, _, _, err := tok.IssuePair(ctx, u.UUID)
	require.NoError(t, err)
	usr.users = nil

	err = auth.ChangePassword(ctx, access, "any", "new")
	require.Error(t, err)
	var he *HTTPError
	require.True(t, errors.As(err, &he))
	require.Equal(t, 401, he.Status)
	require.Contains(t, bl.Added, access)
}

func TestAuthService_ChangePassword_emptyNew(t *testing.T) {
	ctx := context.Background()
	auth, _, _, _, tok := newAuthTestStack()
	access, _, _, _, err := tok.IssuePair(ctx, uuid.New())
	require.NoError(t, err)

	err = auth.ChangePassword(ctx, access, "old", "   ")
	require.Error(t, err)
	var he *HTTPError
	require.True(t, errors.As(err, &he))
	require.Equal(t, 400, he.Status)
}

func TestAuthService_ChangePassword_wrongCurrent(t *testing.T) {
	ctx := context.Background()
	auth, sys, usr, _, tok := newAuthTestStack()
	_, err := sys.Create(ctx, "acme", "st")
	require.NoError(t, err)
	hash, err := bcrypt.GenerateFromPassword([]byte("old"), 4)
	require.NoError(t, err)
	u := &models.User{UUID: uuid.New(), SystemName: "acme", Username: "u", Password: string(hash)}
	require.NoError(t, usr.Create(ctx, u))
	access, _, _, _, err := tok.IssuePair(ctx, u.UUID)
	require.NoError(t, err)

	err = auth.ChangePassword(ctx, access, "not-old", "newpass")
	require.Error(t, err)
	var he *HTTPError
	require.True(t, errors.As(err, &he))
	require.Equal(t, 401, he.Status)
}

func TestAuthService_ChangePassword_success(t *testing.T) {
	ctx := context.Background()
	auth, sys, usr, _, tok := newAuthTestStack()
	_, err := sys.Create(ctx, "acme", "st")
	require.NoError(t, err)
	hash, err := bcrypt.GenerateFromPassword([]byte("old"), 4)
	require.NoError(t, err)
	u := &models.User{UUID: uuid.New(), SystemName: "acme", Username: "u", Password: string(hash)}
	require.NoError(t, usr.Create(ctx, u))
	access, _, _, _, err := tok.IssuePair(ctx, u.UUID)
	require.NoError(t, err)

	require.NoError(t, auth.ChangePassword(ctx, access, "old", "newsecret"))
	require.NoError(t, bcrypt.CompareHashAndPassword([]byte(usr.users[0].Password), []byte("newsecret")))
}

func TestAuthService_Logout_invalidToken(t *testing.T) {
	ctx := context.Background()
	auth, _, _, _, _ := newAuthTestStack()
	err := auth.Logout(ctx, "bad")
	require.Error(t, err)
	var he *HTTPError
	require.True(t, errors.As(err, &he))
}

func TestAuthService_Logout_success(t *testing.T) {
	ctx := context.Background()
	auth, sys, usr, bl, tok := newAuthTestStack()
	_, err := sys.Create(ctx, "acme", "st")
	require.NoError(t, err)
	u := &models.User{UUID: uuid.New(), SystemName: "acme", Username: "u", Password: "x"}
	require.NoError(t, usr.Create(ctx, u))
	access, _, _, _, err := tok.IssuePair(ctx, u.UUID)
	require.NoError(t, err)

	require.NoError(t, auth.Logout(ctx, access))
	require.Contains(t, bl.Added, access)
}

func ptr(s string) *string { return &s }
